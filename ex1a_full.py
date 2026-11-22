import ctypes as c
import ipaddress
import os
import queue
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import traceback
import unittest
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

import psutil
import ex1a_gui as basic


cap = basic.capture

DISPLAY_LIMIT = 1000
MAX_PACKET_SIZE = 16 * 1024 * 1024
MAX_FLOW_READ = 16 * 1024 * 1024
MAX_STREAM_DISPLAY = 2 * 1024 * 1024

PACKET_COLUMNS = (
    "ts", "wire", "raw", "family", "src", "dst",
    "transport", "protocol", "sport", "dport",
    "seq", "flags", "flow", "pid_src", "pid_dst",
    "process", "info",
)

INSERT_SQL = (
    "INSERT INTO packets ("
    + ", ".join(PACKET_COLUMNS)
    + ") VALUES ("
    + ", ".join(":" + name for name in PACKET_COLUMNS)
    + ")"
)

METADATA_SQL = """
SELECT id, ts, wire, length(raw) AS captured,
       family, src, dst, transport, protocol,
       sport, dport, seq, flags, flow,
       pid_src, pid_dst, process, info
FROM packets
"""


def normalize_ip(value):
    return str(ipaddress.ip_address(value.split("%")[0]))


class ProcessCache:
    """定期查询本机 TCP 连接，用于尽力关联进程。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.exact = {}
        self.listeners = {}
        self.names = {}
        self.updated = 0.0
        self.error = ""
        self.thread = threading.Thread(
            target=self.run, daemon=True
        )
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            try:
                exact = {}
                listeners = {}
                pids = set()

                for connection in psutil.net_connections(kind="tcp"):
                    if connection.pid is None or not connection.laddr:
                        continue

                    local = (
                        normalize_ip(connection.laddr.ip),
                        connection.laddr.port,
                    )
                    pids.add(connection.pid)

                    if connection.raddr:
                        remote = (
                            normalize_ip(connection.raddr.ip),
                            connection.raddr.port,
                        )
                        exact[(local, remote)] = connection.pid
                    elif connection.status == psutil.CONN_LISTEN:
                        listeners[local] = connection.pid

                names = {}
                for pid in pids:
                    try:
                        names[pid] = psutil.Process(pid).name()
                    except psutil.Error:
                        names[pid] = "进程名未知"

                with self.lock:
                    self.exact = exact
                    self.listeners = listeners
                    self.names = names
                    self.updated = time.monotonic()
                    self.error = ""

            except Exception as error:
                with self.lock:
                    self.exact = {}
                    self.listeners = {}
                    self.names = {}
                    self.error = str(error)

            self.stop_event.wait(0.5)

    def lookup(self, packet):
        if (
            packet["transport"] != "TCP"
            or packet["sport"] is None
        ):
            return None, None, ""

        source = (packet["src"], packet["sport"])
        destination = (packet["dst"], packet["dport"])
        wildcard = "::" if packet["family"] == "IPv6" else "0.0.0.0"

        with self.lock:
            if time.monotonic() - self.updated > 3:
                return None, None, ""

            source_pid = self.exact.get((source, destination))
            destination_pid = self.exact.get((destination, source))

            if source_pid is None:
                source_pid = self.listeners.get(
                    source,
                    self.listeners.get((wildcard, source[1])),
                )

            if destination_pid is None:
                destination_pid = self.listeners.get(
                    destination,
                    self.listeners.get((wildcard, destination[1])),
                )

            labels = []
            for pid in sorted({
                pid
                for pid in (source_pid, destination_pid)
                if pid is not None
            }):
                labels.append(
                    f"{pid}/{self.names.get(pid, '进程名未知')}"
                )

        return source_pid, destination_pid, " ↔ ".join(labels)

    def close(self):
        self.stop_event.set()


class FlowIndex:
    """按双向端点归并 TCP 连接，并根据新的 SYN 区分端点复用。"""

    def __init__(self):
        self.current = {}
        self.number = 0

    def assign(self, packet):
        if (
            packet["transport"] != "TCP"
            or packet["sport"] is None
        ):
            return None

        source = (packet["src"], packet["sport"])
        destination = (packet["dst"], packet["dport"])
        endpoints = tuple(sorted((source, destination)))
        key = (packet["family"], endpoints)

        state = self.current.get(key)
        initial_syn = (
            packet["flags"] & 0x02
            and not packet["flags"] & 0x10
        )

        if initial_syn:
            signature = (source, packet["seq"])
            if state is None or state[1] != signature:
                self.number += 1
                state = (self.number, signature)
                self.current[key] = state

        elif state is None:
            self.number += 1
            state = (self.number, None)
            self.current[key] = state

        return state[0]


def decode_packet(timestamp, wire_length, raw, link_type, flows, processes):
    packet = {
        "ts": timestamp,
        "wire": wire_length,
        "raw": raw,
        "family": "",
        "src": "",
        "dst": "",
        "transport": "OTHER",
        "protocol": "OTHER",
        "sport": None,
        "dport": None,
        "seq": None,
        "flags": 0,
        "flow": None,
        "pid_src": None,
        "pid_dst": None,
        "process": "",
        "info": f"链路层报文，捕获 {len(raw)} 字节",
    }

    network = basic.parse_network(raw, link_type)

    if network is not None:
        (
            family, source, destination, number,
            segment, fragment_offset, _,
        ) = network

        packet["family"] = family
        packet["src"] = source
        packet["dst"] = destination
        packet["transport"] = {6: "TCP", 17: "UDP"}.get(
            number, "OTHER"
        )

        parsed = basic.parse_packet(raw, link_type)
        if parsed is not None:
            packet["protocol"] = parsed[2]
            packet["info"] = parsed[3]
        else:
            packet["protocol"] = family
            packet["info"] = f"协议号 {number}，字段不完整或尚未解析"

        if (
            not fragment_offset
            and number in (6, 17)
            and len(segment) >= (20 if number == 6 else 8)
        ):
            packet["sport"] = int.from_bytes(segment[:2], "big")
            packet["dport"] = int.from_bytes(segment[2:4], "big")

            if number == 6:
                packet["seq"] = int.from_bytes(segment[4:8], "big")
                packet["flags"] = segment[13]

        packet["flow"] = flows.assign(packet)

        if processes is not None:
            (
                packet["pid_src"],
                packet["pid_dst"],
                packet["process"],
            ) = processes.lookup(packet)

    if wire_length > len(raw):
        packet["info"] += "  [捕获数据已截断]"

    return packet


class Session:
    """原始数据和索引写入临时数据库，界面仅加载匹配的最近记录。"""

    def __init__(self):
        self.directory = Path(tempfile.mkdtemp(prefix="ex1a_"))
        self.path = self.directory / "capture.sqlite"
        self.link_type = None
        self.total = 0
        self.flows = FlowIndex()

        connection = self.connect()
        try:
            connection.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE packets (
                    id INTEGER PRIMARY KEY,
                    ts INTEGER NOT NULL,
                    wire INTEGER NOT NULL,
                    raw BLOB NOT NULL,
                    family TEXT,
                    src TEXT,
                    dst TEXT,
                    transport TEXT,
                    protocol TEXT,
                    sport INTEGER,
                    dport INTEGER,
                    seq INTEGER,
                    flags INTEGER,
                    flow INTEGER,
                    pid_src INTEGER,
                    pid_dst INTEGER,
                    process TEXT,
                    info TEXT
                );
                CREATE INDEX packet_flow ON packets(flow, id);
                CREATE INDEX packet_protocol ON packets(protocol, id);
                CREATE INDEX packet_family ON packets(family, id);
            """)
        finally:
            connection.close()

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def set_link_type(self, link_type):
        if link_type not in (cap.DLT_NULL, cap.DLT_EN10MB):
            raise RuntimeError(
                f"暂不支持数据链路类型 {link_type}。"
            )

        if self.link_type is not None and self.link_type != link_type:
            raise RuntimeError(
                "新网卡的数据链路类型与当前记录不同。"
                "请先保存 PCAP，再点击“清空记录”后切换网卡。"
            )

        self.link_type = link_type

    def ingest(self, items, stop_event=None, processes=None):
        connection = self.connect()
        pending = 0
        last_id = self.total
        last_commit = time.monotonic()

        try:
            for item in items:
                if stop_event is not None and stop_event.is_set():
                    break

                if item is not None:
                    timestamp, wire_length, raw, link_type = item
                    self.set_link_type(link_type)
                    packet = decode_packet(
                        timestamp, wire_length, raw,
                        link_type, self.flows, processes,
                    )
                    cursor = connection.execute(INSERT_SQL, packet)
                    last_id = cursor.lastrowid
                    pending += 1

                if pending and (
                    pending >= 100
                    or time.monotonic() - last_commit >= 0.2
                ):
                    connection.commit()
                    self.total = last_id
                    pending = 0
                    last_commit = time.monotonic()

        finally:
            try:
                connection.commit()
                if pending:
                    self.total = last_id
            finally:
                connection.close()
                close = getattr(items, "close", None)
                if close is not None:
                    close()

    def query(self, filters):
        conditions = []
        parameters = []

        protocol = filters.get("protocol", "全部")

        if protocol in ("IPv4", "IPv6"):
            conditions.append("family = ?")
            parameters.append(protocol)
        elif protocol == "TCP":
            conditions.append("transport = 'TCP'")
        elif protocol == "ICMP":
            conditions.append("protocol IN ('ICMP', 'ICMPv6')")
        elif protocol != "全部":
            conditions.append("protocol = ?")
            parameters.append(protocol)

        address = filters.get("ip")
        if address:
            conditions.append("(src = ? OR dst = ?)")
            parameters.extend((address, address))

        port = filters.get("port")
        if port is not None:
            conditions.append("(sport = ? OR dport = ?)")
            parameters.extend((port, port))

        pid = filters.get("pid")
        if pid is not None:
            conditions.append("(pid_src = ? OR pid_dst = ?)")
            parameters.extend((pid, pid))

        where = ""
        if conditions:
            where = " WHERE " + " AND ".join(conditions)

        connection = self.connect()
        try:
            rows = connection.execute(
                METADATA_SQL + where
                + f" ORDER BY id DESC LIMIT {DISPLAY_LIMIT}",
                parameters,
            ).fetchall()
            return list(reversed(rows))
        finally:
            connection.close()

    def get(self, packet_id):
        connection = self.connect()
        try:
            return connection.execute(
                "SELECT * FROM packets WHERE id = ?",
                (packet_id,),
            ).fetchone()
        finally:
            connection.close()

    def close(self):
        shutil.rmtree(self.directory, ignore_errors=True)


@contextmanager
def npc_library():
    directory = Path(os.environ["SystemRoot"]) / "System32" / "Npcap"
    with os.add_dll_directory(str(directory)):
        pcap = c.CDLL(str(directory / "wpcap.dll"))
        cap.configure_api(pcap)
        yield pcap


def capture_items(pcap, device, stop_event, session, ready=None):
    error = c.create_string_buffer(cap.PCAP_ERRBUF_SIZE)
    handle = pcap.pcap_open_live(device, 65535, 0, 100, error)

    if not handle:
        raise RuntimeError(
            error.value.decode("mbcs", errors="replace")
        )

    try:
        link_type = pcap.pcap_datalink(handle)
        session.set_link_type(link_type)

        if pcap.pcap_setnonblock(handle, 1, error) != 0:
            raise RuntimeError(
                error.value.decode("mbcs", errors="replace")
            )

        if ready is not None:
            ready.set()

        header = cap.HeaderPointer()
        data = cap.PacketPointer()

        while not stop_event.is_set():
            result = pcap.pcap_next_ex(
                handle, c.byref(header), c.byref(data)
            )

            if result == 0:
                stop_event.wait(0.02)
                yield None
                continue

            if result != 1:
                raise RuntimeError(
                    pcap.pcap_geterr(handle).decode(
                        "mbcs", errors="replace"
                    )
                )

            metadata = header.contents
            timestamp = (
                metadata.seconds * 1_000_000
                + metadata.microseconds
            )
            raw = c.string_at(data, metadata.captured_length)

            yield (
                timestamp,
                metadata.original_length,
                raw,
                link_type,
            )

    finally:
        pcap.pcap_close(handle)


def read_pcap(path):
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }

    with open(path, "rb") as source:
        header = source.read(24)

        if len(header) != 24 or header[:4] not in formats:
            raise ValueError("请选择标准 PCAP 文件。")

        endian, scale = formats[header[:4]]
        major, minor, _, _, snaplen, network = struct.unpack(
            endian + "HHiIII", header[4:]
        )

        if (major, minor) != (2, 4):
            raise ValueError("PCAP 版本暂不支持。")

        link_type = network & 0xFFFF
        if link_type not in (cap.DLT_NULL, cap.DLT_EN10MB):
            raise ValueError(
                f"PCAP 数据链路类型 {link_type} 暂不支持。"
            )

        while True:
            record = source.read(16)
            if not record:
                return
            if len(record) != 16:
                raise ValueError("PCAP 记录头不完整。")

            seconds, fraction, captured, wire_length = struct.unpack(
                endian + "IIII", record
            )

            if (
                captured > MAX_PACKET_SIZE
                or (snaplen and captured > snaplen)
                or wire_length < captured
                or fraction >= scale
            ):
                raise ValueError("PCAP 记录长度或时间戳无效。")

            raw = source.read(captured)
            if len(raw) != captured:
                raise ValueError("PCAP 数据包内容不完整。")

            timestamp = (
                seconds * 1_000_000
                + fraction * 1_000_000 // scale
            )
            yield timestamp, wire_length, raw, link_type


def load_pcap(path, cancel_event):
    session = Session()

    try:
        session.ingest(read_pcap(path), cancel_event)
        if cancel_event.is_set():
            raise RuntimeError("打开文件已取消。")
        return session
    except Exception:
        session.close()
        raise


def save_pcap(session, path, cancel_event):
    if session.total == 0 or session.link_type is None:
        raise ValueError("当前没有可保存的数据包。")

    destination = Path(path)
    connection = session.connect()
    temporary = None

    try:
        connection.execute("BEGIN")
        maximum = connection.execute(
            "SELECT MAX(length(raw)) FROM packets"
        ).fetchone()[0]

        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=".ex1a_",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(struct.pack(
                "<IHHIIII",
                0xA1B2C3D4, 2, 4, 0, 0,
                max(65535, maximum or 0),
                session.link_type,
            ))

            for row in connection.execute(
                "SELECT ts, wire, raw FROM packets ORDER BY id"
            ):
                if cancel_event.is_set():
                    raise RuntimeError("保存已取消。")

                seconds, microseconds = divmod(
                    row["ts"], 1_000_000
                )
                if not 0 <= seconds <= 0xFFFFFFFF:
                    raise ValueError(
                        "数据包时间超出标准 PCAP 的保存范围。"
                    )

                raw = bytes(row["raw"])
                output.write(struct.pack(
                    "<IIII",
                    seconds, microseconds,
                    len(raw), row["wire"],
                ))
                output.write(raw)

            output.flush()
            os.fsync(output.fileno())

        if cancel_event.is_set():
            raise RuntimeError("保存已取消。")

        os.replace(temporary, destination)
        temporary = None
        return str(destination)

    finally:
        connection.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def tcp_payload(row, link_type):
    network = basic.parse_network(bytes(row["raw"]), link_type)

    if network is None:
        return b""

    _, _, _, number, segment, offset, _ = network
    if number != 6 or offset or len(segment) < 20:
        return b""

    header_length = (segment[12] >> 4) * 4
    if header_length < 20 or header_length > len(segment):
        return b""

    return segment[header_length:]


def assemble_segments(segments):
    """按序号排序，跳过重复覆盖字节，并标明捕获缺口。"""
    if not segments:
        return "此方向没有捕获到 TCP 应用数据。"

    reference = segments[0][0]
    ordered = []

    for order, (sequence, payload) in enumerate(segments):
        offset = (
            (sequence - reference + 0x80000000) % 0x100000000
            - 0x80000000
        )
        ordered.append((offset, order, payload))

    ordered.sort(key=lambda item: (item[0], item[1]))

    result = bytearray()
    cursor = None
    displayed = 0
    gaps = 0

    for offset, _, payload in ordered:
        if cursor is None:
            cursor = offset

        if offset > cursor:
            missing = offset - cursor
            marker = f"\n[缺失 {missing} 字节]\n".encode("utf-8")
            result.extend(marker)
            gaps += 1
            cursor = offset

        skip = max(0, cursor - offset)
        if skip >= len(payload):
            continue

        remaining = MAX_STREAM_DISPLAY - displayed
        if remaining <= 0:
            result.extend("\n[达到本窗口显示上限]\n".encode("utf-8"))
            break

        chunk = payload[skip:skip + remaining]
        result.extend(chunk)
        displayed += len(chunk)
        cursor = offset + skip + len(chunk)

        if skip + len(chunk) < len(payload):
            result.extend("\n[达到本窗口显示上限]\n".encode("utf-8"))
            break

    text = result.decode("utf-8", errors="replace")
    text = text.replace("\x00", "\\x00")

    if gaps:
        text += f"\n\n[共发现 {gaps} 个捕获缺口]"

    return text


def load_flow(session, flow_id, cancel_event):
    connection = session.connect()
    rows = []
    size = 0
    limited = False

    try:
        connection.execute("BEGIN")

        for row in connection.execute(
            "SELECT * FROM packets WHERE flow = ? ORDER BY id",
            (flow_id,),
        ):
            if cancel_event.is_set():
                raise RuntimeError("TCP 流读取已取消。")

            size += len(row["raw"])
            if size > MAX_FLOW_READ:
                limited = True
                break
            rows.append(row)

    finally:
        connection.close()

    if not rows:
        raise ValueError("没有找到这条 TCP 流。")

    first = rows[0]
    endpoint_a = (first["src"], first["sport"])
    endpoint_b = (first["dst"], first["dport"])
    forward = []
    backward = []

    for row in rows:
        payload = tcp_payload(row, session.link_type)
        if not payload:
            continue

        sequence = (
            row["seq"] + (1 if row["flags"] & 0x02 else 0)
        ) % 0x100000000

        source = (row["src"], row["sport"])
        target = forward if source == endpoint_a else backward
        target.append((sequence, payload))

    return {
        "flow": flow_id,
        "rows": rows[:2000],
        "a": endpoint_a,
        "b": endpoint_b,
        "forward": assemble_segments(forward),
        "backward": assemble_segments(backward),
        "limited": limited or len(rows) > 2000,
    }


def hex_dump(raw):
    lines = []

    for offset in range(0, min(len(raw), 65536), 16):
        chunk = raw[offset:offset + 16]
        hexadecimal = " ".join(f"{value:02x}" for value in chunk)
        printable = "".join(
            chr(value) if 32 <= value < 127 else "."
            for value in chunk
        )
        lines.append(
            f"{offset:06x}  {hexadecimal:<47}  {printable}"
        )

    if len(raw) > 65536:
        lines.append(
            "\n[原始字节窗口显示前 65536 字节，PCAP 保存完整捕获数据]"
        )

    return "\n".join(lines)


def packet_values(row):
    timestamp = datetime.fromtimestamp(
        row["ts"] / 1_000_000
    ).strftime("%H:%M:%S.%f")[:-3]

    return (
        row["id"], timestamp,
        row["src"] or "-",
        row["dst"] or "-",
        row["protocol"],
        "" if row["sport"] is None else row["sport"],
        "" if row["dport"] is None else row["dport"],
        row["process"] or "未知",
        row["wire"],
        row["info"],
    )


def create_packet_table(parent):
    frame = ttk.Frame(parent)
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)

    columns = (
        "id", "time", "source", "destination", "protocol",
        "sport", "dport", "process", "length", "info",
    )
    headings = (
        "序号", "时间", "源 IP", "目的 IP", "协议",
        "源端口", "目的端口", "本机进程", "长度", "信息",
    )
    widths = (60, 110, 230, 230, 75, 75, 75, 180, 65, 450)

    table = ttk.Treeview(
        frame, columns=columns, show="headings"
    )

    for name, heading, width in zip(columns, headings, widths):
        table.heading(name, text=heading)
        table.column(name, width=width, minwidth=45)

    vertical = ttk.Scrollbar(
        frame, orient="vertical", command=table.yview
    )
    horizontal = ttk.Scrollbar(
        frame, orient="horizontal", command=table.xview
    )
    table.configure(
        yscrollcommand=vertical.set,
        xscrollcommand=horizontal.set,
    )

    table.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    return frame, table


def put_text(widget, text):
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", text)
    widget.configure(state="disabled")



# EX1A_TCP_TIMELINE_V1
class TCPFlowTimeline(ttk.Frame):
    """以捕获顺序等距绘制报文，时间标签保留实际捕获时间。"""

    def __init__(self, parent, rows, endpoint_a, endpoint_b, link_type):
        super().__init__(parent)
        self.endpoint_a = endpoint_a
        self.endpoint_b = endpoint_b
        self.pending_redraw = None
        self.packets = []

        for row in rows:
            network = basic.parse_network(bytes(row["raw"]), link_type)
            acknowledgment = None
            payload_length = None

            if network is not None:
                _, _, _, number, segment, fragment_offset, _ = network
                if number == 6 and not fragment_offset and len(segment) >= 20:
                    header_length = (segment[12] >> 4) * 4
                    if 20 <= header_length <= len(segment):
                        acknowledgment = int.from_bytes(segment[8:12], "big")
                        payload_length = len(segment) - header_length

            flags = [
                name
                for mask, name in (
                    (0x01, "FIN"), (0x02, "SYN"),
                    (0x04, "RST"), (0x08, "PSH"),
                    (0x10, "ACK"), (0x20, "URG"),
                    (0x40, "ECE"), (0x80, "CWR"),
                )
                if row["flags"] & mask
            ]

            self.packets.append({
                "id": row["id"],
                "ts": row["ts"],
                "forward": (row["src"], row["sport"]) == endpoint_a,
                "protocol": row["protocol"],
                "flags": ", ".join(flags) or "无标志",
                "sequence": row["seq"],
                "acknowledgment": acknowledgment,
                "payload_length": payload_length,
                "wire_length": row["wire"],
            })

        note = (
            "纵向按抓包顺序等距排列，时间标签为本机捕获时间。"
            "Seq/Ack 为原始 TCP 序号。"
            "箭头表示报文方向，长度不代表传输耗时。"
        )
        self.note = ttk.Label(self, text=note, padding=8, wraplength=950)
        self.note.grid(row=0, column=0, columnspan=2, sticky="ew")

        style = ttk.Style(self)
        background = style.lookup("TFrame", "background") or "#f0f0f0"
        self.foreground = style.lookup("TLabel", "foreground") or "#202020"
        self.canvas = tk.Canvas(
            self, background=background, highlightthickness=0,
            xscrollincrement=24, yscrollincrement=24,
        )
        vertical = ttk.Scrollbar(
            self, orient="vertical", command=self.canvas.yview
        )
        horizontal = ttk.Scrollbar(
            self, orient="horizontal", command=self.canvas.xview
        )
        self.canvas.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )
        self.canvas.grid(row=1, column=0, sticky="nsew")
        vertical.grid(row=1, column=1, sticky="ns")
        horizontal.grid(row=2, column=0, sticky="ew")
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)
        self.canvas.bind("<Configure>", self.request_redraw)
        self.canvas.bind("<MouseWheel>", self.scroll_mouse)
        self.canvas.bind(
            "<Button-4>", lambda event: self.canvas.yview_scroll(-3, "units")
        )
        self.canvas.bind(
            "<Button-5>", lambda event: self.canvas.yview_scroll(3, "units")
        )
        self.bind("<Destroy>", self.cancel_redraw)
        self.request_redraw()

    def request_redraw(self, event=None):
        if self.pending_redraw is not None:
            self.after_cancel(self.pending_redraw)
        self.pending_redraw = self.after(60, self.draw)

    def cancel_redraw(self, event):
        if event.widget is self and self.pending_redraw is not None:
            self.after_cancel(self.pending_redraw)
            self.pending_redraw = None

    def scroll_mouse(self, event):
        if event.delta:
            units = max(1, abs(event.delta) // 120)
            direction = -1 if event.delta > 0 else 1
            self.canvas.yview_scroll(direction * units * 3, "units")
        return "break"

    def draw(self):
        self.pending_redraw = None
        canvas = self.canvas
        old_position = canvas.yview()[0]
        canvas.delete("all")
        width = max(960, canvas.winfo_width())
        self.note.configure(wraplength=max(500, canvas.winfo_width() - 30))
        x_a = 360
        x_b = width - 170
        center = (x_a + x_b) / 2
        text_width = x_b - x_a - 36
        row_height = 112
        y_first = 132
        height = max(320, y_first + len(self.packets) * row_height + 40)

        def text(x, y, value, **options):
            return canvas.create_text(
                x, y, text=value, fill=self.foreground,
                font="TkDefaultFont", **options
            )

        text(16, 20, "报文序号 / 相对首包时间\n本机捕获时间", anchor="nw")
        text(
            x_a, 20,
            f"A\n[{self.endpoint_a[0]}]:{self.endpoint_a[1]}",
            width=250, anchor="n",
        )
        text(
            x_b, 20,
            f"B\n[{self.endpoint_b[0]}]:{self.endpoint_b[1]}",
            width=250, anchor="n",
        )
        text(center, 86, "时间顺序向下 ↓", anchor="center")
        canvas.create_line(
            x_a, 100, x_a, height - 20,
            fill=self.foreground, dash=(4, 4),
        )
        canvas.create_line(
            x_b, 100, x_b, height - 20,
            fill=self.foreground, dash=(4, 4),
        )

        if not self.packets:
            text(center, 180, "这条 TCP 流没有可绘制的报文。")
        else:
            first_timestamp = self.packets[0]["ts"]

            for index, packet in enumerate(self.packets):
                y = y_first + index * row_height
                relative_ms = (packet["ts"] - first_timestamp) / 1000
                timestamp = datetime.fromtimestamp(
                    packet["ts"] / 1_000_000
                ).strftime("%H:%M:%S.%f")
                text(
                    16, y - 8,
                    f"#{packet['id']}  {relative_ms:.3f} ms\n{timestamp}",
                    anchor="nw",
                )

                if packet["forward"]:
                    start, end = x_a + 8, x_b - 8
                    direction = "A → B"
                else:
                    start, end = x_b - 8, x_a + 8
                    direction = "B → A"

                canvas.create_line(
                    start, y, end, y,
                    arrow="last", arrowshape=(10, 12, 4),
                    width=2, fill=self.foreground,
                )
                acknowledgment = packet["acknowledgment"]
                acknowledgment = "-" if acknowledgment is None else acknowledgment
                payload_length = packet["payload_length"]
                payload_length = "-" if payload_length is None else payload_length

                summary = (
                    f"{direction}  {packet['protocol']} [{packet['flags']}]\n"
                    f"Seq={packet['sequence']}  Ack={acknowledgment}\n"
                    f"Data={payload_length} B  Frame={packet['wire_length']} B"
                )
                text(
                    center, y + 9, summary,
                    width=text_width, anchor="n",
                )

        canvas.configure(scrollregion=(0, 0, width, height))
        canvas.yview_moveto(old_position)


class App:
    def __init__(self, root, pcap):
        self.root = root
        self.pcap = pcap
        self.session = Session()
        self.processes = ProcessCache()
        self.interfaces = cap.list_interfaces(pcap)

        if not self.interfaces:
            raise RuntimeError("没有找到可抓包的网卡。")

        self.worker = None
        self.job = None
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.cancel_job = threading.Event()
        self.closing = False
        self.last_total = -1
        self.saved_count = 0
        self.filters = {"protocol": "全部"}
        self.selected_id = None

        root.title("实验 1A — 网络嗅探与协议分析")
        root.geometry("1250x780")
        root.minsize(900, 550)

        top = ttk.Frame(root, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="网卡").pack(side="left")
        self.interface_box = ttk.Combobox(
            top,
            width=52,
            state="readonly",
            values=[
                f"{index}. {description}"
                for index, (_, description) in enumerate(
                    self.interfaces, start=1
                )
            ],
        )
        self.interface_box.pack(side="left", padx=6)

        default = next(
            (
                index
                for index, (_, label) in enumerate(self.interfaces)
                if "Wi-Fi" in label
            ),
            0,
        )
        self.interface_box.current(default)

        self.start_button = ttk.Button(
            top, text="开始抓包", command=self.start
        )
        self.start_button.pack(side="left", padx=4)
        self.stop_button = ttk.Button(
            top, text="停止抓包", command=self.stop
        )
        self.stop_button.pack(side="left", padx=4)

        actions = ttk.Frame(root, padding=(8, 0, 8, 8))
        actions.pack(fill="x")
        self.action_buttons = {}

        for text, command in (
            ("保存全部 PCAP", self.save),
            ("打开 PCAP", self.open_file),
            ("清空记录", self.clear),
            ("追踪所选 TCP 流", self.follow),
            ("自动测试", self.check),
        ):
            button = ttk.Button(actions, text=text, command=command)
            button.pack(side="left", padx=(0, 6))
            self.action_buttons[text] = button

        filters = ttk.Frame(root, padding=(8, 0, 8, 8))
        filters.pack(fill="x")

        ttk.Label(filters, text="协议").pack(side="left")
        self.protocol_box = ttk.Combobox(
            filters,
            width=10,
            state="readonly",
            values=(
                "全部", "IPv4", "IPv6", "TCP",
                "UDP", "ICMP", "ICMPv6", "HTTP", "OTHER",
            ),
        )
        self.protocol_box.current(0)
        self.protocol_box.pack(side="left", padx=5)
        self.protocol_box.bind(
            "<<ComboboxSelected>>", lambda event: self.apply_filter()
        )

        ttk.Label(filters, text="IP").pack(side="left")
        self.ip_entry = ttk.Entry(filters, width=24)
        self.ip_entry.pack(side="left", padx=5)

        ttk.Label(filters, text="端口").pack(side="left")
        self.port_entry = ttk.Entry(filters, width=7)
        self.port_entry.pack(side="left", padx=5)

        ttk.Label(filters, text="PID").pack(side="left")
        self.pid_entry = ttk.Entry(filters, width=8)
        self.pid_entry.pack(side="left", padx=5)

        ttk.Button(
            filters, text="应用筛选", command=self.apply_filter
        ).pack(side="left", padx=5)

        ttk.Label(
            root,
            text=(
                "筛选条件按 AND 组合，IP 和端口匹配任一通信方向。"
                "列表显示最近 1000 条匹配记录，本次会话数据保留至清空或关闭。"
            ),
            padding=(8, 0, 8, 6),
        ).pack(fill="x")

        panes = ttk.Panedwindow(root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=8)

        frame, self.table = create_packet_table(panes)
        panes.add(frame, weight=3)
        self.table.bind("<<TreeviewSelect>>", self.select_packet)

        notebook = ttk.Notebook(panes)
        self.details = ScrolledText(
            notebook, wrap="word", height=12, state="disabled"
        )
        self.bytes_view = ScrolledText(
            notebook,
            wrap="none",
            height=12,
            font=("Consolas", 10),
            state="disabled",
        )
        notebook.add(self.details, text="数据包详情")
        notebook.add(self.bytes_view, text="原始字节")
        panes.add(notebook, weight=2)

        self.status = tk.StringVar(value="准备就绪")
        ttk.Label(
            root, textvariable=self.status, padding=8
        ).pack(fill="x")

        root.protocol("WM_DELETE_WINDOW", self.close)
        self.update_controls()
        root.after(100, self.poll)

    def update_controls(self):
        idle = self.worker is None and self.job is None
        self.start_button.configure(
            state="normal" if idle else "disabled"
        )
        self.stop_button.configure(
            state=(
                "normal"
                if self.worker is not None
                and not self.stop_event.is_set()
                else "disabled"
            )
        )
        self.interface_box.configure(
            state="readonly" if idle else "disabled"
        )

        for text, button in self.action_buttons.items():
            enabled = idle

            if text == "保存全部 PCAP":
                enabled = idle and self.session.total > 0
            elif text == "追踪所选 TCP 流":
                enabled = (
                    self.job is None
                    and self.selected_id is not None
                )

            button.configure(
                state="normal" if enabled else "disabled"
            )

    def start(self):
        if self.worker is not None or self.job is not None:
            return

        device, _ = self.interfaces[self.interface_box.current()]
        self.stop_event.clear()
        session = self.session

        def work():
            try:
                session.ingest(
                    capture_items(
                        self.pcap, device,
                        self.stop_event, session,
                    ),
                    self.stop_event,
                    self.processes,
                )
            except Exception as error:
                self.events.put(("capture_error", str(error)))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.update_controls()

    def stop(self):
        self.stop_event.set()
        self.update_controls()

    def run_job(self, function, success):
        if self.job is not None:
            return

        self.cancel_job.clear()

        def work():
            try:
                result = function()
                self.events.put(("job_done", success, result, None))
            except Exception as error:
                self.events.put(
                    ("job_done", success, None, str(error))
                )

        self.job = threading.Thread(target=work, daemon=True)
        self.job.start()
        self.update_controls()

    def apply_filter(self):
        try:
            address = self.ip_entry.get().strip()
            address = normalize_ip(address) if address else ""

            port_text = self.port_entry.get().strip()
            port = int(port_text) if port_text else None
            if port is not None and not 0 <= port <= 65535:
                raise ValueError("端口范围为 0～65535。")

            pid_text = self.pid_entry.get().strip()
            pid = int(pid_text) if pid_text else None
            if pid is not None and pid < 0:
                raise ValueError("PID 应为非负整数。")

            self.filters = {
                "protocol": self.protocol_box.get(),
                "ip": address,
                "port": port,
                "pid": pid,
            }
            self.refresh_table()

        except ValueError as error:
            messagebox.showerror("筛选条件有误", str(error))

    def refresh_table(self):
        rows = self.session.query(self.filters)
        old_selection = self.selected_id

        existing = self.table.get_children()
        if existing:
            self.table.delete(*existing)

        for row in rows:
            self.table.insert(
                "",
                "end",
                iid=str(row["id"]),
                values=packet_values(row),
            )

        if (
            old_selection is not None
            and self.table.exists(str(old_selection))
        ):
            self.table.selection_set(str(old_selection))
        elif rows and old_selection is None:
            self.table.yview_moveto(1)

        self.last_total = self.session.total

    def select_packet(self, event=None):
        selected = self.table.selection()
        if not selected:
            return

        self.selected_id = int(selected[0])
        row = self.session.get(self.selected_id)
        if row is None:
            return

        timestamp = datetime.fromtimestamp(
            row["ts"] / 1_000_000
        ).isoformat(timespec="microseconds")

        fields = [
            ("序号", row["id"]),
            ("时间", timestamp),
            ("IP 版本", row["family"] or "未知"),
            ("源 IP", row["src"] or "-"),
            ("目的 IP", row["dst"] or "-"),
            ("传输层", row["transport"]),
            ("识别协议", row["protocol"]),
            ("源端口", row["sport"]),
            ("目的端口", row["dport"]),
            ("TCP 序列号", row["seq"]),
            ("TCP 标志位", hex(row["flags"])),
            ("TCP 流编号", row["flow"]),
            ("捕获长度", len(row["raw"])),
            ("原始长度", row["wire"]),
            ("本机进程快照", row["process"] or "未知"),
            ("信息", row["info"]),
        ]

        put_text(
            self.details,
            "\n".join(
                f"{name}    {value if value is not None else '-'}"
                for name, value in fields
            ),
        )
        put_text(self.bytes_view, hex_dump(bytes(row["raw"])))
        self.update_controls()

    def save(self):
        if self.worker is not None or self.job is not None:
            return

        path = filedialog.asksaveasfilename(
            title="保存本次会话全部记录",
            defaultextension=".pcap",
            filetypes=[("PCAP 抓包文件", "*.pcap")],
            initialfile="ex1a_capture.pcap",
        )
        if not path:
            return

        session = self.session

        def success(result):
            self.saved_count = session.total
            messagebox.showinfo(
                "保存成功",
                f"已保存 {session.total} 条记录。\n{result}",
            )

        self.run_job(
            lambda: save_pcap(session, path, self.cancel_job),
            success,
        )

    def can_discard(self):
        if self.session.total <= self.saved_count:
            return True
        return messagebox.askyesno(
            "存在未保存的记录",
            "当前会话还有未保存的记录，是否继续？",
        )

    def replace_session(self, session, saved=False):
        old = self.session
        self.session = session
        self.saved_count = session.total if saved else 0
        self.selected_id = None
        self.last_total = -1
        put_text(self.details, "")
        put_text(self.bytes_view, "")
        self.refresh_table()
        old.close()
        self.update_controls()

    def clear(self):
        if self.worker is not None or self.job is not None:
            return
        if self.can_discard():
            self.replace_session(Session())

    def open_file(self):
        if self.worker is not None or self.job is not None:
            return

        path = filedialog.askopenfilename(
            filetypes=[("PCAP 抓包文件", "*.pcap")]
        )
        if not path or not self.can_discard():
            return

        self.run_job(
            lambda: load_pcap(path, self.cancel_job),
            lambda session: self.replace_session(session, saved=True),
        )

    def follow(self):
        if self.selected_id is None or self.job is not None:
            return

        row = self.session.get(self.selected_id)
        if row is None or row["flow"] is None:
            messagebox.showinfo(
                "选择 TCP 数据包",
                "请先选中一条 TCP 或 HTTP 记录。",
            )
            return

        session = self.session
        flow_id = row["flow"]

        self.run_job(
            lambda: load_flow(
                session, flow_id, self.cancel_job
            ),
            self.show_flow,
        )

    def show_flow(self, result):
        window = tk.Toplevel(self.root)
        window.title(f"TCP 流 {result['flow']}")
        window.geometry("1100x650")

        a = result["a"]
        b = result["b"]
        labels = (
            f"A = [{a[0]}]:{a[1]}    "
            f"B = [{b[0]}]:{b[1]}"
        )
        ttk.Label(
            window, text=labels, padding=8
        ).pack(fill="x")

        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True)

        timeline = TCPFlowTimeline(
            notebook, result["rows"],
            result["a"], result["b"], self.session.link_type,
        )
        notebook.add(timeline, text="流时序图")

        frame, table = create_packet_table(notebook)
        notebook.add(frame, text="双向数据包")

        for row in result["rows"]:
            table.insert(
                "", "end", values=packet_values(row)
            )

        for title, content in (
            ("A → B 应用数据", result["forward"]),
            ("B → A 应用数据", result["backward"]),
        ):
            text = ScrolledText(
                notebook,
                wrap="none",
                font=("Consolas", 10),
            )
            put_text(text, content)
            notebook.add(text, text=title)

        notice = (
            "按 TCP 序号整理，重复覆盖部分跳过，缺口会标注。"
            "重叠冲突采用排序后先出现的数据。"
        )
        if result["limited"]:
            notice += (
                " 此流较大，本窗口限制读取 16 MiB，"
                "报文表最多显示 2000 条。"
            )

        ttk.Label(
            window, text=notice, padding=8, wraplength=1000
        ).pack(fill="x")

    def check(self):
        if self.worker is not None or self.job is not None:
            return

        def work():
            environment = dict(os.environ)
            environment["PYTHONIOENCODING"] = "utf-8"

            process = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--check"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            started = time.monotonic()

            while process.poll() is None:
                if (
                    self.cancel_job.wait(0.1)
                    or time.monotonic() - started > 90
                ):
                    process.terminate()
                    try:
                        process.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                    raise RuntimeError("自动测试已取消或超时。")

            output = process.communicate()[0].decode(
                "utf-8", errors="replace"
            )
            if process.returncode:
                raise RuntimeError(output)
            return output

        self.run_job(
            work,
            lambda output: messagebox.showinfo(
                "自动测试结果", output
            ),
        )

    def poll(self):
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break

            if event[0] == "capture_error":
                if not self.closing:
                    messagebox.showerror("抓包失败", event[1])

            elif event[0] == "job_done":
                _, success, result, error = event
                self.job = None

                if self.closing:
                    if isinstance(result, Session):
                        result.close()
                elif error:
                    messagebox.showerror("操作失败", error)
                else:
                    success(result)

        if self.worker is not None and not self.worker.is_alive():
            self.worker = None

        if self.closing:
            if self.worker is None and self.job is None:
                self.processes.close()
                self.session.close()
                self.root.destroy()
                return
        else:
            if self.session.total != self.last_total:
                self.refresh_table()

            state = "已停止"
            if self.worker is not None:
                state = (
                    "正在停止"
                    if self.stop_event.is_set()
                    else "抓包中"
                )
            if self.job is not None:
                state += " · 后台操作中"

            self.status.set(
                f"{state} · 会话已归档 {self.session.total} 条"
                f" · 列表显示 {len(self.table.get_children())} 条匹配记录"
            )

        self.update_controls()
        self.root.after(500, self.poll)

    def close(self):
        if not self.closing and not self.can_discard():
            return

        self.closing = True
        self.stop_event.set()
        self.cancel_job.set()
        self.status.set("正在停止后台任务并关闭……")


# 以下为自动测试代码。


def test_frame(family, protocol, payload, reverse=False):
    if family == "IPv4":
        source = "192.0.2.1"
        destination = "192.0.2.2"
        if reverse:
            source, destination = destination, source

        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + len(payload), 0, 0,
            64, protocol, 0,
            socket.inet_aton(source),
            socket.inet_aton(destination),
        )
        ether_type = b"\x08\x00"

    else:
        source = "2001:db8::1"
        destination = "2001:db8::2"
        if reverse:
            source, destination = destination, source

        header = struct.pack(
            "!IHBB16s16s",
            6 << 28, len(payload), protocol, 64,
            socket.inet_pton(socket.AF_INET6, source),
            socket.inet_pton(socket.AF_INET6, destination),
        )
        ether_type = b"\x86\xdd"

    return bytes(12) + ether_type + header + payload


def test_tcp(sequence, payload=b"", flags=0x18, reverse=False):
    source, destination = (8000, 45000) if reverse else (45000, 8000)
    return struct.pack(
        "!HHIIBBHHH",
        source, destination, sequence, 0,
        5 << 4, flags, 65535, 0, 0,
    ) + payload


def test_udp(payload=b"lab"):
    return struct.pack(
        "!HHHH", 45001, 9000, len(payload) + 8, 0
    ) + payload


class Checks(unittest.TestCase):
    def setUp(self):
        self.session = Session()

    def tearDown(self):
        self.session.close()

    def add(self, frames):
        self.session.ingest(
            (
                1_700_000_000_000_000 + index,
                len(frame),
                frame,
                cap.DLT_EN10MB,
            )
            for index, frame in enumerate(frames)
        )

    def test_ipv4_ipv6_protocols(self):
        frames = [
            test_frame("IPv4", 6, test_tcp(
                100, b"GET / HTTP/1.1\r\n\r\n"
            )),
            test_frame("IPv6", 6, test_tcp(
                100, b"GET / HTTP/1.1\r\n\r\n"
            )),
            test_frame("IPv4", 17, test_udp()),
            test_frame("IPv6", 17, test_udp()),
            test_frame("IPv4", 1, b"\x08\x00" + bytes(6)),
            test_frame("IPv6", 58, b"\x80\x00" + bytes(6)),
        ]
        self.add(frames)

        self.assertEqual(self.session.total, 6)
        self.assertEqual(
            len(self.session.query({"protocol": "IPv6"})), 3
        )
        self.assertEqual(
            len(self.session.query({"protocol": "TCP"})), 2
        )
        self.assertEqual(
            len(self.session.query({
                "protocol": "TCP",
                "ip": "2001:db8::1",
                "port": 8000,
            })),
            1,
        )

    def test_history_and_pcap_roundtrip(self):
        icmp = test_frame(
            "IPv4", 1, b"\x08\x00" + bytes(6)
        )
        udp = test_frame("IPv4", 17, test_udp())
        self.add([icmp] + [udp] * 1005)

        self.assertEqual(self.session.total, 1006)
        self.assertEqual(
            len(self.session.query({"protocol": "全部"})), 1000
        )
        self.assertEqual(
            len(self.session.query({"protocol": "ICMP"})), 1
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "roundtrip.pcap"
            save_pcap(self.session, path, threading.Event())
            packets = list(read_pcap(path))
            self.assertEqual(len(packets), 1006)
            self.assertEqual(packets[0][2], icmp)

            restored = load_pcap(path, threading.Event())
            try:
                self.assertEqual(restored.total, 1006)
            finally:
                restored.close()

    def test_tcp_reordering_retransmission_and_reuse(self):
        request = b"GET /split HTTP/1.1\r\nHost: local\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\n\r\nOK"

        self.add([
            test_frame("IPv4", 6, test_tcp(100, flags=0x02)),
            test_frame("IPv4", 6, test_tcp(111, request[10:])),
            test_frame("IPv4", 6, test_tcp(101, request[:10])),
            test_frame("IPv4", 6, test_tcp(101, request[:10])),
            test_frame("IPv4", 6, test_tcp(
                5000, response, reverse=True
            ), reverse=True),
            test_frame("IPv4", 6, test_tcp(900, flags=0x02)),
        ])

        rows = self.session.query({"protocol": "TCP"})
        self.assertNotEqual(rows[0]["flow"], rows[-1]["flow"])

        result = load_flow(
            self.session, rows[0]["flow"], threading.Event()
        )
        self.assertIn(request.decode(), result["forward"])
        self.assertIn(response.decode(), result["backward"])
        self.assertEqual(result["forward"].count("GET /split"), 1)

    def test_tcp_gap_and_sequence_wrap(self):
        text = assemble_segments([
            (100, b"abc"), (106, b"xyz"), (100, b"abc")
        ])
        self.assertIn("缺失 3 字节", text)
        self.assertEqual(
            assemble_segments([
                (0xFFFFFFFE, b"ab"), (0, b"cd")
            ]),
            "abcd",
        )


def local_exchange(family, kind):
    host = "127.0.0.1" if family == socket.AF_INET else "::1"
    errors = []

    with socket.socket(family, kind) as server:
        server.settimeout(4)
        server.bind((host, 0))
        address = server.getsockname()

        if kind == socket.SOCK_STREAM:
            server.listen(1)

        def respond():
            try:
                if kind == socket.SOCK_STREAM:
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(4)
                        request = b""
                        while b"\r\n\r\n" not in request:
                            chunk = connection.recv(4096)
                            if not chunk:
                                break
                            request += chunk
                        connection.sendall(
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Length: 2\r\n"
                            b"Connection: close\r\n\r\nOK"
                        )
                else:
                    payload, peer = server.recvfrom(4096)
                    server.sendto(payload, peer)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=respond, daemon=True)
        thread.start()

        with socket.socket(family, kind) as client:
            client.settimeout(4)

            if kind == socket.SOCK_STREAM:
                client.connect(address)
                client.sendall(
                    b"GET /self-test HTTP/1.1\r\n"
                    b"Host: localhost\r\n\r\n"
                )
                reply = b""
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    reply += chunk
                if b"200 OK" not in reply:
                    raise RuntimeError("本机 TCP 服务应答异常。")
            else:
                client.sendto(b"ex1a_udp_test", address)
                reply, _ = client.recvfrom(4096)
                if reply != b"ex1a_udp_test":
                    raise RuntimeError("本机 UDP 回显异常。")

        thread.join(5)
        if thread.is_alive():
            raise RuntimeError("本机测试服务未正常结束。")
        if errors:
            raise errors[0]

        return address[1]


def live_checks():
    session = Session()

    try:
        with npc_library() as pcap:
            interfaces = cap.list_interfaces(pcap)
            device = next(
                (
                    name
                    for name, _ in interfaces
                    if name == cap.LOOPBACK_DEVICE
                ),
                None,
            )
            if device is None:
                raise RuntimeError("未找到 Npcap Loopback 网卡。")

            for round_number in (1, 2):
                before = session.total
                stop_event = threading.Event()
                ready = threading.Event()
                errors = []

                def capture_work():
                    try:
                        session.ingest(
                            capture_items(
                                pcap, device, stop_event,
                                session, ready,
                            ),
                            stop_event,
                        )
                    except Exception as error:
                        errors.append(error)
                    finally:
                        ready.set()

                thread = threading.Thread(
                    target=capture_work, daemon=True
                )
                thread.start()

                tests = []
                try:
                    if not ready.wait(6):
                        raise RuntimeError("启动本机抓包超时。")
                    if errors:
                        raise errors[0]
                    if session.link_type is None:
                        raise RuntimeError("本机抓包启动失败。")

                    for family, label in (
                        (socket.AF_INET, "IPv4"),
                        (socket.AF_INET6, "IPv6"),
                    ):
                        for kind, protocol in (
                            (socket.SOCK_STREAM, "TCP"),
                            (socket.SOCK_DGRAM, "UDP"),
                        ):
                            port = local_exchange(family, kind)
                            tests.append((label, protocol, port))

                    time.sleep(0.5)

                finally:
                    stop_event.set()
                    thread.join(8)

                if thread.is_alive():
                    raise RuntimeError("抓包线程未正常停止。")
                if errors:
                    raise errors[0]

                connection = session.connect()
                try:
                    for family, protocol, port in tests:
                        count = connection.execute(
                            """
                            SELECT COUNT(*) FROM packets
                            WHERE id > ? AND family = ?
                              AND transport = ?
                              AND (sport = ? OR dport = ?)
                            """,
                            (before, family, protocol, port, port),
                        ).fetchone()[0]

                        if count == 0:
                            raise RuntimeError(
                                f"第 {round_number} 轮未捕获到 "
                                f"{family} {protocol} 测试流量。"
                            )
                        print(
                            f"PASS 第 {round_number} 轮 "
                            f"{family} {protocol} 实时抓包"
                        )
                finally:
                    connection.close()

            print("PASS 抓包停止与再次启动")

    finally:
        session.close()


def run_checks():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Checks)
    result = unittest.TextTestRunner(
        stream=sys.stdout, verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        return 1

    live_checks()
    print("\n自动测试全部通过。")
    return 0


def main():
    if not hasattr(basic, "parse_network"):
        raise RuntimeError(
            "请保留之前加入 IPv6 和 HTTP 功能的最新版 ex1a_gui.py。"
        )

    if "--check" in sys.argv:
        return run_checks()

    root = tk.Tk()
    try:
        with npc_library() as pcap:
            App(root, pcap)
            root.mainloop()
    except Exception as error:
        messagebox.showerror("启动失败", str(error), parent=root)
        root.destroy()
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)