import ctypes as c
import os
import queue
import re
import socket
import threading
import tkinter as tk
from collections import deque
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

import ex1a_capture as capture


HTTP_REQUEST = (
    rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+ "
    rb"[^\x00-\x20\x7f]+ HTTP/1\.[01]"
)
HTTP_RESPONSE = rb"HTTP/1\.[01] [0-9]{3} [^\r\n]*"


def http_start_line(payload):
    """识别单个 TCP 包中完整的 HTTP/1.x 首行。"""
    line, separator, _ = payload.partition(b"\r\n")
    if not separator:
        return None

    if (
        re.fullmatch(HTTP_REQUEST, line)
        or re.fullmatch(HTTP_RESPONSE, line)
    ):
        return line.decode("ascii", errors="replace")[:200]

    return None


def parse_network(frame, link_type):
    """返回 IP 版本、地址、协议号、载荷和分片信息。"""
    if link_type == capture.DLT_NULL:
        if len(frame) < 4:
            return None

        family = int.from_bytes(frame[:4], "little")
        if family not in (2, 24):
            return None

        ether_type = 0x0800 if family == 2 else 0x86DD
        ip_start = 4

    elif link_type == capture.DLT_EN10MB:
        if len(frame) < 14:
            return None

        ether_type = int.from_bytes(frame[12:14], "big")
        ip_start = 14

        # 跳过以太网 VLAN 标签。
        while ether_type in (0x8100, 0x88A8, 0x9100):
            if len(frame) < ip_start + 4:
                return None
            ether_type = int.from_bytes(
                frame[ip_start + 2:ip_start + 4], "big"
            )
            ip_start += 4

    else:
        return None

    ip = frame[ip_start:]

    if ether_type == 0x0800:
        if len(ip) < 20 or ip[0] >> 4 != 4:
            return None

        header_length = (ip[0] & 0x0F) * 4
        total_length = int.from_bytes(ip[2:4], "big")

        if (
            header_length < 20
            or len(ip) < header_length
            or total_length < header_length
        ):
            return None

        source = socket.inet_ntoa(ip[12:16])
        destination = socket.inet_ntoa(ip[16:20])
        fragment = int.from_bytes(ip[6:8], "big")
        fragment_offset = (fragment & 0x1FFF) * 8
        more_fragments = bool(fragment & 0x2000)
        payload = ip[header_length:min(total_length, len(ip))]

        return (
            "IPv4", source, destination, ip[9],
            payload, fragment_offset, more_fragments,
        )

    if ether_type != 0x86DD:
        return None

    if len(ip) < 40 or ip[0] >> 4 != 6:
        return None

    payload_length = int.from_bytes(ip[4:6], "big")

    # 超大 IPv6 数据报需要额外解析 Jumbo Payload 选项。
    if payload_length == 0 and len(ip) > 40:
        return None

    ip = ip[:min(40 + payload_length, len(ip))]
    source = socket.inet_ntop(socket.AF_INET6, ip[8:24])
    destination = socket.inet_ntop(socket.AF_INET6, ip[24:40])

    next_header = ip[6]
    offset = 40
    fragment_offset = 0
    more_fragments = False

    # 处理常见 IPv6 扩展头。
    while next_header in (0, 43, 44, 51, 60):
        if next_header == 44:
            if len(ip) < offset + 8:
                return None

            fragment = int.from_bytes(
                ip[offset + 2:offset + 4], "big"
            )
            fragment_offset = fragment & 0xFFF8
            more_fragments = bool(fragment & 1)
            next_header = ip[offset]
            offset += 8

            if fragment_offset:
                break
            continue

        if len(ip) < offset + 2:
            return None

        if next_header == 51:
            extension_length = (ip[offset + 1] + 2) * 4
            if extension_length < 12:
                return None
        else:
            extension_length = (ip[offset + 1] + 1) * 8

        if len(ip) < offset + extension_length:
            return None

        next_header = ip[offset]
        offset += extension_length

    return (
        "IPv6", source, destination, next_header,
        ip[offset:], fragment_offset, more_fragments,
    )


def parse_packet(frame, link_type):
    network = parse_network(frame, link_type)
    if network is None:
        return None

    (
        version, source, destination, protocol_number,
        segment, fragment_offset, more_fragments,
    ) = network

    protocol = {6: "TCP", 17: "UDP"}.get(
        protocol_number, version
    )

    if version == "IPv4" and protocol_number == 1:
        protocol = "ICMP"
    elif version == "IPv6" and protocol_number == 58:
        protocol = "ICMPv6"

    if fragment_offset:
        info = f"{version} 分片，偏移 {fragment_offset} 字节"
        return source, destination, protocol, info

    if protocol in ("ICMP", "ICMPv6"):
        if len(segment) < 8:
            return None

        if protocol == "ICMP":
            types = {
                0: "Echo Reply（应答）",
                3: "Destination Unreachable（目的不可达）",
                8: "Echo Request（请求）",
                11: "Time Exceeded（超时）",
            }
        else:
            types = {
                1: "Destination Unreachable（目的不可达）",
                2: "Packet Too Big（报文过大）",
                3: "Time Exceeded（超时）",
                128: "Echo Request（请求）",
                129: "Echo Reply（应答）",
                133: "Router Solicitation（路由器请求）",
                134: "Router Advertisement（路由器通告）",
                135: "Neighbor Solicitation（邻居请求）",
                136: "Neighbor Advertisement（邻居通告）",
            }

        kind = types.get(segment[0], f"Type={segment[0]}")
        info = f"{kind}，Code={segment[1]}"
        return source, destination, protocol, info

    if protocol not in ("TCP", "UDP"):
        info = f"Next Header / 协议号 {protocol_number}"
        return source, destination, protocol, info

    minimum_length = 20 if protocol == "TCP" else 8
    if len(segment) < minimum_length:
        return None

    source_port = int.from_bytes(segment[0:2], "big")
    destination_port = int.from_bytes(segment[2:4], "big")
    info = f"端口 {source_port} → {destination_port}"

    if protocol == "UDP":
        udp_length = int.from_bytes(segment[4:6], "big")
        if udp_length < 8:
            return None

        info += f"  UDP 长度 {udp_length} 字节"
        return source, destination, protocol, info

    tcp_header_length = (segment[12] >> 4) * 4
    if (
        tcp_header_length < 20
        or tcp_header_length > len(segment)
    ):
        return None

    flags = [
        name
        for mask, name in (
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        )
        if segment[13] & mask
    ]

    if flags:
        info += "  [" + ", ".join(flags) + "]"

    if not more_fragments:
        payload = segment[tcp_header_length:]
        first_line = http_start_line(payload)
        if first_line:
            protocol = "HTTP"
            info += "  " + first_line

    return source, destination, protocol, info


def matches_filter(record, selected):
    source = record[2]
    protocol = record[4]

    if selected == "全部":
        return True
    if selected == "IPv4":
        return ":" not in source
    if selected == "IPv6":
        return ":" in source
    if selected == "TCP":
        return protocol in ("TCP", "HTTP")
    if selected == "ICMP":
        return protocol in ("ICMP", "ICMPv6")

    return protocol == selected


class SnifferApp:
    def __init__(self, root, pcap):
        self.root = root
        self.pcap = pcap
        self.interfaces = capture.list_interfaces(pcap)

        if not self.interfaces:
            raise RuntimeError("没有找到可抓包的网卡。")

        self.worker = None
        self.stop_event = threading.Event()
        self.messages = queue.Queue(maxsize=2000)
        self.records = deque(maxlen=1000)
        self.closing = False
        self.count = 0
        self.dropped = 0
        self.error = None

        root.title("实验 1A — 网络嗅探器")
        root.geometry("1150x650")

        toolbar = ttk.Frame(root, padding=10)
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="抓包网卡").pack(side="left")

        self.interface_box = ttk.Combobox(
            toolbar,
            state="readonly",
            width=48,
            values=[
                f"{index}. {description}"
                for index, (_, description) in enumerate(
                    self.interfaces, start=1
                )
            ],
        )
        self.interface_box.pack(side="left", padx=8)
        self.interface_box.current(0)

        self.start_button = ttk.Button(
            toolbar, text="开始抓包", command=self.start
        )
        self.start_button.pack(side="left", padx=4)

        self.stop_button = ttk.Button(
            toolbar,
            text="停止抓包",
            command=self.stop,
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=4)

        filter_bar = ttk.Frame(
            root, padding=(10, 0, 10, 10)
        )
        filter_bar.pack(fill="x")

        ttk.Label(
            filter_bar, text="显示协议"
        ).pack(side="left")

        self.protocol_box = ttk.Combobox(
            filter_bar,
            state="readonly",
            width=12,
            values=(
                "全部", "IPv4", "IPv6", "TCP",
                "UDP", "ICMP", "ICMPv6", "HTTP",
            ),
        )
        self.protocol_box.current(0)
        self.protocol_box.pack(side="left", padx=8)
        self.protocol_box.bind(
            "<<ComboboxSelected>>", self.refresh_table
        )

        ttk.Label(
            filter_bar,
            text="保留最近 1000 条记录，可随时切换筛选。",
        ).pack(side="left", padx=8)

        frame = ttk.Frame(root, padding=(10, 0))
        frame.pack(fill="both", expand=True)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        columns = (
            "number", "time", "source",
            "destination", "protocol", "info",
        )
        headings = (
            "序号", "时间", "源 IP",
            "目的 IP", "协议", "详细信息",
        )
        widths = (60, 120, 250, 250, 85, 450)

        self.table = ttk.Treeview(
            frame, columns=columns, show="headings"
        )

        for column, heading, width in zip(
            columns, headings, widths
        ):
            self.table.heading(column, text=heading)
            self.table.column(
                column, width=width, minwidth=50
            )

        vertical = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.table.yview,
        )
        horizontal = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=self.table.xview,
        )

        self.table.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )

        self.table.grid(
            row=0, column=0, sticky="nsew"
        )
        vertical.grid(
            row=0, column=1, sticky="ns"
        )
        horizontal.grid(
            row=1, column=0, sticky="ew"
        )

        self.status = tk.StringVar(
            value="请选择网卡，然后开始抓包。"
        )
        ttk.Label(
            root, textvariable=self.status, padding=10
        ).pack(fill="x")

        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(50, self.poll)

    def start(self):
        if self.worker is not None:
            return

        device, _ = self.interfaces[
            self.interface_box.current()
        ]
        self.stop_event.clear()
        self.error = None

        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.interface_box.configure(state="disabled")

        self.worker = threading.Thread(
            target=self.read_packets,
            args=(device,),
            daemon=True,
        )
        self.worker.start()

    def read_packets(self, device):
        handle = None

        try:
            error = c.create_string_buffer(
                capture.PCAP_ERRBUF_SIZE
            )
            handle = self.pcap.pcap_open_live(
                device, 65535, 0, 100, error
            )

            if not handle:
                raise RuntimeError(
                    error.value.decode(
                        "mbcs", errors="replace"
                    )
                )

            link_type = self.pcap.pcap_datalink(handle)
            if link_type not in (
                capture.DLT_NULL, capture.DLT_EN10MB
            ):
                raise RuntimeError(
                    "请选择普通网卡或 Loopback 网卡。"
                )

            if self.pcap.pcap_setnonblock(
                handle, 1, error
            ) != 0:
                raise RuntimeError(
                    error.value.decode(
                        "mbcs", errors="replace"
                    )
                )

            header = capture.HeaderPointer()
            data = capture.PacketPointer()

            while not self.stop_event.is_set():
                result = self.pcap.pcap_next_ex(
                    handle,
                    c.byref(header),
                    c.byref(data),
                )

                if result == 0:
                    self.stop_event.wait(0.02)
                    continue

                if result != 1:
                    raise RuntimeError(
                        self.pcap.pcap_geterr(handle).decode(
                            "mbcs", errors="replace"
                        )
                    )

                metadata = header.contents
                frame = c.string_at(
                    data, metadata.captured_length
                )
                parsed = parse_packet(frame, link_type)

                if parsed is None:
                    continue

                timestamp = datetime.fromtimestamp(
                    metadata.seconds
                ).strftime("%H:%M:%S")
                timestamp += (
                    f".{metadata.microseconds // 1000:03d}"
                )

                try:
                    self.messages.put_nowait(
                        (timestamp, *parsed)
                    )
                except queue.Full:
                    self.dropped += 1

        except Exception as error:
            self.error = str(error)

        finally:
            if handle:
                self.pcap.pcap_close(handle)

    def stop(self):
        self.stop_event.set()
        self.stop_button.configure(state="disabled")

    def add_record(self, packet):
        self.count += 1
        record = (self.count, *packet)

        if len(self.records) == self.records.maxlen:
            oldest_id = str(self.records[0][0])
            if self.table.exists(oldest_id):
                self.table.delete(oldest_id)

        self.records.append(record)

        if matches_filter(record, self.protocol_box.get()):
            self.table.insert(
                "",
                "end",
                iid=str(record[0]),
                values=record,
            )
            self.table.yview_moveto(1)

    def refresh_table(self, event=None):
        rows = self.table.get_children()
        if rows:
            self.table.delete(*rows)

        selected = self.protocol_box.get()
        for record in self.records:
            if matches_filter(record, selected):
                self.table.insert(
                    "",
                    "end",
                    iid=str(record[0]),
                    values=record,
                )

        self.table.yview_moveto(1)

    def poll(self):
        for _ in range(200):
            try:
                packet = self.messages.get_nowait()
            except queue.Empty:
                break

            self.add_record(packet)

        if (
            self.worker is not None
            and not self.worker.is_alive()
        ):
            self.worker = None
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.interface_box.configure(state="readonly")

            if self.error and not self.closing:
                messagebox.showerror(
                    "抓包失败", self.error
                )

        state = "已停止"
        if self.worker is not None:
            state = (
                "正在停止"
                if self.stop_event.is_set()
                else "抓包中"
            )

        visible = len(self.table.get_children())
        self.status.set(
            f"{state} · 累计记录 {self.count} 条"
            f" · 当前显示 {visible} 条"
            f" · 显示队列丢弃 {self.dropped} 条"
        )

        if self.closing and self.worker is None:
            self.root.destroy()
            return

        self.root.after(50, self.poll)

    def close(self):
        self.closing = True
        self.stop()


def main():
    root = tk.Tk()

    try:
        dll_directory = (
            Path(os.environ["SystemRoot"])
            / "System32"
            / "Npcap"
        )

        with os.add_dll_directory(str(dll_directory)):
            pcap = c.CDLL(
                str(dll_directory / "wpcap.dll")
            )
            capture.configure_api(pcap)
            SnifferApp(root, pcap)
            root.mainloop()

    except Exception as error:
        messagebox.showerror(
            "启动失败", str(error), parent=root
        )
        root.destroy()


if __name__ == "__main__":
    main()