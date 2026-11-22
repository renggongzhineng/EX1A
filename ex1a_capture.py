"""实验 1A 第一步：通过 Npcap 实时观察 IPv4 ping。"""

import ctypes as c
import os
import socket
import sys
import time
from datetime import datetime
from pathlib import Path


PCAP_ERRBUF_SIZE = 256
DLT_NULL = 0
DLT_EN10MB = 1
LOOPBACK_DEVICE = br"\Device\NPF_Loopback"
ECHO_TYPES = {0: "Echo Reply（应答）", 8: "Echo Request（请求）"}


class PcapInterface(c.Structure):
    pass


InterfacePointer = c.POINTER(PcapInterface)
PcapInterface._fields_ = [
    ("next", InterfacePointer),
    ("name", c.c_char_p),
    ("description", c.c_char_p),
    ("addresses", c.c_void_p),
    ("flags", c.c_uint32),
]


class PcapPacketHeader(c.Structure):
    # Windows timeval 的秒和微秒字段均为 32 位。
    _fields_ = [
        ("seconds", c.c_int32),
        ("microseconds", c.c_int32),
        ("captured_length", c.c_uint32),
        ("original_length", c.c_uint32),
    ]


HeaderPointer = c.POINTER(PcapPacketHeader)
PacketPointer = c.POINTER(c.c_ubyte)


def configure_api(pcap):
    # 传给 DLL 的指针和返回值都需要声明，尤其是 64 位 Python 中的句柄。
    signatures = {
        "pcap_findalldevs": (c.c_int, c.POINTER(InterfacePointer), c.c_char_p),
        "pcap_freealldevs": (None, InterfacePointer),
        "pcap_open_live": (c.c_void_p, c.c_char_p, c.c_int, c.c_int, c.c_int, c.c_char_p),
        "pcap_datalink": (c.c_int, c.c_void_p),
        "pcap_setnonblock": (c.c_int, c.c_void_p, c.c_int, c.c_char_p),
        "pcap_next_ex": (c.c_int, c.c_void_p, c.POINTER(HeaderPointer), c.POINTER(PacketPointer)),
        "pcap_geterr": (c.c_char_p, c.c_void_p),
        "pcap_close": (None, c.c_void_p),
    }
    for name, (return_type, *argument_types) in signatures.items():
        function = getattr(pcap, name)
        function.restype = return_type
        function.argtypes = argument_types


def list_interfaces(pcap):
    error = c.create_string_buffer(PCAP_ERRBUF_SIZE)
    first = InterfacePointer()
    if pcap.pcap_findalldevs(c.byref(first), error) != 0:
        raise RuntimeError(f"获取网卡失败：{error.value.decode('mbcs', errors='replace')}")

    interfaces = []
    current = first
    try:
        while current:
            interface = current.contents
            label = interface.description or interface.name
            description = label.decode("mbcs", errors="replace")
            if interface.name == LOOPBACK_DEVICE:
                description = "Loopback（本机回环，测试 127.0.0.1 选此项）"
            interfaces.append((interface.name, description))
            current = interface.next
    finally:
        if first:
            pcap.pcap_freealldevs(first)
    return interfaces


def parse_ping(frame, link_type):
    if link_type == DLT_NULL:
        # Npcap 回环头中的 2 表示 IPv4，后面紧接 IP 头。
        if frame[:4] != b"\x02\x00\x00\x00":
            return None
        ip_start = 4
    else:
        # 普通以太网帧头的 EtherType 0x0800 表示 IPv4。
        if frame[12:14] != b"\x08\x00":
            return None
        ip_start = 14

    ip = frame[ip_start:]
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 1:
        return None

    # IPv4 首字节低四位给出头长，单位为 4 字节。协议号 1 是 ICMP。
    header_length = (ip[0] & 0x0F) * 4
    total_length = int.from_bytes(ip[2:4], "big")
    fragment_offset = int.from_bytes(ip[6:8], "big") & 0x1FFF
    if fragment_offset or header_length < 20 or header_length + 8 > min(len(ip), total_length):
        return None

    kind = ECHO_TYPES.get(ip[header_length])
    if kind is None:
        return None
    return socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20]), kind


def capture(pcap, device):
    error = c.create_string_buffer(PCAP_ERRBUF_SIZE)
    handle = pcap.pcap_open_live(device, 65535, 0, 100, error)
    if not handle:
        raise RuntimeError(f"打开网卡失败：{error.value.decode('mbcs', errors='replace')}")

    try:
        link_type = pcap.pcap_datalink(handle)
        if link_type not in (DLT_NULL, DLT_EN10MB):
            raise RuntimeError(f"此网卡的数据链路类型为 {link_type}，请改选回环或普通网卡。")
        if pcap.pcap_setnonblock(handle, 1, error) != 0:
            raise RuntimeError(f"设置抓包模式失败：{error.value.decode('mbcs', errors='replace')}")

        print("正在抓包，按 Ctrl+C 停止。", flush=True)
        header = HeaderPointer()
        data = PacketPointer()
        while True:
            status = pcap.pcap_next_ex(handle, c.byref(header), c.byref(data))
            if status == 0:
                time.sleep(0.02)
                continue
            if status != 1:
                message = pcap.pcap_geterr(handle).decode("mbcs", errors="replace")
                raise RuntimeError(f"读取数据包失败：{message}")

            metadata = header.contents
            frame = c.string_at(data, metadata.captured_length)
            ping = parse_ping(frame, link_type)
            if ping:
                source, destination, kind = ping
                timestamp = datetime.fromtimestamp(metadata.seconds).strftime("%H:%M:%S")
                milliseconds = metadata.microseconds // 1000
                print(f"{timestamp}.{milliseconds:03d}  {source} -> {destination}  ICMP {kind}", flush=True)
    finally:
        pcap.pcap_close(handle)


def main():
    if sys.platform != "win32":
        raise RuntimeError("这个脚本需要在已安装 Npcap 的 Windows 上运行。")

    dll_directory = Path(os.environ["SystemRoot"]) / "System32" / "Npcap"
    with os.add_dll_directory(str(dll_directory)):
        pcap = c.CDLL(str(dll_directory / "wpcap.dll"))
        configure_api(pcap)
        interfaces = list_interfaces(pcap)
        if not interfaces:
            raise RuntimeError("未找到可抓包的网卡。请尝试用管理员身份打开 PowerShell 后重试。")

        print("可用网卡")
        for number, (_, description) in enumerate(interfaces, start=1):
            print(f"  {number}. {description}")
        choice = int(input("输入要抓包的网卡编号：").strip())
        if not 1 <= choice <= len(interfaces):
            raise ValueError("请输入列表中的网卡编号。")
        device, _ = interfaces[choice - 1]
        capture(pcap, device)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已停止抓包。")
    except (OSError, RuntimeError, ValueError, EOFError) as error:
        print(f"运行失败：{error}", file=sys.stderr)
        sys.exit(1)
