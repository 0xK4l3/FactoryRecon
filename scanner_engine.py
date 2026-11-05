"""
FactoryRecon - Native Windows Ethernet Discovery & Scanner Engine.
Works 100% with built-in Windows APIs (iphlpapi.dll, WinSock2, PowerShell NetTCPIP)
without requiring external packet capture drivers like Npcap.
"""

from __future__ import annotations

import concurrent.futures
import ctypes
import ipaddress
import json
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from oui_db import lookup_mac_vendor

# Windows IP Helper API setup
iphlpapi = ctypes.windll.iphlpapi


class MIB_IPNETROW(ctypes.Structure):
    _fields_ = [
        ("dwIndex", ctypes.c_ulong),
        ("dwPhysAddrLen", ctypes.c_ulong),
        ("bPhysAddr", ctypes.c_ubyte * 8),
        ("dwAddr", ctypes.c_ulong),
        ("dwType", ctypes.c_ulong),
    ]


COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP (Web UI)",
    102: "Siemens S7 (ISO-TSAP)",
    135: "MS RPC",
    139: "NetBIOS",
    161: "SNMP",
    443: "HTTPS (Web UI)",
    445: "SMB",
    502: "Modbus TCP",
    554: "RTSP (IP Camera)",
    1883: "MQTT",
    2222: "EtherNet/IP (Implicit)",
    3389: "RDP (Escritorio Remoto)",
    4840: "OPC UA",
    5000: "UPnP / Flask / Synology",
    5900: "VNC",
    8000: "HTTP Alt / Hikvision",
    8080: "HTTP Proxy / Web",
    8443: "HTTPS Alt",
    9100: "Impresora RAW / JetDirect",
    9600: "Omron FINS",
    20000: "DNP3",
    34964: "Profinet RT",
    44818: "EtherNet/IP (Rockwell/AB)",
    47808: "BACnet/IP",
}

# Most common static IP ranges used by PLCs, routers, cameras, and industrial devices
COMMON_INDUSTRIAL_SUBNETS: list[str] = [
    "192.168.0.0/24",
    "192.168.1.0/24",
    "192.168.2.0/24",
    "192.168.10.0/24",
    "192.168.100.0/24",
    "192.168.250.0/24",  # Omron default
    "10.0.0.0/24",
    "10.10.10.0/24",
    "172.16.0.0/24",
]

# High-probability static host octets inside unknown subnets (e.g. .1, .10, .100, .200, .250, .254)
PRIORITY_HOST_OCTETS: list[int] = [
    1, 2, 10, 20, 50, 64, 99, 100, 101, 108, 128, 150, 199, 200, 201, 240, 250, 253, 254
]


@dataclass
class NetworkAdapter:
    if_index: int
    name: str
    description: str
    status: str
    mac_address: str
    link_speed: str
    ipv4_addresses: list[tuple[str, int]] = field(default_factory=list)  # (ip, prefix_len)

    @property
    def primary_ip(self) -> str:
        return self.ipv4_addresses[0][0] if self.ipv4_addresses else "0.0.0.0"

    @property
    def primary_prefix(self) -> int:
        return self.ipv4_addresses[0][1] if self.ipv4_addresses else 24

    @property
    def is_apipa(self) -> bool:
        return self.primary_ip.startswith("169.254.")


@dataclass
class DiscoveredDevice:
    ip: str
    mac: str = "Desconocida"
    vendor: str = "Desconocido"
    hostname: str = ""
    discovery_methods: set[str] = field(default_factory=set)
    open_ports: dict[int, str] = field(default_factory=dict)
    subnet_mismatch: bool = False
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    extra_info: str = ""
    interface_index: int = 0

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "discovery_methods": sorted(list(self.discovery_methods)),
            "open_ports": [{"port": p, "service": s} for p, s in sorted(self.open_ports.items())],
            "subnet_mismatch": self.subnet_mismatch,
            "first_seen": time.strftime("%H:%M:%S", time.localtime(self.first_seen)),
            "last_seen": time.strftime("%H:%M:%S", time.localtime(self.last_seen)),
            "extra_info": self.extra_info,
            "interface_index": self.interface_index,
        }


def is_admin() -> bool:
    """Checks if the current process has Windows Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_network_adapters() -> list[NetworkAdapter]:
    """
    Retrieves Ethernet and wireless network adapters along with their IPv4 addresses
    using Windows PowerShell / WMI / NetTCPIP.
    """
    ps_script = r"""
    $adapters = Get-NetAdapter | Select-Object ifIndex, Name, InterfaceDescription, Status, MacAddress, LinkSpeed
    $ips = Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceIndex, IPAddress, PrefixLength
    $result = @()
    foreach ($a in $adapters) {
        $adapterIps = @($ips | Where-Object { $_.InterfaceIndex -eq $a.ifIndex } | ForEach-Object {
            @{ ip = $_.IPAddress; prefix = $_.PrefixLength }
        })
        $result += @{
            ifIndex = $a.ifIndex
            name = $a.Name
            description = $a.InterfaceDescription
            status = [string]$a.Status
            mac = [string]$a.MacAddress
            speed = [string]$a.LinkSpeed
            ips = $adapterIps
        }
    }
    $result | ConvertTo-Json -Depth 4 -Compress
    """
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        raw = proc.stdout.strip()
        if not raw:
            return []
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]

        adapters: list[NetworkAdapter] = []
        for item in data:
            mac = (item.get("mac") or "").replace("-", ":").upper()
            ips = []
            for ip_entry in item.get("ips") or []:
                ip_str = ip_entry.get("ip", "")
                prefix = int(ip_entry.get("prefix", 24))
                if ip_str and not ip_str.startswith("127."):
                    ips.append((ip_str, prefix))

            adapters.append(
                NetworkAdapter(
                    if_index=int(item.get("ifIndex", 0)),
                    name=item.get("name", "Ethernet"),
                    description=item.get("description", ""),
                    status=item.get("status", "Unknown"),
                    mac_address=mac,
                    link_speed=item.get("speed", ""),
                    ipv4_addresses=ips,
                )
            )

        # Sort so 'Up' physical Ethernet adapters with real IPs come before virtual/APIPA adapters
        def _adapter_sort_key(a: NetworkAdapter) -> tuple:
            desc_low = a.description.lower()
            is_virtual = any(v in desc_low for v in ("virtualbox", "vmware", "hyper-v", "tap", "vpn", "loopback"))
            is_up = a.status.lower() == "up"
            return (
                0 if is_up else 1,
                1 if is_virtual else 0,
                1 if a.is_apipa else 0,
                a.if_index,
            )

        adapters.sort(key=_adapter_sort_key)
        return adapters
    except Exception:
        return []


def send_arp_request(dest_ip: str, src_ip: str = "0.0.0.0") -> Optional[str]:
    """
    Calls Windows Native iphlpapi.SendARP to resolve an IPv4 address to a MAC address.
    Returns 'AA:BB:CC:DD:EE:FF' if the host responds, or None on timeout/unreachable.
    """
    try:
        dest_addr = struct.unpack("I", socket.inet_aton(dest_ip))[0]
        src_addr = struct.unpack("I", socket.inet_aton(src_ip))[0] if src_ip and src_ip != "0.0.0.0" else 0
        mac_buf = (ctypes.c_ubyte * 6)()
        phys_len = ctypes.c_ulong(6)

        res = iphlpapi.SendARP(dest_addr, src_addr, ctypes.byref(mac_buf), ctypes.byref(phys_len))
        if res == 0 and phys_len.value == 6:
            mac_str = ":".join(f"{b:02X}" for b in mac_buf[:6])
            if mac_str != "00:00:00:00:00:00" and mac_str != "FF:FF:FF:FF:FF:FF":
                return mac_str
    except Exception:
        pass
    return None


def get_kernel_arp_table(interface_index: Optional[int] = None) -> list[tuple[str, str, int]]:
    """
    Reads the Windows kernel ARP cache (MIB_IPNETTABLE) via GetIpNetTable.
    Returns list of (ip_str, mac_str, if_index).
    """
    results: list[tuple[str, str, int]] = []
    try:
        size = ctypes.c_ulong(0)
        iphlpapi.GetIpNetTable(None, ctypes.byref(size), False)
        if size.value == 0:
            return results

        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetIpNetTable(buf, ctypes.byref(size), False)
        if ret != 0:
            return results

        num_entries = struct.unpack("I", buf[:4])[0]
        row_size = ctypes.sizeof(MIB_IPNETROW)
        offset = 4

        for _ in range(num_entries):
            if offset + row_size > size.value:
                break
            row = MIB_IPNETROW.from_buffer_copy(buf, offset)
            offset += row_size

            # dwType: 3 = Dynamic, 4 = Static (ignore 2 = Invalid/Incomplete)
            if row.dwType not in (3, 4):
                continue
            if interface_index is not None and row.dwIndex != interface_index:
                continue

            ip_str = socket.inet_ntoa(struct.pack("I", row.dwAddr))
            # Filter multicast/broadcast/loopback
            first_octet = int(ip_str.split(".")[0])
            if first_octet in (0, 127) or first_octet >= 224 or ip_str.endswith(".255"):
                continue

            mac_len = min(row.dwPhysAddrLen, 6)
            if mac_len < 6:
                continue
            mac_str = ":".join(f"{row.bPhysAddr[i]:02X}" for i in range(6))
            if mac_str in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                continue

            results.append((ip_str, mac_str, int(row.dwIndex)))
    except Exception:
        pass
    return results


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """Attempts reverse DNS / NetBIOS name resolution."""
    try:
        old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        finally:
            socket.setdefaulttimeout(old_to)
    except Exception:
        return ""


def query_netbios_name(ip: str, timeout: float = 0.6) -> str:
    """
    Sends a UDP NetBIOS Node Status Request (port 137) to quickly get a Windows/Linux/PLC
    NetBIOS hostname even without DNS.
    """
    # NetBIOS Name Service Node Status Request packet for '*'
    packet = (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x00\x00\x21\x00\x01"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) > 57:
            num_names = data[56]
            pos = 57
            for _ in range(num_names):
                if pos + 18 > len(data):
                    break
                raw_name = data[pos : pos + 15].decode("ascii", errors="ignore").strip()
                name_type = data[pos + 15]
                flags = struct.unpack(">H", data[pos + 16 : pos + 18])[0]
                pos += 18
                # Unique workstation/server name (0x00 or 0x20), not group flag (0x8000)
                if name_type in (0x00, 0x20) and not (flags & 0x8000) and raw_name:
                    return raw_name
    except Exception:
        pass
    finally:
        sock.close()
    return ""


def grab_http_title_or_server(ip: str, port: int = 80, timeout: float = 0.8) -> str:
    """Attempts a lightweight HTTP HEAD/GET to identify embedded web servers (PLCs, Routers, Cameras)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: FactoryRecon/1.0\r\n\r\n".encode("ascii")
        sock.sendall(req)
        resp = sock.recv(2048).decode("utf-8", errors="ignore")
        server_hdr = ""
        title = ""
        for line in resp.splitlines():
            if line.lower().startswith("server:"):
                server_hdr = line.split(":", 1)[1].strip()
                break
        if "<title>" in resp.lower():
            low = resp.lower()
            start = low.find("<title>") + 7
            end = low.find("</title>", start)
            if end > start:
                title = resp[start:end].strip()
        parts = [p for p in (title, server_hdr) if p]
        return " | ".join(parts)[:80]
    except Exception:
        return ""
    finally:
        sock.close()


def scan_device_ports(
    ip: str,
    ports: Optional[list[int]] = None,
    timeout: float = 0.35,
) -> tuple[dict[int, str], str]:
    """
    Scans common TCP ports on a target IP and returns (open_ports_dict, extra_banner_info).
    """
    target_ports = ports if ports is not None else list(COMMON_PORTS.keys())
    open_ports: dict[int, str] = {}
    extra_info_parts: list[str] = []

    def check_port(port: int) -> Optional[int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                return port
        except Exception:
            pass
        finally:
            s.close()
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        futures = {executor.submit(check_port, p): p for p in target_ports}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res is not None:
                open_ports[res] = COMMON_PORTS.get(res, f"TCP/{res}")

    # Grab HTTP banner if port 80 or 8080 is open
    for http_port in (80, 8080, 8000):
        if http_port in open_ports:
            banner = grab_http_title_or_server(ip, http_port)
            if banner:
                extra_info_parts.append(f"Web({http_port}): {banner}")
                break

    return open_ports, " ; ".join(extra_info_parts)


class DiscoveryEngine:
    """
    Coordinates active and passive discovery of Ethernet devices connected to Windows.
    Supports:
    1. Kernel ARP Table monitoring
    2. Active Parallel ARP sweep on local interface subnet(s)
    3. Passive UDP Broadcast/Multicast listener (mDNS 5353, SSDP 1900, WS-Discovery 3702,
       NetBIOS 137/138, EtherNet/IP, DHCP) to catch devices on DIFFERENT subnets!
    4. Active Multicast/Broadcast probes (mDNS, SSDP, EtherNet/IP ListIdentity, NetBIOS)
    5. Optional Multi-Subnet Route Probing (when running as Admin) to discover silent
       static-IP devices in foreign subnets (192.168.0.x, 192.168.1.x, 10.0.0.x, etc.)
    """

    def __init__(self, on_device_Callback: Optional[Callable[[DiscoveredDevice], None]] = None):
        self.devices: dict[str, DiscoveredDevice] = {}
        self.lock = threading.Lock()
        self.on_device_callback = on_device_Callback
        self.running_passive = False
        self.passive_threads: list[threading.Thread] = []
        self.scan_in_progress = False
        self.scan_progress: float = 0.0
        self.scan_status_text: str = "Listo para escanear"
        self.logs: list[str] = []

    def log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        with self.lock:
            self.logs.append(entry)
            if len(self.logs) > 300:
                self.logs = self.logs[-300:]

    def register_device(
        self,
        ip: str,
        mac: str = "",
        method: str = "ARP",
        hostname: str = "",
        extra_info: str = "",
        adapter: Optional[NetworkAdapter] = None,
    ) -> Optional[DiscoveredDevice]:
        if not ip or ip.startswith("127.") or ip.startswith("0.") or ip == "255.255.255.255":
            return None

        # Ignore local adapter's own IPs
        if adapter:
            local_ips = {ip_addr for ip_addr, _ in adapter.ipv4_addresses}
            if ip in local_ips:
                return None

        # Check if IP is outside the adapter's primary subnet
        subnet_mismatch = False
        if adapter and adapter.ipv4_addresses:
            subnet_mismatch = True
            try:
                target_ip_obj = ipaddress.IPv4Address(ip)
                for local_ip, prefix in adapter.ipv4_addresses:
                    net = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
                    if target_ip_obj in net:
                        subnet_mismatch = False
                        break
            except Exception:
                pass

        clean_mac = mac.upper().replace("-", ":") if mac else ""
        if clean_mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            clean_mac = ""

        is_new = False
        with self.lock:
            if ip not in self.devices:
                is_new = True
                vendor = lookup_mac_vendor(clean_mac) if clean_mac else "Desconocido"
                dev = DiscoveredDevice(
                    ip=ip,
                    mac=clean_mac or "Desconocida",
                    vendor=vendor,
                    hostname=hostname,
                    discovery_methods={method},
                    subnet_mismatch=subnet_mismatch,
                    extra_info=extra_info,
                    interface_index=adapter.if_index if adapter else 0,
                )
                self.devices[ip] = dev
            else:
                dev = self.devices[ip]
                dev.last_seen = time.time()
                dev.discovery_methods.add(method)
                if clean_mac and dev.mac == "Desconocida":
                    dev.mac = clean_mac
                    dev.vendor = lookup_mac_vendor(clean_mac)
                if hostname and not dev.hostname:
                    dev.hostname = hostname
                if extra_info and extra_info not in dev.extra_info:
                    dev.extra_info = f"{dev.extra_info} | {extra_info}".strip(" |")
                if adapter:
                    dev.subnet_mismatch = subnet_mismatch

        if is_new:
            mismatch_tag = " [¡SUBRED DIFERENTE!]" if subnet_mismatch else ""
            self.log(f"Equipo detectado: {ip} ({dev.mac} - {dev.vendor}) vía {method}{mismatch_tag}")
            # Enrich device asynchronously (ports, NetBIOS, reverse DNS)
            threading.Thread(
                target=self._enrich_device,
                args=(dev, adapter),
                daemon=True,
            ).start()

        if self.on_device_callback:
            self.on_device_callback(dev)
        return dev

    def _enrich_device(self, dev: DiscoveredDevice, adapter: Optional[NetworkAdapter]) -> None:
        """Resolves MAC (if missing), hostname, NetBIOS name, and open TCP ports."""
        if dev.mac == "Desconocida":
            src_ip = adapter.primary_ip if adapter else "0.0.0.0"
            mac = send_arp_request(dev.ip, src_ip)
            if mac:
                with self.lock:
                    dev.mac = mac
                    dev.vendor = lookup_mac_vendor(mac)

        if not dev.hostname:
            nb_name = query_netbios_name(dev.ip)
            if not nb_name:
                nb_name = resolve_hostname(dev.ip)
            if nb_name:
                with self.lock:
                    dev.hostname = nb_name

        open_ports, banner_info = scan_device_ports(dev.ip)
        with self.lock:
            if open_ports:
                dev.open_ports.update(open_ports)
            if banner_info and banner_info not in dev.extra_info:
                dev.extra_info = f"{dev.extra_info} | {banner_info}".strip(" |")

    def start_passive_listeners(self, adapter: Optional[NetworkAdapter] = None) -> None:
        """
        Starts background UDP broadcast/multicast listeners and active multicast probes.
        Crucially, UDP packets from a device on a DIFFERENT subnet (e.g. 192.168.1.50
        broadcasting SSDP, mDNS, NetBIOS, or EtherNet/IP while the PC is on 169.254.x.x)
        are still received by Windows sockets bound to 0.0.0.0, revealing the device's IP!
        """
        if self.running_passive:
            return
        self.running_passive = True
        self.log("Escucha pasiva iniciada (mDNS, SSDP, NetBIOS, WS-Discovery, EtherNet/IP, Tabla ARP).")

        # UDP ports to listen on for broadcast/multicast announcements
        udp_ports = [
            (5353, "224.0.0.251", "mDNS / Bonjour"),
            (1900, "239.255.255.250", "SSDP / UPnP"),
            (3702, "239.255.255.250", "WS-Discovery (ONVIF/Windows)"),
            (137, None, "NetBIOS Name Service"),
            (138, None, "NetBIOS Datagram"),
            (44818, None, "EtherNet/IP Broadcast"),
        ]

        for port, mcast_grp, label in udp_ports:
            t = threading.Thread(
                target=self._udp_listener_worker,
                args=(port, mcast_grp, label, adapter),
                daemon=True,
            )
            t.start()
            self.passive_threads.append(t)

        # Kernel ARP table poller thread
        t_arp = threading.Thread(
            target=self._arp_table_poller,
            args=(adapter,),
            daemon=True,
        )
        t_arp.start()
        self.passive_threads.append(t_arp)

    def stop_passive_listeners(self) -> None:
        self.running_passive = False
        self.log("Escucha pasiva detenida.")

    def _udp_listener_worker(
        self,
        port: int,
        mcast_group: Optional[str],
        label: str,
        adapter: Optional[NetworkAdapter],
    ) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", port))
            if mcast_group:
                mreq = struct.pack("4s4s", socket.inet_aton(mcast_group), socket.inet_aton("0.0.0.0"))
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                except Exception:
                    pass
            sock.settimeout(1.5)
            while self.running_passive:
                try:
                    data, addr = sock.recvfrom(2048)
                    sender_ip = addr[0]
                    info = self._parse_udp_payload(port, data)
                    self.register_device(
                        ip=sender_ip,
                        method=label,
                        extra_info=info,
                        adapter=adapter,
                    )
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            sock.close()

    def _parse_udp_payload(self, port: int, data: bytes) -> str:
        """Extracts human-readable model/service info from SSDP, mDNS, or EtherNet/IP packets."""
        try:
            if port == 1900:
                text = data.decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()[:60]
            elif port == 44818 and len(data) > 48:
                # EtherNet/IP ListIdentity response contains product name string
                printable = "".join(chr(b) if 32 <= b < 127 else " " for b in data[44:])
                cleaned = " ".join(printable.split())
                if cleaned:
                    return f"EtherNet/IP: {cleaned[:50]}"
        except Exception:
            pass
        return ""

    def _arp_table_poller(self, adapter: Optional[NetworkAdapter]) -> None:
        while self.running_passive:
            if_idx = adapter.if_index if adapter else None
            entries = get_kernel_arp_table(if_idx)
            for ip_str, mac_str, _ in entries:
                self.register_device(
                    ip=ip_str,
                    mac=mac_str,
                    method="Tabla ARP",
                    adapter=adapter,
                )
            time.sleep(2.5)

    def send_active_broadcast_probes(self, adapter: Optional[NetworkAdapter] = None) -> None:
        """
        Sends active broadcast/multicast discovery queries over UDP:
        - SSDP M-SEARCH (discovers routers, cameras, UPnP devices, HMIs)
        - EtherNet/IP ListIdentity broadcast on UDP 44818 (discovers Allen-Bradley/Rockwell/industrial devices even on different subnets)
        - mDNS query for _services._dns-sd._udp.local
        - WS-Discovery Probe on UDP 3702 (discovers ONVIF IP cameras, Windows PCs, printers)
        """
        self.log("Enviando sondas de descubrimiento Broadcast/Multicast (SSDP, mDNS, EtherNet/IP, WS-Discovery)...")
        bind_ip = adapter.primary_ip if (adapter and adapter.primary_ip != "0.0.0.0") else "0.0.0.0"

        # 1. SSDP M-SEARCH
        ssdp_req = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\n'
            b"MX: 2\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )
        # 2. EtherNet/IP ListIdentity Request (24-byte header: command 0x0063, all zeros)
        enip_req = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)

        # 3. mDNS query for _services._dns-sd._udp.local
        mdns_req = (
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
            b"\x00\x0c\x00\x01"
        )

        probes = [
            (ssdp_req, ("239.255.255.250", 1900), "SSDP"),
            (ssdp_req, ("255.255.255.255", 1900), "SSDP Broadcast"),
            (enip_req, ("255.255.255.255", 44818), "EtherNet/IP"),
            (mdns_req, ("224.0.0.251", 5353), "mDNS"),
        ]

        for payload, target, proto_name in probes:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(0.8)
            try:
                if bind_ip != "0.0.0.0":
                    sock.bind((bind_ip, 0))
                sock.sendto(payload, target)
                # Read immediate replies on the ephemeral port
                start = time.time()
                while time.time() - start < 0.8:
                    try:
                        data, addr = sock.recvfrom(2048)
                        info = self._parse_udp_payload(target[1], data)
                        self.register_device(
                            ip=addr[0],
                            method=proto_name,
                            extra_info=info,
                            adapter=adapter,
                        )
                    except socket.timeout:
                        break
            except Exception:
                pass
            finally:
                sock.close()

    def run_full_scan(
        self,
        adapter: NetworkAdapter,
        custom_subnets: Optional[list[str]] = None,
        deep_cross_subnet: bool = True,
    ) -> None:
        """
        Executes a comprehensive discovery run on the selected Ethernet adapter:
        Step 1: Read current Windows ARP cache for the interface.
        Step 2: Send active UDP broadcast/multicast probes (SSDP, EtherNet/IP, mDNS).
        Step 3: Perform fast parallel native SendARP sweep across the adapter's current subnet(s).
        Step 4: Cross-subnet discovery!
                - If running as Administrator: temporarily adds an on-link route (`route add <net> mask 255.255.255.0 0.0.0.0 IF <ifIndex>`)
                  so Windows `SendARP` emits real Layer-2 ARP requests for foreign subnets (192.168.0.x, 192.168.1.x, 10.0.0.x, etc.)
                  directly out the Ethernet cable without changing the PC's IP!
                - Even without Admin: scans priority static IPs if routable or checks ARP cache entries triggered by broadcast probes.
        """
        if self.scan_in_progress:
            return
        self.scan_in_progress = True
        self.scan_progress = 0.02
        self.scan_status_text = f"Iniciando escaneo en {adapter.name} ({adapter.primary_ip})..."
        self.log(f"=== Iniciando escaneo completo en {adapter.name} (ifIndex={adapter.if_index}, IP={adapter.primary_ip}) ===")

        try:
            # Step 1: Kernel ARP table
            self.scan_status_text = "Leyendo tabla ARP del kernel de Windows..."
            arp_entries = get_kernel_arp_table(adapter.if_index)
            for ip_str, mac_str, _ in arp_entries:
                self.register_device(ip=ip_str, mac=mac_str, method="Tabla ARP", adapter=adapter)
            self.scan_progress = 0.10

            # Step 2: Broadcast & Multicast active probes
            self.scan_status_text = "Enviando sondas Broadcast / Multicast (mDNS, SSDP, EtherNet/IP)..."
            self.send_active_broadcast_probes(adapter)
            self.scan_progress = 0.20

            # Step 3: Active ARP sweep of the adapter's own configured subnet(s)
            subnets_to_sweep: list[str] = []
            if custom_subnets:
                subnets_to_sweep.extend(custom_subnets)
            else:
                for ip_str, prefix in adapter.ipv4_addresses:
                    if ip_str.startswith("169.254."):
                        # APIPA is /16 (65534 hosts) - sweep 169.254.0.x, 169.254.1.x and the adapter's own /24
                        own_octets = ip_str.split(".")
                        subnets_to_sweep.append(f"169.254.{own_octets[2]}.0/24")
                        subnets_to_sweep.append("169.254.1.0/24")
                        subnets_to_sweep.append("169.254.0.0/24")
                    else:
                        scan_prefix = max(prefix, 24)  # Cap automatic sweep to /24 for speed
                        net = ipaddress.IPv4Network(f"{ip_str}/{scan_prefix}", strict=False)
                        subnets_to_sweep.append(str(net))

            total_own = max(len(subnets_to_sweep), 1)
            for idx, net_cidr in enumerate(subnets_to_sweep):
                self.scan_status_text = f"Barrido ARP en subred local {net_cidr}..."
                self._sweep_subnet_arp(net_cidr, adapter, full_sweep=True)
                self.scan_progress = 0.20 + 0.45 * ((idx + 1) / total_own)

            # Step 4: Cross-Subnet Discovery (finding static IP devices in other subnets)
            if deep_cross_subnet:
                self._run_cross_subnet_discovery(adapter, custom_subnets)

            # Final ARP table re-check
            for ip_str, mac_str, _ in get_kernel_arp_table(adapter.if_index):
                self.register_device(ip=ip_str, mac=mac_str, method="Tabla ARP", adapter=adapter)

            self.scan_progress = 1.0
            count = len(self.devices)
            self.scan_status_text = f"Escaneo finalizado ({count} equipo{'s' if count != 1 else ''} detectado{'s' if count != 1 else ''})"
            self.log(f"=== Escaneo completado. Equipos totales encontrados: {count} ===")
        except Exception as exc:
            self.log(f"Error durante el escaneo: {exc}")
            self.scan_status_text = f"Error: {exc}"
        finally:
            self.scan_in_progress = False

    def _sweep_subnet_arp(
        self,
        cidr: str,
        adapter: NetworkAdapter,
        full_sweep: bool = True,
    ) -> int:
        """
        Sweeps a /24 subnet (or priority IPs) using parallel Windows SendARP calls.
        Returns number of responding hosts.
        """
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except Exception:
            return 0

        src_ip = adapter.primary_ip if adapter.primary_ip != "0.0.0.0" else "0.0.0.0"
        if full_sweep and net.num_addresses <= 512:
            target_ips = [str(ip) for ip in net.hosts()]
        else:
            base = str(net.network_address).rsplit(".", 1)[0]
            target_ips = [f"{base}.{octet}" for octet in PRIORITY_HOST_OCTETS]

        found_count = 0

        def probe_ip(ip_str: str) -> None:
            nonlocal found_count
            mac = send_arp_request(ip_str, src_ip)
            if mac:
                found_count += 1
                self.register_device(
                    ip=ip_str,
                    mac=mac,
                    method="ARP Activo",
                    adapter=adapter,
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=96) as executor:
            list(executor.map(probe_ip, target_ips))

        return found_count

    def _run_cross_subnet_discovery(
        self,
        adapter: NetworkAdapter,
        custom_subnets: Optional[list[str]] = None,
    ) -> None:
        """
        Probes common industrial/office subnets (192.168.0.x, 192.168.1.x, 10.0.0.x, etc.)
        that differ from the PC's current IP address.
        When running with Administrator rights, temporarily binds an on-link route to the
        Ethernet interface so Windows kernel emits direct Layer-2 ARP requests on the wire
        even when the PC is in APIPA (169.254.x.x) or another subnet!
        """
        own_nets = set()
        for ip_str, prefix in adapter.ipv4_addresses:
            try:
                own_nets.add(str(ipaddress.IPv4Network(f"{ip_str}/24", strict=False)))
            except Exception:
                pass

        candidate_subnets = [s for s in (custom_subnets or COMMON_INDUSTRIAL_SUBNETS) if s not in own_nets]
        if not candidate_subnets:
            return

        admin = is_admin()
        if admin:
            self.log("Modo Administrador activo: sondeando subredes cruzadas vía rutas directas Capa 2 (On-Link ARP)...")
        else:
            self.log("Sondeando IPs estáticas comunes en subredes industriales (ejecuta como Administrador para barrido Capa 2 profundo sin cambiar IP)...")

        total = len(candidate_subnets)
        for idx, subnet_cidr in enumerate(candidate_subnets):
            self.scan_status_text = f"Buscando en subred externa {subnet_cidr}..."
            self.scan_progress = 0.65 + 0.30 * ((idx + 1) / total)

            net = ipaddress.IPv4Network(subnet_cidr, strict=False)
            net_addr = str(net.network_address)
            mask_addr = str(net.netmask)

            route_added = False
            if admin:
                # Add temporary on-link route: route add 192.168.1.0 mask 255.255.255.0 0.0.0.0 IF <ifIndex>
                try:
                    res = subprocess.run(
                        ["route", "add", net_addr, "mask", mask_addr, "0.0.0.0", "IF", str(adapter.if_index), "metric", "5"],
                        capture_output=True,
                        timeout=3,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    route_added = res.returncode == 0
                except Exception:
                    route_added = False

            try:
                # First probe priority static octets (.1, .10, .100, .200, .250, .254, etc.)
                hits = self._sweep_subnet_arp(subnet_cidr, adapter, full_sweep=False)
                # If any device responded on this foreign subnet, sweep the entire /24!
                if hits > 0:
                    self.log(f"¡Actividad detectada en subred externa {subnet_cidr}! Escaneando rango completo /24...")
                    self._sweep_subnet_arp(subnet_cidr, adapter, full_sweep=True)
            finally:
                if route_added:
                    try:
                        subprocess.run(
                            ["route", "delete", net_addr, "mask", mask_addr, "0.0.0.0", "IF", str(adapter.if_index)],
                            capture_output=True,
                            timeout=3,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                    except Exception:
                        pass


def add_temporary_ip_alias(if_index: int, target_device_ip: str) -> tuple[bool, str]:
    """
    Helper to add a compatible secondary IP address to the Windows Ethernet adapter
    so the user can immediately open the device's web interface or connect via PLC software.
    Requires Administrator privileges.
    """
    try:
        parts = [int(x) for x in target_device_ip.split(".")]
        last_octet = parts[3]
        # Pick a safe host octet (.222 or .223) different from the target device
        new_host = 222 if last_octet != 222 else 223
        alias_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{new_host}"

        cmd = [
            "netsh",
            "interface",
            "ipv4",
            "add",
            "address",
            f"name={if_index}",
            f"addr={alias_ip}",
            "mask=255.255.255.0",
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=6,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if proc.returncode == 0:
            return True, f"IP secundaria {alias_ip}/24 agregada exitosamente a la interfaz #{if_index}."
        else:
            err = (proc.stderr or proc.stdout).strip()
            return False, f"No se pudo agregar la IP ({err}). Ejecuta la aplicación como Administrador."
    except Exception as exc:
        return False, str(exc)
