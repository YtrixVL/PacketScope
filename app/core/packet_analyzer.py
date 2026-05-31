from datetime import datetime
import string

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS
from scapy.packet import Raw

from app.models.packet_info import PacketInfo


class PacketAnalyzer:
    MAX_PAYLOAD_PREVIEW = 512

    TCP_PORT_PROTOCOLS = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        3306: "MYSQL",
        3389: "RDP",
        5432: "POSTGRESQL",
        6379: "REDIS",
        8080: "HTTP-ALT",
        8443: "HTTPS-ALT",
    }

    UDP_PORT_PROTOCOLS = {
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        123: "NTP",
        137: "NETBIOS",
        138: "NETBIOS",
        161: "SNMP",
        162: "SNMP",
        500: "ISAKMP",
        1900: "SSDP",
        5353: "MDNS",
    }

    def analyze(self, packet, number: int) -> PacketInfo:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        return PacketInfo(
            number=number,
            timestamp=timestamp,
            source=self.get_source(packet),
            destination=self.get_destination(packet),
            protocol=self.get_protocol(packet),
            length=len(packet),
            info=self.get_info(packet)
        )

    def get_source(self, packet) -> str:
        if packet.haslayer(IP):
            return packet[IP].src

        if packet.haslayer(ARP):
            return packet[ARP].psrc

        if packet.haslayer(Ether):
            return packet[Ether].src

        return "Unknown"

    def get_destination(self, packet) -> str:
        if packet.haslayer(IP):
            return packet[IP].dst

        if packet.haslayer(ARP):
            return packet[ARP].pdst

        if packet.haslayer(Ether):
            return packet[Ether].dst

        return "Unknown"

    def get_protocol(self, packet) -> str:
        if packet.haslayer(DNS):
            return "DNS"

        if packet.haslayer(TCP):
            tcp = packet[TCP]

            if tcp.sport in self.TCP_PORT_PROTOCOLS:
                return self.TCP_PORT_PROTOCOLS[tcp.sport]

            if tcp.dport in self.TCP_PORT_PROTOCOLS:
                return self.TCP_PORT_PROTOCOLS[tcp.dport]

            return "TCP"

        if packet.haslayer(UDP):
            udp = packet[UDP]

            if udp.sport in self.UDP_PORT_PROTOCOLS:
                return self.UDP_PORT_PROTOCOLS[udp.sport]

            if udp.dport in self.UDP_PORT_PROTOCOLS:
                return self.UDP_PORT_PROTOCOLS[udp.dport]

            return "UDP"

        if packet.haslayer(ICMP):
            return "ICMP"

        if packet.haslayer(ARP):
            return "ARP"

        if packet.haslayer(IP):
            return "IP"

        return "OTHER"

    def get_info(self, packet) -> str:
        protocol = self.get_protocol(packet)

        if packet.haslayer(DNS):
            domain = self.get_dns_query_name(packet)

            if domain:
                return f"DNS query: {domain}"

            return "DNS packet"

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = str(tcp.flags)

            return (
                f"{protocol} TCP "
                f"{tcp.sport} → {tcp.dport} "
                f"Flags={flags}"
            )

        if packet.haslayer(UDP):
            udp = packet[UDP]

            return (
                f"{protocol} UDP "
                f"{udp.sport} → {udp.dport}"
            )

        if packet.haslayer(ICMP):
            return "ICMP packet"

        if packet.haslayer(ARP):
            return "ARP packet"

        return packet.summary()

    def get_dns_query_name(self, packet) -> str | None:
        if not packet.haslayer(DNS):
            return None

        dns = packet[DNS]

        if not dns.qd:
            return None

        try:
            return dns.qd.qname.decode(errors="ignore").rstrip(".")
        except Exception:
            return None

    def get_structure_details(self, packet) -> str:
        lines = []

        lines.append("=== Packet Summary ===")
        lines.append(packet.summary())
        lines.append("")

        lines.append("=== Main Info ===")
        lines.append(f"Source:      {self.get_source(packet)}")
        lines.append(f"Destination: {self.get_destination(packet)}")
        lines.append(f"Protocol:    {self.get_protocol(packet)}")
        lines.append(f"Length:      {len(packet)} bytes")
        lines.append(f"Info:        {self.get_info(packet)}")
        lines.append("")

        if packet.haslayer(Ether):
            eth = packet[Ether]
            lines.append("=== Ethernet ===")
            lines.append(f"Source MAC:      {eth.src}")
            lines.append(f"Destination MAC: {eth.dst}")
            lines.append(f"Type:            {eth.type}")
            lines.append("")

        if packet.haslayer(IP):
            ip = packet[IP]
            lines.append("=== IPv4 ===")
            lines.append(f"Version:         {ip.version}")
            lines.append(f"Header length:   {ip.ihl * 4} bytes")
            lines.append(f"TTL:             {ip.ttl}")
            lines.append(f"Source IP:       {ip.src}")
            lines.append(f"Destination IP:  {ip.dst}")
            lines.append(f"Protocol number: {ip.proto}")
            lines.append("")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            lines.append("=== TCP ===")
            lines.append(f"Source port:      {tcp.sport}")
            lines.append(f"Destination port: {tcp.dport}")
            lines.append(f"Detected protocol:{self.get_protocol(packet)}")
            lines.append(f"Sequence number:  {tcp.seq}")
            lines.append(f"Ack number:       {tcp.ack}")
            lines.append(f"Flags:            {tcp.flags}")
            lines.append(f"Window size:      {tcp.window}")
            lines.append("")

        if packet.haslayer(UDP):
            udp = packet[UDP]
            lines.append("=== UDP ===")
            lines.append(f"Source port:      {udp.sport}")
            lines.append(f"Destination port: {udp.dport}")
            lines.append(f"Detected protocol:{self.get_protocol(packet)}")
            lines.append(f"Length:           {udp.len}")
            lines.append("")

        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            lines.append("=== ICMP ===")
            lines.append(f"Type: {icmp.type}")
            lines.append(f"Code: {icmp.code}")
            lines.append("")

        if packet.haslayer(ARP):
            arp = packet[ARP]
            lines.append("=== ARP ===")
            lines.append(f"Operation:        {arp.op}")
            lines.append(f"Sender MAC:       {arp.hwsrc}")
            lines.append(f"Sender IP:        {arp.psrc}")
            lines.append(f"Target MAC:       {arp.hwdst}")
            lines.append(f"Target IP:        {arp.pdst}")
            lines.append("")

        if packet.haslayer(DNS):
            lines.append(self.get_dns_details(packet))
            lines.append("")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            lines.append("=== Payload ===")
            lines.append(f"Payload length: {len(payload)} bytes")
            lines.append("Payload content is available in ASCII, HEX and Raw tabs.")
        else:
            lines.append("=== Payload ===")
            lines.append("No payload")

        return "\n".join(lines)

    def get_dns_details(self, packet) -> str:
        dns = packet[DNS]
        lines = []

        lines.append("=== DNS ===")
        lines.append(f"Transaction ID: {dns.id}")
        lines.append(f"Questions:      {dns.qdcount}")
        lines.append(f"Answers:        {dns.ancount}")

        domain = self.get_dns_query_name(packet)

        if domain:
            lines.append(f"Query name:     {domain}")

        return "\n".join(lines)

    def get_ascii_view(self, packet) -> str:
        if not packet.haslayer(Raw):
            return "No payload"

        payload = packet[Raw].load
        preview = payload[:self.MAX_PAYLOAD_PREVIEW]

        lines = []
        lines.append(f"Payload length: {len(payload)} bytes")

        if len(payload) > self.MAX_PAYLOAD_PREVIEW:
            lines.append(f"Shown first {self.MAX_PAYLOAD_PREVIEW} bytes")
            lines.append("")

        lines.append(self.bytes_to_ascii_preview(preview))

        if not self.looks_like_text(payload):
            lines.append("")
            lines.append(
                "Note: payload looks like binary or encrypted data. "
                "For HTTPS/TLS traffic, readable text is usually not available."
            )

        return "\n".join(lines)

    def get_hex_view(self, packet) -> str:
        if not packet.haslayer(Raw):
            return "No payload"

        payload = packet[Raw].load
        preview = payload[:self.MAX_PAYLOAD_PREVIEW]

        lines = []
        lines.append(f"Payload length: {len(payload)} bytes")

        if len(payload) > self.MAX_PAYLOAD_PREVIEW:
            lines.append(f"Shown first {self.MAX_PAYLOAD_PREVIEW} bytes")
            lines.append("")

        lines.append(self.bytes_to_hex_preview(preview))

        return "\n".join(lines)

    def get_raw_view(self, packet) -> str:
        try:
            return packet.show(dump=True)
        except Exception as error:
            return f"Cannot show raw packet: {error}"

    def get_full_details(self, packet) -> str:
        return self.get_structure_details(packet)

    def bytes_to_ascii_preview(self, data: bytes) -> str:
        result = []

        for byte in data:
            char = chr(byte)

            if char in string.printable and char not in "\r\n\t\x0b\x0c":
                result.append(char)
            elif char in "\r\n\t":
                result.append(char)
            else:
                result.append(".")

        return "".join(result)

    def bytes_to_hex_preview(self, data: bytes, bytes_per_line: int = 16) -> str:
        lines = []

        for offset in range(0, len(data), bytes_per_line):
            chunk = data[offset:offset + bytes_per_line]
            hex_part = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_part = self.bytes_to_ascii_preview(chunk)
            lines.append(f"{offset:08x}  {hex_part:<48}  {ascii_part}")

        return "\n".join(lines)

    def looks_like_text(self, data: bytes) -> bool:
        if not data:
            return False

        sample = data[:256]
        printable_count = 0

        for byte in sample:
            if chr(byte) in string.printable:
                printable_count += 1

        return printable_count / len(sample) > 0.85