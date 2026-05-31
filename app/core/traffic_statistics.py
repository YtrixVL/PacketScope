from collections import Counter


class TrafficStatistics:
    def calculate(self, packet_infos):
        protocols = Counter()
        ip_counter = Counter()
        dns_domains = Counter()
        total_size = 0

        for packet_info in packet_infos:
            protocols[packet_info.protocol] += 1
            total_size += packet_info.length

            if packet_info.source and packet_info.source != "Unknown":
                ip_counter[packet_info.source] += 1

            if packet_info.destination and packet_info.destination != "Unknown":
                ip_counter[packet_info.destination] += 1

            domain = self.extract_dns_domain(packet_info.info)

            if domain:
                dns_domains[domain] += 1

        total_packets = len(packet_infos)
        average_size = total_size / total_packets if total_packets else 0

        return {
            "total_packets": total_packets,
            "total_size": total_size,
            "average_size": average_size,
            "protocols": dict(protocols),
            "top_ips": ip_counter.most_common(5),
            "dns_domains": dns_domains.most_common(10),
        }

    def extract_dns_domain(self, info: str) -> str | None:
        prefix = "DNS query:"

        if not info.startswith(prefix):
            return None

        domain = info.replace(prefix, "", 1).strip()

        if not domain:
            return None

        return domain