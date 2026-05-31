from collections import Counter


class SecurityAnalyzer:
    SUSPICIOUS_PORTS = {
        23: "TELNET",
        2323: "TELNET-ALT",
        4444: "COMMON-BACKDOOR",
        5555: "ADB/COMMON-BACKDOOR",
        6667: "IRC",
        31337: "BACK-ORIFICE",
    }

    def analyze(self, packet_infos):
        warnings = []

        if not packet_infos:
            return ["Нет данных для анализа безопасности."]

        total_packets = len(packet_infos)
        protocol_counter = Counter(packet.protocol for packet in packet_infos)

        icmp_count = protocol_counter.get("ICMP", 0)
        dns_count = protocol_counter.get("DNS", 0)

        if icmp_count > 50 and icmp_count / total_packets > 0.25:
            warnings.append(
                "Высокая ICMP-активность: возможно выполняется ping scan или диагностика сети."
            )

        if dns_count > 100 and dns_count / total_packets > 0.30:
            warnings.append(
                "Высокая DNS-активность: много DNS-запросов за короткий период."
            )

        unusual_ports = self.find_suspicious_ports(packet_infos)

        for port, protocol_name, count in unusual_ports:
            warnings.append(
                f"Обнаружена активность на подозрительном порту {port} ({protocol_name}), пакетов: {count}."
            )

        syn_like_count = self.count_syn_like_packets(packet_infos)

        if syn_like_count > 100 and syn_like_count / total_packets > 0.20:
            warnings.append(
                "Много TCP SYN-пакетов: возможно сканирование портов или большое количество новых соединений."
            )

        if not warnings:
            warnings.append("Подозрительная активность не обнаружена.")

        return warnings

    def find_suspicious_ports(self, packet_infos):
        counter = Counter()

        for packet_info in packet_infos:
            info = packet_info.info

            for port, protocol_name in self.SUSPICIOUS_PORTS.items():
                if f"→ {port}" in info or f"{port} →" in info:
                    counter[(port, protocol_name)] += 1

        result = []

        for (port, protocol_name), count in counter.items():
            if count >= 3:
                result.append((port, protocol_name, count))

        return result

    def count_syn_like_packets(self, packet_infos):
        count = 0

        for packet_info in packet_infos:
            info = packet_info.info

            if "Flags=S" in info:
                count += 1

        return count