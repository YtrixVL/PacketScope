import csv


class ReportExporter:
    """
    Экспортирует результаты анализа в CSV и TXT.
    """

    def export_to_csv(self, packet_infos, file_path: str):
        with open(file_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            writer.writerow([
                "Number",
                "Time",
                "Source",
                "Destination",
                "Protocol",
                "Length",
                "Info"
            ])

            for packet in packet_infos:
                writer.writerow([
                    packet.number,
                    packet.timestamp,
                    packet.source,
                    packet.destination,
                    packet.protocol,
                    packet.length,
                    packet.info
                ])

    def export_to_txt(self, packet_infos, statistics, security_warnings, file_path: str):
        with open(file_path, "w", encoding="utf-8") as file:
            file.write("PacketScope Traffic Report\n")
            file.write("=" * 40 + "\n\n")

            file.write("Statistics\n")
            file.write("-" * 40 + "\n")
            file.write(f"Total packets: {statistics['total_packets']}\n")
            file.write(f"Total size: {statistics['total_size']} bytes\n")
            file.write(f"Average packet size: {statistics['average_size']:.2f} bytes\n\n")

            file.write("Protocols\n")
            file.write("-" * 40 + "\n")

            for protocol, count in sorted(statistics["protocols"].items()):
                file.write(f"{protocol}: {count}\n")

            file.write("\nTop IP addresses\n")
            file.write("-" * 40 + "\n")

            for ip_address, count in statistics["top_ips"]:
                file.write(f"{ip_address}: {count}\n")

            file.write("\nDNS domains\n")
            file.write("-" * 40 + "\n")

            if statistics["dns_domains"]:
                for domain, count in statistics["dns_domains"]:
                    file.write(f"{domain}: {count}\n")
            else:
                file.write("No DNS domains found\n")

            file.write("\nSecurity analysis\n")
            file.write("-" * 40 + "\n")

            for warning in security_warnings:
                file.write(f"- {warning}\n")

            file.write("\nPackets\n")
            file.write("-" * 40 + "\n")

            for packet in packet_infos:
                file.write(
                    f"{packet.number}. "
                    f"[{packet.timestamp}] "
                    f"{packet.source} -> {packet.destination} "
                    f"{packet.protocol} "
                    f"{packet.length} bytes "
                    f"{packet.info}\n"
                )