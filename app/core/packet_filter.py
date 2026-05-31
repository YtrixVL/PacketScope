class PacketFilter:
    def filter_packet_infos(self, packet_infos, query: str):
        if not query:
            return packet_infos

        query = query.lower().strip()

        result = []

        for packet_info in packet_infos:
            searchable_text = (
                f"{packet_info.number} "
                f"{packet_info.timestamp} "
                f"{packet_info.source} "
                f"{packet_info.destination} "
                f"{packet_info.protocol} "
                f"{packet_info.length} "
                f"{packet_info.info}"
            ).lower()

            if query in searchable_text:
                result.append(packet_info)

        return result