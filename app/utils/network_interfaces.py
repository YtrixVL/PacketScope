from scapy.all import get_if_list


def get_network_interfaces():
    """
    Возвращает список сетевых интерфейсов, доступных Scapy.
    """
    try:
        return get_if_list()
    except Exception:
        return []