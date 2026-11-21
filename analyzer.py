
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS
from collections import Counter


def analyze_pcap(filepath):

    # Lecture du fichier PCAP
    packets = rdpcap(filepath)

    # Statistiques generales
    total_packets = len(packets)

    packet_sizes = [len(packet) for packet in packets]

    total_bytes = sum(packet_sizes)

    average_size = (
        total_bytes / total_packets
        if total_packets > 0 else 0
    )

    max_size = max(packet_sizes) if packet_sizes else 0
    min_size = min(packet_sizes) if packet_sizes else 0

    # Compteurs
    source_ips = Counter()
    destination_ips = Counter()
    protocols = Counter()

    # Liste des anomalies
    anomalies = []

    # Analyse des paquets
    for packet in packets:

        # Detection des paquets volumineux
        if len(packet) > 1500:
            anomalies.append(
                f"Paquet volumineux detecte : {len(packet)} Bytes"
            )

        if IP in packet:

            src = packet[IP].src
            dst = packet[IP].dst

            source_ips[src] += 1
            destination_ips[dst] += 1

            # Detection des protocoles
            if DNS in packet:
                protocols["DNS"] += 1

            elif TCP in packet:
                protocols["TCP"] += 1

            elif UDP in packet:
                protocols["UDP"] += 1

            elif ICMP in packet:
                protocols["ICMP"] += 1

            else:
                protocols["Other"] += 1

        else:
            protocols["Non-IP"] += 1

    # Detection d'un trafic eleve
    for ip, count in source_ips.items():

        if count > 100:
            anomalies.append(
                f"Trafic eleve detecte depuis {ip} : {count} paquets"
            )

    # Resultats
    return {
        "total_packets": total_packets,
        "source_ips": dict(source_ips),
        "destination_ips": dict(destination_ips),
        "protocols": dict(protocols),
        "total_bytes": total_bytes,
        "average_size": round(average_size, 2),
        "max_size": max_size,
        "min_size": min_size,
        "anomalies": anomalies
    }
