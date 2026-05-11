from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
import os

LOG_FILE = "logs/sniffer.log"


def log_packet(message):
    os.makedirs("logs", exist_ok=True)

    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


def process_packet(packet):

    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        protocol = "OTHER"

        if packet.haslayer(TCP):
            protocol = "TCP"

        elif packet.haslayer(UDP):
            protocol = "UDP"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        message = f"[{timestamp}] {protocol}: {src} -> {dst}"

        print(message)

        log_packet(message)


def start_sniffer():
    print("\n🔍 Packet Sniffer Started...\n")

    sniff(prn=process_packet, store=False)