from scapy.all import sniff, ARP
import datetime
import os

arp_table = {}

LOG_FILE = "logs/arp_alerts.log"


def log_alert(message):
    os.makedirs("logs", exist_ok=True)

    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

def detect_arp(packet):

    if packet.haslayer(ARP):

        print(packet.summary())

        if packet[ARP].op == 2:

            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc

            print(f"ARP Reply -> IP: {ip}, MAC: {mac}")

            if ip in arp_table:

                if arp_table[ip] != mac:

                    alert = (
                        f"\n🚨 POSSIBLE ARP SPOOFING DETECTED!\n"
                        f"IP Address: {ip}\n"
                        f"Old MAC: {arp_table[ip]}\n"
                        f"New MAC: {mac}\n"
                    )

                    print(alert)

                    log_alert(alert)

            arp_table[ip] = mac

def start_detector():
    print("\n🛡️ ARP Spoofing Detector Started...\n")

    sniff(prn=detect_arp, store=False)