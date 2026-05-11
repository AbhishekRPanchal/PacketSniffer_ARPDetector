from packet_sniffer import start_sniffer
from arp_detector import start_detector
import threading


def menu():

    while True:

        print("\n==============================")
        print("🛡️ Network Security Toolkit")
        print("==============================")
        print("1. Start Packet Sniffer")
        print("2. Start ARP Spoofing Detector")
        print("3. Run Both")
        print("4. Exit")

        choice = input("\nEnter choice: ")

        if choice == "1":
            start_sniffer()

        elif choice == "2":
            start_detector()

        elif choice == "3":

            t1 = threading.Thread(target=start_sniffer)
            t2 = threading.Thread(target=start_detector)

            t1.start()
            t2.start()

            t1.join()
            t2.join()

        elif choice == "4":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    menu()