from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv
from datetime import datetime

OUTPUT_FILE = "packet_report.csv"
PACKET_LIMIT = 30
packet_count = 0

def analyze_packet(packet):
    global packet_count

    if IP not in packet:
        return

    ip = packet[IP]
    source = ip.src
    destination = ip.dst
    size = len(packet)

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other"

    packet_count += 1
    timestamp = datetime.now().strftime("%H:%M:%S")

    print(
        f"{packet_count}. {source} -> {destination} | "
        f"{protocol} | {size} bytes"
    )

    with open(OUTPUT_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp, source, destination, protocol, size
        ])

def main():
    print("=" * 55)
    print("       BASIC NETWORK SNIFFER")
    print("=" * 55)
    print("Capturing up to 30 IP packets.")
    print("Use only on networks you are authorized to monitor.")
    print("Press Ctrl+C to stop early.\n")

    with open(OUTPUT_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Time", "Source IP", "Destination IP",
            "Protocol", "Packet Size (Bytes)"
        ])

    try:
        sniff(
            filter="ip",
            prn=analyze_packet,
            count=PACKET_LIMIT,
            store=False
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as error:
        print("\nCapture error:", error)
        print("Check Npcap installation and permissions.")
    finally:
        print(f"\nPackets analyzed: {packet_count}")
        print(f"Report saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()