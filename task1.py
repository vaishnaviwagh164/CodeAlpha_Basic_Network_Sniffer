from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    print("\n========== Network Packet ==========")

    if IP in packet:
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)

        if TCP in packet:
            print("Protocol       : TCP")
        elif UDP in packet:
            print("Protocol       : UDP")
        elif ICMP in packet:
            print("Protocol       : ICMP")
        else:
            print("Protocol       : Other")

        if packet.haslayer(TCP):
            print("Source Port    :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Source Port    :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        if packet.haslayer("Raw"):
            payload = bytes(packet["Raw"].load)
            print("Payload        :", repr(payload[:50]))
        else:
            print("Payload        : No readable payload available")

    else:
        print("Non-IP packet detected")

    print("====================================")


def main():
    print("====================================")
    print("       BASIC NETWORK SNIFFER")
    print("====================================")
    print("Starting packet capture...")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(prn=analyze_packet, store=False)
    except PermissionError:
        print("Permission denied. Run with appropriate privileges.")
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
        print("Thank you for using Basic Network Sniffer!")


if __name__ == "__main__":
    main()