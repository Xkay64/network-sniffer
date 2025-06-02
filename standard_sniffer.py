from scapy.all import sniff
from datetime import datetime

log_file = "packet_log.txt"

def log_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info = f"[{timestamp}] {packet.summary()}\n"
    print(info.strip())  
    with open(log_file, "a") as f:
        f.write(info)


def start_sniffing(interface="eth0", packet_count=0, filter=None):
    print(f"[*] Starting sniffer on {interface} (filter: {filter or 'None'})")
    sniff(iface=interface, prn=log_packet, count=packet_count, filter=filter)

if __name__ == "__main__":
    # Adjust interface and filters as needed
    start_sniffing(interface="eth0", packet_count=0, filter="tcp or udp or icmp")
