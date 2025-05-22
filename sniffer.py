from scapy.all import sniff, wrpcap

# List to store captured packets
packets = []

# Function to handle each packet
def process_packet(packet):
    print(packet.summary())
    packets.append(packet)

# Start sniffing (you can increase count or set timeout)
sniff(prn=process_packet, count=20)

# Save captured packets to a file
wrpcap("captured_packets.pcap", packets)
print("[+] Packets saved to captured_packets.pcap")
