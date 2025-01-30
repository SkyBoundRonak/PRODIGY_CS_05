from scapy.all import sniff, IP, Raw

# Define the callback function to handle packets
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address
        protocol = packet.proto   # Protocol (e.g., TCP, UDP)
        
        # Display the basic information
        print(f"Packet captured: {packet.summary()}")
        print(f"Source IP: {ip_src} --> Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        
        # If the packet contains payload data
        if packet.haslayer(Raw):
            payload = packet[Raw].load  # Raw payload data
            print(f"Payload Data: {payload}")
        print("="*50)

# Start sniffing the network
def start_sniffing():
    print("[*] Starting packet sniffer... Press Ctrl+C to stop.")
    # Sniff packets on the network, call packet_callback for each packet captured
    sniff(prn=packet_callback, store=0)  # prn specifies the callback function, store=0 avoids storing packets

if __name__ == "__main__":
    start_sniffing()
