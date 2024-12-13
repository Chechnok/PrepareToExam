import socket

def scan_ports(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

if __name__ == "__main__":
    host = input("Enter host to scan (e.g., 127.0.0.1): ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    print(f"Scanning ports {start_port}-{end_port} on host {host}...")
    open_ports = scan_ports(host, start_port, end_port)
    print("Open ports:", open_ports)
