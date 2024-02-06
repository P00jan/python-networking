import socket
import sys
import platform
import subprocess

def send_tcp_packet(target_ip, target_port, packet_count=20):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((target_ip, target_port))
        for _ in range(packet_count):
            s.sendall(b'This is a TCP packet')

def send_udp_packet(target_ip, target_port, packet_count=20):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _ in range(packet_count):
            s.sendto(b'This is a UDP packet', (target_ip, target_port))

def send_icmp_packet(target_ip, packet_count=20):
    if platform.system().lower() == 'windows':
        command = ['ping', '-n', str(packet_count), target_ip]
    elif platform.system().lower() == 'linux':
        command = ['ping', '-c', str(packet_count), target_ip]
    else:
        print("Unsupported operating system.")
        sys.exit(1)

    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")

    try:
        target_ip = socket.gethostbyname(target_ip)
    except socket.error as e:
        print(f"Error: {e}")
        sys.exit(1)

    target_port = 9012  # You can change this to the desired port
    packet_count = 20

    os_choice = input("Choose your operating system (windows/linux): ").lower()

    if os_choice == 'windows':
        send_tcp_packet(target_ip, target_port, packet_count)
        send_udp_packet(target_ip, target_port, packet_count)
        send_icmp_packet(target_ip, packet_count)
    elif os_choice == 'linux':
        send_tcp_packet(target_ip, target_port, packet_count)
        send_udp_packet(target_ip, target_port, packet_count)
        send_icmp_packet(target_ip, packet_count)
    else:
        print("Unsupported operating system.")
        sys.exit(1)
