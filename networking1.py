import platform
import subprocess
import pandas as pd
import time
import re
import socket
import nmap
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt

def get_network_info():
    system_platform = platform.system().lower()

    if system_platform == 'windows':
        ipconfig_result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        network_info_text = ipconfig_result.stdout
    elif system_platform == 'linux':
        ifconfig_result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        network_info_text = ifconfig_result.stdout
    else:
        print("Unsupported platform.")
        return None

    return network_info_text

def extract_ip_addresses(network_info_text):
    ip_addresses = re.findall(r'(\d+\.\d+\.\d+\.\d+)', network_info_text)
    return ip_addresses

def scan_open_ports(ip_address):
    nm = nmap.PortScanner()
    open_ports = []

    start_time = time.time()

    try:
        while time.time() - start_time < 30:
            nm.scan(ip_address, arguments='-p 1-1024')
            for port in nm[ip_address]['tcp']:
                state = nm[ip_address]['tcp'][port]['state']

                # Try to get service name
                service = None
                try:
                    service = socket.getservbyport(port)
                except socket.error:
                    pass

                open_ports.append({'Port': port, 'State': state, 'Service': service})
    except KeyError:
        print(f"No open ports information found for {ip_address}")

    # Print the results in tabular format
    print("\nOpen Ports for IP address {}: (Scanned for {} seconds)".format(ip_address, round(time.time() - start_time, 2)))
    print("{:<10} {:<10} {:<15}".format("Port", "State", "Service"))
    print("-" * 35)
    for port_info in open_ports:
        print("{:<10} {:<10} {:<15}".format(port_info['Port'], port_info['State'], port_info['Service']))

    return open_ports

def scan_open_ports(target_ip: str) -> str:
    try:
        # Run Nmap command with a timeout of 10 seconds
        result = subprocess.check_output(['nmap', '-sV','-T4','-O', '-F','--version-light', target_ip], timeout=30)
        return result.decode('utf-8')

    except subprocess.TimeoutExpired:
        logging.warning(f"Scanning IP {target_ip} timed out after 30 seconds. Moving to the next IP.")
        return "Timeout: Scanning took longer than 30 seconds."

    except Exception as e:
        logging.error(f"Error in scan_open_ports: {str(e)}")
        return f"Error: {str(e)}"

    

def analyze_network_info(ip_addresses):
    df_data = {'Interface': [], 'IP Address': []}

    for ip_address in ip_addresses:
        df_data['Interface'].append(socket.gethostname())
        df_data['IP Address'].append(ip_address)

    df = pd.DataFrame(df_data)
    return df

def packet_sniffer(packet_count, packets):
    def count_packets(packet_type):
        return sum(1 for packet in packets if packet_type in packet)

    # Stop sniffing after capturing 50 packets
    #if len(packets) >= packet_count:
       # sniff_process.stop()
    
    # Display captured packets in a tabular form
    df_data = {
        'Packet Type': ['TCP', 'UDP', 'ICMP'],
        'Packet Count': [count_packets(TCP), count_packets(UDP), count_packets(ICMP)]
    }

    df = pd.DataFrame(df_data)
    print("\nCaptured Packets:")
    print(df)

    # Plot the analysis of captured packets
    plt.figure(figsize=(8, 6))
    plt.bar(df['Packet Type'], df['Packet Count'], color=['blue', 'orange', 'green'])
    plt.title('Analysis of Captured Packets')
    plt.xlabel('Packet Type')
    plt.ylabel('Packet Count')
    plt.show()

def start_packet_sniffing(packet_count):
    packets = []

    def packet_callback(packet):
        if IP in packet:
            packets.append(packet)

    print(f"Packet Sniffing Started. Capturing {packet_count} packets. Press Ctrl+C to stop.")
    sniff_process = sniff(prn=packet_callback, store=0, count=packet_count)
    packet_sniffer(packet_count, packets)

def main():
    network_info_text = get_network_info()

    if network_info_text:
        ip_addresses = extract_ip_addresses(network_info_text)

        print("Network Statistics and Analysis:")
        df = analyze_network_info(ip_addresses)
        print(df)

        for ip_address in ip_addresses:
            print(f"\nScanning open ports for IP address: {ip_address}")
            open_ports = scan_open_ports(ip_address)
            print("Open Ports:")
            print(open_ports)
        
        start_packet_sniffing(packet_count=50)
if __name__ == "__main__":
    main()
