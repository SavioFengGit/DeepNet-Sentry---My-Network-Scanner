import argparse
from scapy.all import srp, Ether, ARP, conf
import sys
import socket

class NetworkScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip

    def get_hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.timeout):
            return "Unknown"

    def scan_arp(self):
        print(f"[*] Scanning Started on the IP: {self.target_ip}")
        
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target_ip)
        answered_list = srp(packet, timeout=2, verbose=False)[0]

        clients = []
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            hostname = self.get_hostname(ip)
            
            clients.append({"ip": ip, "mac": mac, "hostname": hostname})
        
        return clients

def display_results(results):
    print("\nIP Address\t\tMAC Address\t\tHostname")
    print("-" * 70)
    for client in results:
        print(f"{client['ip']:20}\t{client['mac']:20}\t{client['hostname']}")

def main():
    parser = argparse.ArgumentParser(description="Python Network Scanner (Nmap-style)")
    parser.add_argument("-t", "--target", dest="target", help="Target IP o Range IP", required=True)
    args = parser.parse_args()

    try:
        scanner = NetworkScanner(args.target)
        scan_results = scanner.scan_arp()
        display_results(scan_results)
        
    except KeyboardInterrupt:
        print("\n[!] Scansione interrotta dall'utente.")
        sys.exit()
    except Exception as e:
        print(f"[!] Errore durante la scansione: {e}")

if __name__ == "__main__":
    main()