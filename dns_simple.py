#!/usr/bin/env python3
import socket
import sys
import re
import dns.resolver
import dns.reversename

class DNSClient:
    def __init__(self):
        self.custom_dns = None
        self.resolver = dns.resolver.Resolver()
        # Păstrăm serverele DNS implicite
        self.system_dns = self.resolver.nameservers.copy()
    
    def is_valid_ip(self, ip):
        """Verifică dacă un string este o adresă IP validă."""
        pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if not re.match(pattern, ip):
            return False
        
        # Verifică fiecare octet
        octets = ip.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                return False
        
        return True
    
    def resolve_domain(self, domain):
        """Rezolvă un domeniu în adrese IP."""
        try:
            # Configurează resolver-ul cu serverul DNS specificat sau cel implicit
            if self.custom_dns:
                self.resolver.nameservers = [self.custom_dns]
            else:
                self.resolver.nameservers = self.system_dns
            
            # Încearcă să obțină înregistrări A (IPv4)
            answers = self.resolver.resolve(domain, 'A')
            
            print(f"IP-uri pentru domeniul {domain}:")
            for rdata in answers:
                print(f"- {rdata}")
            
        except dns.resolver.NXDOMAIN:
            print(f"Eroare: Domeniul {domain} nu există")
        except dns.resolver.NoAnswer:
            print(f"Eroare: Nu s-a găsit niciun IP pentru domeniul {domain}")
        except Exception as e:
            print(f"Eroare la rezolvarea domeniului: {str(e)}")
    
    def resolve_ip(self, ip):
        """Rezolvă o adresă IP în domeniu."""
        try:
            # Configurează resolver-ul cu serverul DNS specificat sau cel implicit
            if self.custom_dns:
                self.resolver.nameservers = [self.custom_dns]
            else:
                self.resolver.nameservers = self.system_dns
            
            # Convertește IP-ul în format pentru căutare inversă
            addr = dns.reversename.from_address(ip)
            
            # Obține înregistrarea PTR
            answers = self.resolver.resolve(addr, 'PTR')
            
            print(f"Domenii pentru IP-ul {ip}:")
            for rdata in answers:
                print(f"- {rdata}")
        
        except dns.resolver.NXDOMAIN:
            print(f"Eroare: Nu s-a găsit niciun domeniu pentru IP-ul {ip}")
        except Exception as e:
            print(f"Eroare la rezolvarea IP-ului {ip}: {str(e)}")
    
    def set_dns_server(self, ip):
        """Setează serverul DNS pentru rezolvare."""
        if not self.is_valid_ip(ip):
            print(f"Eroare: '{ip}' nu este o adresă IP validă.")
            return False
        
        # Setează noul server DNS
        self.custom_dns = ip
        print(f"Serverul DNS a fost schimbat la {ip}")
        return True
    
    def process_command(self, cmd_args):
        """Procesează comenzile utilizatorului."""
        if not cmd_args:
            self.show_usage()
            return
        
        cmd = cmd_args[0].lower()
        
        if cmd == "resolve" and len(cmd_args) >= 2:
            host = cmd_args[1]
            if self.is_valid_ip(host):
                self.resolve_ip(host)
            else:
                self.resolve_domain(host)
        
        elif cmd == "use" and len(cmd_args) >= 3 and cmd_args[1].lower() == "dns":
            self.set_dns_server(cmd_args[2])
        
        else:
            self.show_usage()
    
    def show_usage(self):
        """Afișează instrucțiuni de utilizare."""
        print("Utilizare:")
        print("  resolve <domeniu/IP> - rezolvă un domeniu în IP sau un IP în domeniu")
        print("  use dns <IP> - schimbă serverul DNS utilizat pentru rezolvare")

def main():
    # Verifică dacă biblioteca dnspython este instalată
    try:
        import dns.resolver
    except ImportError:
        print("Eroare: Biblioteca 'dnspython' nu este instalată.")
        print("Instalați-o folosind comanda: pip install dnspython")
        sys.exit(1)
    
    client = DNSClient()
    
    if len(sys.argv) > 1:
        # Mod linie de comandă
        client.process_command(sys.argv[1:])
    else:
        # Mod interactiv
        print("Client DNS - Introduceți 'quit' pentru a ieși")
        print("Comenzi disponibile: 'resolve <domeniu/IP>', 'use dns <IP>'")
        
        while True:
            try:
                cmd_input = input("\nIntroduceți o comandă: ").strip()
                if cmd_input.lower() in ['quit', 'exit']:
                    break
                
                args = cmd_input.split()
                client.process_command(args)
            
            except KeyboardInterrupt:
                print("\nLa revedere!")
                break
            except Exception as e:
                print(f"Eroare: {str(e)}")

if __name__ == "__main__":
    main()