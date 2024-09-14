import nmap
import subprocess

def scan_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(ip_range, '1-1024')
    return nm

def check_vulnerabilities(scan_data):
    vulnerabilities = []
    for host in scan_data.all_hosts():
        for proto in scan_data[host].all_protocols():
            lport = scan_data[host][proto].keys()
            for port in lport:
                if scan_data[host][proto][port]['state'] == 'open':
                    vulnerabilities.append((host, port, proto))
    return vulnerabilities

def exploit_vulnerability(host, port, vulnerability):
    # Örnek bir exploit komutu (gerçek bir exploit komutu kullanmayın)
    result = subprocess.run(['echo', f'Exploiting {host}:{port} for {vulnerability}'], capture_output=True, text=True)
    return result.stdout

def main():
    ip_range = '192.168.1.0/24'  # Test edilecek IP aralığı
    print(f'Scanning network: {ip_range}')
    scan_data = scan_network(ip_range)
    vulnerabilities = check_vulnerabilities(scan_data)
    
    known_vulnerabilities = {
        3389: "MS12-020: Uzak Masaüstündeki Güvenlik Açıkları",
        445: "MS17-010: Microsoft Windows SMB Server ETERNALBLUE",
        443: "SSL/TLS Güvenlik Açıkları",
        80: "HTTP Güvenlik Açıkları",
        # Diğer port ve güvenlik açıkları eşleştirmeleri
    }
    
    if vulnerabilities:
        print('Vulnerabilities found:')
        for host, port, proto in vulnerabilities:
            vulnerability = known_vulnerabilities.get(port, "Unknown Vulnerability")
            print(f'Host: {host}, Port: {port}, Protocol: {proto}, Vulnerability: {vulnerability}')
            exploit_result = exploit_vulnerability(host, port, vulnerability)
            print(f'Exploit result: {exploit_result}')
    else:
        print('No vulnerabilities found.')

if __name__ == '__main__':
    main()