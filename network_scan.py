import socket
import struct
import time
import datetime
import ipaddress
from urllib.parse import urlparse
import subprocess

# Função para enviar um ping e verificar se o host está ativo
def ping_host(host, timeout):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout // 1000), str(host)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result.returncode == 0:
            return True  # Host respondeu ao ping
    except Exception as e:
        print(f"Erro ao pingar {host}: {e}")
    return False

# Função para realizar a varredura de uma rede e encontrar hosts ativos
def scan_network(network, timeout):
    active_hosts = []
    total_hosts = 0
    start_scan = time.time()

    for host in network:
        if host == network.network_address or host == network.broadcast_address:
            continue

        total_hosts += 1
        if ping_host(host, timeout):
            active_hosts.append(str(host))

    end_scan = time.time()
    total_scan_time = (end_scan - start_scan) * 1000  # em milissegundos

    return active_hosts, total_hosts, total_scan_time

# Função para capturar pacotes de rede e monitorar DNS e HTTP
def sniff_packets(active_hosts):
    log_entries = []
    sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sniffer_socket.bind(("0.0.0.0", 0))
    sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print("Iniciando captura de pacotes...")
    try:
        while True:
            raw_data, addr = sniffer_socket.recvfrom(65535)
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            src_ip = get_ip_from_bytes(iph[8])

            if src_ip not in active_hosts:
                continue  # Ignora pacotes de hosts que não estão na lista de ativos

            date_time = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

            # Verificar se é pacote HTTP
            if raw_data[23] == 6:  # Protocolo TCP
                tcp_header = raw_data[20:40]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                header_size = 20 + (tcph[4] >> 4) * 4
                data = raw_data[header_size:]

                if data.startswith(b'GET') or data.startswith(b'POST'):
                    try:
                        http_request = data.decode('utf-8')
                        lines = http_request.split('\r\n')
                        url = lines[0].split(' ')[1]
                        if not url.startswith("http"):
                            url = "http://" + src_ip + url
                        log_entries.append((date_time, src_ip, url))
                        print(f"Captured HTTP request: {src_ip} requested {url}")
                    except:
                        continue

            # Condição de parada para demonstração
            if len(log_entries) >= 10:
                break
    except KeyboardInterrupt:
        print("\nFinalizando captura.")
    finally:
        sniffer_socket.close()
        save_to_html(log_entries)

# Função para salvar as entradas de log no formato HTML
def save_to_html(log_entries):
    with open("historico.html", "w") as f:
        f.write("<html>\n<header>\n<title>Historico de Navegacao</title>\n</header>\n<body>\n<ul>\n")
        for entry in log_entries:
            date_time, ip, url = entry
            if url.startswith("https"):
                domain = urlparse(url).netloc
                f.write(f'<li>{date_time} - {ip} - <a href="{url}">{domain}</a></li>\n')
            else:
                f.write(f'<li>{date_time} - {ip} - <a href="{url}">{url}</a></li>\n')
        f.write("</ul>\n</body>\n</html>")

# Função para extrair o IP a partir dos bytes do cabeçalho IP
def get_ip_from_bytes(ip_bytes):
    return '.'.join(map(str, ip_bytes))

# Função principal
def main():
    # Exemplo de entrada de rede e máscara
    network_input = input("Digite a rede e máscara (ex.: 192.168.1.128/25): ")
    timeout = int(input("Digite o tempo limite de espera (em ms): "))

    # Converte a entrada em uma rede válida
    network = ipaddress.IPv4Network(network_input, strict=False)

    # Realiza a varredura e obtém a lista de hosts ativos
    active_hosts, total_hosts, total_scan_time = scan_network(network, timeout)

    # Exibe os resultados da varredura
    print(f"Número de máquinas ativas: {len(active_hosts)}")
    print(f"Número total de máquinas na rede: {total_hosts}")
    print(f"Tempo total de varredura: {total_scan_time:.2f} ms")

    # Executa o sniffer para monitorar os hosts ativos
    sniff_packets(active_hosts)

if __name__ == "__main__":
    main()
