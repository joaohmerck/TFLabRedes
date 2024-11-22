import os
import socket
import threading
from queue import Queue
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

def registrar_historico(caminho_arquivo, ip_detectado):
    """Salva o IP identificado em um arquivo de log."""
    with open(caminho_arquivo, "a") as log:
        registro = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{registro} - IP ativo detectado: {ip_detectado}\n")
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

def iniciar_varredura():
    """Inicia o processo de varredura na sub-rede."""
    ip_local = obter_ip_local()
    if not ip_local:
        print("[!] Não foi possível identificar o IP local.")
        return

    print(f"[+] IP Local detectado: {ip_local}")

    hosts_identificados = []
    arquivo_historico = "log_ips.txt"

    # Cria ou limpa o arquivo de log antes de iniciar
    with open(arquivo_historico, "w") as log:
        log.write("Log de dispositivos ativos na rede\n")
        log.write(f"Início da varredura: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    escanear_dispositivos(ip_local, hosts_identificados, arquivo_historico)

    print(f"[*] Log salvo em: {arquivo_historico}")
    if hosts_identificados:
        print("[*] Dispositivos ativos:")
        for host in hosts_identificados:
            print(f"- {host}")
    else:
        print("[!] Nenhum dispositivo ativo encontrado.")

if __name__ == "__main__":
    iniciar_varredura()
