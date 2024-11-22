import socket
import struct
import time
import ipaddress
from threading import Thread

# Função para calcular checksum
def calculate_checksum(source_string):
    checksum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        checksum = checksum + this_val
        checksum = checksum & 0xFFFFFFFF
        count = count + 2

    if count_to < len(source_string):
        checksum = checksum + source_string[len(source_string) - 1]
        checksum = checksum & 0xFFFFFFFF

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = checksum + (checksum >> 16)
    answer = ~checksum
    answer = answer & 0xFFFF
    answer = answer >> 8 | (answer << 8 & 0xFF00)
    return answer

# Função para criar o pacote ICMP
def create_icmp_packet(id):
    # Cabeçalho ICMP (Tipo: 8, Código: 0, Checksum: 0, Identificador e Sequência)
    type = 8  # Echo Request
    code = 0
    checksum = 0
    seq = 1
    header = struct.pack('!BBHHH', type, code, checksum, id, seq)
    data = b'ping'
    # Calcula checksum
    checksum = calculate_checksum(header + data)
    # Atualiza o cabeçalho com o checksum correto
    header = struct.pack('!BBHHH', type, code, checksum, id, seq)
    return header + data

# Função para varredura de um IP
def scan_ip(ip, timeout, results):
    packet = create_icmp_packet(id=12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)  # Aumentar buffer de recepção
    try:
        send_time = time.time()
        sock.sendto(packet, (ip, 1))
        response, addr = sock.recvfrom(1024)
        recv_time = time.time()

        # Verifica se a resposta é ICMP reply
        icmp_header = response[20:28]
        icmp_type, _, _, recv_id, _ = struct.unpack('!BBHHH', icmp_header)
        if icmp_type == 0 and recv_id == 12345:  # Echo Reply
            rtt = round((recv_time - send_time) * 1000, 2)
            results.append((ip, rtt))
            print(f"Host ativo: {ip} com RTT: {rtt} ms")
    except socket.timeout:
        print(f"{ip} não respondeu no tempo limite.")
    except Exception as e:
        print(f"Erro ao escanear {ip}: {e}")
    finally:
        sock.close()

# Função principal
def icmp_scan(network, timeout_ms, use_threads=True):
    try:
        net = ipaddress.ip_network(network, strict=False)
        timeout_s = timeout_ms / 1000.0
        active_hosts = []
        total_hosts = len(list(net.hosts()))  # Exclui endereço de rede e broadcast

        print(f"Varredura iniciada para a rede {network}...")
        start_time = time.time()

        # Threads opcionais
        threads = []
        for ip in net.hosts():
            if use_threads:
                t = Thread(target=scan_ip, args=(str(ip), timeout_s, active_hosts))
                t.start()
                threads.append(t)
            else:
                scan_ip(str(ip), timeout_s, active_hosts)

        if use_threads:
            for t in threads:
                t.join()

        end_time = time.time()
        total_time = round((end_time - start_time), 2)

        # Resultados
        print("\nResultados da varredura:")
        print(f"Total de hosts ativos: {len(active_hosts)}")
        print(f"Total de hosts na rede: {total_hosts}")
        print(f"Tempo total da varredura: {total_time} segundos")
        print("Hosts ativos e tempos de resposta:")
        for host, rtt in active_hosts:
            print(f"- {host} : {rtt} ms")

    except PermissionError:
        print("Erro: Este script precisa ser executado com permissões de administrador (root).")
    except Exception as e:
        print(f"Erro: {e}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Uso: python raw_socket_scanner.py <rede/máscara> <timeout_ms>")
        print("Exemplo: python raw_socket_scanner.py 192.168.1.128/25 1000")
        sys.exit(1)

    network_arg = sys.argv[1]
    timeout_arg = int(sys.argv[2])

    icmp_scan(network_arg, timeout_arg, use_threads=True)
