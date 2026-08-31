#!/usr/bin/env python3

import sys
import subprocess
import importlib

# --- INSTALACIÓN AUTOMÁTICA DE LIBRERÍAS ---
def instalar_e_importar(paquete_pip, modulo_nombre=None):
    if modulo_nombre is None:
        modulo_nombre = paquete_pip
    try:
        return importlib.import_module(modulo_nombre)
    except ImportError:
        print(f"[*] Instalando '{paquete_pip}' automáticamente...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", paquete_pip])
        except subprocess.CalledProcessError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", paquete_pip, "--break-system-packages"])
        return importlib.import_module(modulo_nombre)

# Cargar dependencias
spellchecker = instalar_e_importar("pyspellchecker", "spellchecker")
scapy_all = instalar_e_importar("scapy")

from spellchecker import SpellChecker
from scapy.all import sniff, ICMP, Raw, rdpcap
import re

spell = SpellChecker(language='es')
mensaje_capturado = []

VERDE = "\033[92m"
RESET = "\033[0m"


def capturar_paquete(packet):
    """Extrae el carácter inyectado al inicio del payload ICMP."""
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        if packet.haslayer(Raw):
            try:
                payload_bytes = packet[Raw].load
                
                if len(payload_bytes) > 0:
                    # El carácter está en la posición 0
                    caracter = payload_bytes[0:1].decode("utf-8", errors="ignore")
                    
                    # Evitamos guardar caracteres de control no imprimibles
                    if caracter and caracter.isprintable():
                        mensaje_capturado.append(caracter)
                        print(f"[+] Carácter capturado: {repr(caracter)}")
            except Exception:
                pass

def descifrar_cesar(texto, corrimiento):
    resultado = ""
    for caracter in texto:
        if 'A' <= caracter <= 'Z':
            resultado += chr((ord(caracter) - ord('A') - corrimiento) % 26 + ord('A'))
        elif 'a' <= caracter <= 'z':
            resultado += chr((ord(caracter) - ord('a') - corrimiento) % 26 + ord('a'))
        else:
            resultado += caracter
    return resultado


def es_mensaje_valido(texto):
    palabras = re.findall(r'\b[a-zA-ZáéíóúÁÉÍÓÚñÑ]+\b', texto.lower())
    if not palabras:
        return False

    desconocidas = spell.unknown(palabras)
    reconocidas = len(palabras) - len(desconocidas)
    return (reconocidas / len(palabras)) > 0.5


def main():
    print("[*] Iniciando procesamiento de tráfico ICMP...")
    
    if len(sys.argv) > 1:
        archivo_pcap = sys.argv[1]
        print(f"[*] Modo offline: Leyendo desde archivo {archivo_pcap}...")
        try:
            paquetes = rdpcap(archivo_pcap)
            for packet in paquetes:
                capturar_paquete(packet)
        except Exception as e:
            print(f"[-] Error al leer el archivo pcap: {e}")
            sys.exit(1)
    else:
        print("[*] Modo en vivo: Capturando paquetes en la interfaz de red...")
        print("[*] Presiona Ctrl+C al finalizar la captura.\n")
        try:
            # Filtro Berkeley Packet Filter (BPF) para capturar únicamente Echo Request
            sniff(filter="icmp and icmp[icmptype] == 8", prn=capturar_paquete)
        except KeyboardInterrupt:
            print("\n[*] Captura finalizada.")

    mensaje_cifrado = "".join(mensaje_capturado)
    
    if not mensaje_cifrado:
        print("[-] No se capturaron caracteres válidos en los paquetes ICMP.")
        return

    print(f"\n[*] Mensaje completo capturado: '{mensaje_cifrado}'")
    print("\n[*] Probando las 26 rotaciones del Cifrado César:\n")

    for corrimiento in range(26):
        texto_desplazado = descifrar_cesar(mensaje_cifrado, corrimiento)
        if es_mensaje_valido(texto_desplazado):
            print(f"{VERDE}Corrimiento {corrimiento:2d}: {texto_desplazado}{RESET}")
        else:
            print(f"Corrimiento {corrimiento:2d}: {texto_desplazado}")


if __name__ == "__main__":
    main()
