import os
import sys
import threading
import joblib
import pandas as pd
import customtkinter as ctk
from scapy.all import sniff, IP, TCP, UDP

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CyberIDSApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Kali Linux AI-IDS (Gelişmiş Ağ Sensörü)")
        self.geometry("1000x700")
        self.is_monitoring = False
        self.packet_count_in_session = 0

        # 1. Yapay Zeka Modelini Yükleme (Script ile aynı klasörde olmalılar)
        MODEL_PATH = "cyber_rf_model.pkl"
        COLS_PATH = "model_columns.pkl"
        
        try:
            self.model = joblib.load(MODEL_PATH)
            self.model_columns = joblib.load(COLS_PATH)
            self.model_status = "AI Model: Aktif"
        except Exception as e:
            self.model_status = "AI Model: Hata!"
            self.model_error = str(e)

        # --- UI TASARIMI ---
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Üst Kontrol Paneli
        self.top_frame = ctk.CTkFrame(self, height=80)
        self.top_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=10, pady=5)
        
        self.ip_label = ctk.CTkLabel(self.top_frame, text="Ubuntu IP Adresi:")
        self.ip_label.pack(side="left", padx=15, pady=15)
        
        self.ip_entry = ctk.CTkEntry(self.top_frame, placeholder_text="Örn: 192.168.0.39", width=180)
        self.ip_entry.pack(side="left", padx=5, pady=15)

        self.start_btn = ctk.CTkButton(self.top_frame, text="🛡️ Trafiği Canlı İzle", fg_color="green", hover_color="darkgreen", command=self.start_monitoring)
        self.start_btn.pack(side="left", padx=15, pady=15)

        self.stop_btn = ctk.CTkButton(self.top_frame, text="🛑 Durdur", fg_color="red", hover_color="darkred", state="disabled", command=self.stop_monitoring)
        self.stop_btn.pack(side="left", padx=5, pady=15)

        self.status_lbl = ctk.CTkLabel(self.top_frame, text=self.model_status, text_color="cyan" if "Aktif" in self.model_status else "red")
        self.status_lbl.pack(side="right", padx=20, pady=15)

        # Linux Teşhis ve Sağlık Paneli
        self.health_frame = ctk.CTkFrame(self, height=40, fg_color="#1e2530")
        self.health_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=10, pady=2)
        
        self.health_lbl = ctk.CTkLabel(self.health_frame, text="[i] Linux sistem kontrolleri yapılıyor...", text_color="yellow")
        self.health_lbl.pack(side="left", padx=15, pady=5)

        # Dinamik Log Ekranı
        self.log_textbox = ctk.CTkTextbox(self, font=("Consolas", 12))
        self.log_textbox.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        
        # İlk Sistem Denetimlerini Çalıştır
        self.run_linux_checks()

    def run_linux_checks(self):
        """Program açılırken Kali Linux ağ yetkilerini ve dosyalarını denetler."""
        logs = []
        is_ok = True

        # 1. Root (Kök Kullanıcı) Yetki Kontrolü
        if os.getuid() != 0:
            logs.append("[🛑 KRİTİK HATA] Program 'sudo' (root) yetkisiyle başlatılmadı!")
            logs.append("-> Çözüm: Terminalde 'sudo python3 ids_linux_gui2.py' şeklinde çalıştırın.")
            self.health_lbl.configure(text="Hata: Root Yetkisi Eksik!", text_color="red")
            is_ok = False
        else:
            logs.append("[+ Check] Linux Root (Kök) yetkisi doğrulandı. Soket erişimi açık.")

        # 2. Ağ Kartı (eth0) Kontrolü
        if not os.path.exists("/sys/class/net/eth0"):
            logs.append("[⚠️ UYARI] Kali Linux üzerinde 'eth0' isimli varsayılan ağ kartı bulunamadı!")
            logs.append("-> Eğer Wi-Fi adaptör veya farklı bir sanal kart kullanıyorsanız koddaki 'eth0' alanını güncelleyin.")
            self.health_lbl.configure(text="Ağ Kartı Seçim Hatası!", text_color="orange")
            is_ok = False
        else:
            logs.append("[+ Check] 'eth0' ağ arayüzü aktif ve dinlemeye hazır.")

        # 3. Model Dosyası Kontrolü
        if hasattr(self, 'model_error'):
            logs.append(f"[🛑 MODEL DOSYA HATASI] Yapay zeka model dosyaları yüklenemedi: {self.model_error}")
            logs.append("-> Çözüm: 'cyber_rf_model.pkl' ve 'model_columns.pkl' dosyalarını bu scriptle aynı klasöre koyun.")
            is_ok = False

        if is_ok:
            self.health_lbl.configure(text="Linux Sensör Sağlığı: Kusursuz (Tetik Tetikte)", text_color="green")
            
        for log in logs:
            self.log_textbox.insert("end", log + "\n")

    def start_monitoring(self):
        self.target_ip = self.ip_entry.get().strip()
        if not self.target_ip:
            self.log_textbox.insert("end", "[!] HATA: Lütfen geçerli bir Ubuntu IP'si girin!\n")
            return

        self.is_monitoring = True
        self.packet_count_in_session = 0
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.ip_entry.configure(state="disabled")
        self.log_textbox.insert("end", f"\n[*] eth0 kartı üzerinden {self.target_ip} için canlı sniffer başlatıldı...\n")
        
        self.monitor_thread = threading.Thread(target=self.capture_traffic, daemon=True)
        self.monitor_thread.start()

        self.after(10000, self.check_linux_packet_flow)

    def check_linux_packet_flow(self):
        """Kali'de trafik üretildiği halde buraya hiç paket düşmüyorsa tetiklenir."""
        if self.is_monitoring and self.packet_count_in_session == 0:
            self.log_textbox.insert("end", "\n[⚠️ TRAFİK KÖRLÜĞÜ UYARISI]\n")
            self.log_textbox.insert("end", f"-> Ubuntu ile ağ bağlantınız açık ancak Kali ağ kartından şu an yapay zekaya paket akmıyor.\n")
            self.log_textbox.insert("end", f"-> Olası Neden: İki makinenin IP bloğu kaymış olabilir veya koddaki ağ kartı ismi ('eth0') Kali'deki aktif kartınızla uyuşmuyordur.\n")
            self.log_textbox.insert("end", "-> Öneri: Kali terminalinde 'ip a' yazarak internete çıkan kartın adını (Örn: eth0, wlan0) doğrulayın.\n\n")
            self.health_lbl.configure(text="Ağ Akış Körlüğü!", text_color="orange")

    def stop_monitoring(self):
        self.is_monitoring = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.ip_entry.configure(state="normal")
        self.log_textbox.insert("end", "[*] Canlı izleme durduruldu.\n")
        self.health_lbl.configure(text="Linux Sensör Sağlığı: Kusursuz (Tetik Tetikte)", text_color="green")

    def port_kategorize(self, port):
        if port == 0: return 0
        elif port in [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389]: return 1
        elif port < 1024: return 2
        elif port < 49152: return 3
        else: return 4

    def boyut_kategorisi(self, boyut):
        if boyut <= 64: return 0
        elif boyut <= 128: return 1
        elif boyut <= 512: return 2
        elif boyut <= 1024: return 3
        else: return 4

    def capture_traffic(self):
        def paket_analiz_et(packet):
            if not self.is_monitoring:
                return
                
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                
                self.packet_count_in_session += 1
                
                if ip_layer.src == self.target_ip or ip_layer.dst == self.target_ip:
                    proto = ip_layer.proto
                    size = len(packet)
                    src_port, dst_port, flags = 0, 0, 0
                    
                    if proto == 6 and packet.haslayer(TCP):
                        tcp_layer = packet[TCP]
                        src_port = tcp_layer.sport
                        dst_port = tcp_layer.dport
                        flags = int(tcp_layer.flags)
                    elif proto == 17 and packet.haslayer(UDP):
                        udp_layer = packet[UDP]
                        src_port = udp_layer.sport
                        dst_port = udp_layer.dport

                    if proto not in [6, 17]:
                        return

                    packet_size_cat = self.boyut_kategorisi(size)
                    src_port_cat = self.port_kategorize(src_port)
                    dst_port_cat = self.port_kategorize(dst_port)
                    
                    current_data = {
                        'ip.proto': int(proto), 
                        'tcp.flags': int(flags),
                        'src_port_category': int(src_port_cat), 
                        'dst_port_category': int(dst_port_cat),
                        'packet_size_category': int(packet_size_cat)
                    }
                    
                    df_current = pd.DataFrame([current_data])
                    df_encoded = pd.get_dummies(df_current)
                    df_final = df_encoded.reindex(columns=self.model_columns, fill_value=0)
                    
                    prediction = self.model.predict(df_final)[0]
                    
                    # Eğer paket meşru bir ACK veya PUSH-ACK aşamasıysa (16 veya 24), kesinlikle MEŞRU yap.
                    if flags in [16, 24]:
                        prediction = 0
                        
                    # Eğer paket bir flood/tarama bayrağı içeriyorsa ve çok hızlı geliyorsa kesinlikle SALDIRI yap.
                    elif flags in [41, 0] or (flags == 2 and packet_size_cat == 0):
                        prediction = 1
                    
                    if flags == 2 and packet_size_cat == 0 and proto == 6:
                    	prediction = 1
                    
                    proto_name = "TCP" if proto == 6 else "UDP"
                    if prediction == 1:
                        log_msg = f"[🚨 ALARM] {proto_name} | {ip_layer.src}:{src_port} -> {ip_layer.dst}:{dst_port} | SALDIRI TESPİT EDİLDİ!\n"
                        self.append_log(log_msg)
                    else:
                        log_msg = f"[🟢 MEŞRU] {proto_name} | {ip_layer.src}:{src_port} -> {ip_layer.dst}:{dst_port} | Trafik Olağan.\n"
                        self.append_log(log_msg)

        # try-except bloğu ve sniff komutu tamamen capture_traffic fonksiyonunun içindedir (Aynı girinti seviyesinde)
        try:
            filtre_cumlesi = f"host {self.target_ip}"
            sniff(filter=filtre_cumlesi, prn=paket_analiz_et, store=0, iface="eth0", stop_filter=lambda p: not self.is_monitoring)
        except Exception as e:
            self.log_textbox.insert("end", f"\n[🛑 SNIFF MOTORU ÇÖKTÜ] Hata Detayı: {str(e)}\n")

    def append_log(self, text):
        self.log_textbox.insert("end", text)
        self.log_textbox.see("end")

if __name__ == "__main__":
    app = CyberIDSApp()
    app.mainloop()
