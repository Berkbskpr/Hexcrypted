import customtkinter as ctk
import tkinter as tk
from crypto_manager import EncryptionEngine
from utils import logger, get_icon_path
import ctypes

class HexcryptedGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # --- Motoru Yükle ---
        self.engine = EncryptionEngine()

        # --- Pencere Ayarları ---
        self.setup_window()
        
        # --- Arayüz Bileşenleri ---
        self.create_layouts()

    def setup_window(self):
        """Pencere ve tema ayarları"""
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("green")
        
        self.title("HEXCRYPTED v2.0")
        self.geometry("750x650")
        self.resizable(False, False)
        self.configure(fg_color="#1a1a1a")

        # İkon
        icon = get_icon_path()
        if icon:
            try:
                self.iconbitmap(icon)
                # Taskbar ID
                app_id = 'antigravity.hexcrypted.encoder.2.0'
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
            except Exception as e:
                logger.warning(f"GUI İkon hatası: {e}")

    def create_layouts(self):
        """Ana düzeni oluşturur"""
        
        # 1. Header (Logo)
        header = ctk.CTkFrame(self, corner_radius=0, fg_color="#111111", height=80)
        header.pack(fill="x")
        
        logo = ctk.CTkLabel(header, text="⬢ HEXCRYPTED", font=("Roboto", 28, "bold"), text_color="#00FF41")
        logo.place(relx=0.5, rely=0.5, anchor="center")
        
        # Bildirim Çubuğu (Status Bar) - Header'ın altında
        self.status_label = ctk.CTkLabel(self, text="", font=("Roboto", 12), text_color="#aaaaaa", height=20)
        self.status_label.pack(pady=(5, 0))

        # 2. Tabview (Sekmeli Yapı) - ENCRYPT / DECRYPT
        self.tab_view = ctk.CTkTabview(self, width=700, height=500, corner_radius=10, fg_color="#2b2b2b")
        self.tab_view.pack(pady=20, padx=20, expand=True, fill="both")

        self.tab_view.add("ŞİFRELE (ENCRYPT)")
        self.tab_view.add("ÇÖZ (DECRYPT)")

        # Sekme içlerini doldur
        self.setup_encrypt_tab(self.tab_view.tab("ŞİFRELE (ENCRYPT)"))
        self.setup_decrypt_tab(self.tab_view.tab("ÇÖZ (DECRYPT)"))

    def setup_encrypt_tab(self, parent):
        """Şifreleme sekmesi içeriği"""
        # Girdi
        ctk.CTkLabel(parent, text="GİRİLECEK METİN", font=("Roboto", 12, "bold")).pack(anchor="w", pady=(10, 5))
        e_input = ctk.CTkTextbox(parent, height=120, font=("Consolas", 12))
        e_input.pack(fill="x", pady=5)

        # Şifre
        ctk.CTkLabel(parent, text="GÜVENLİK ANAHTARI", font=("Roboto", 12, "bold")).pack(anchor="w", pady=(15, 5))
        e_pass = ctk.CTkEntry(parent, show="•", placeholder_text="Güçlü bir şifre girin...")
        e_pass.pack(fill="x", pady=5)

        # Buton
        btn = ctk.CTkButton(parent, text="ŞİFRELE VE KOPYALA", 
                            font=("Roboto", 14, "bold"), 
                            fg_color="#006400", hover_color="#008000", height=40,
                            command=lambda: self.perform_encryption(e_input, e_pass, e_output))
        btn.pack(pady=20, fill="x")

        # Çıktı
        ctk.CTkLabel(parent, text="SONUÇ (ŞİFRELİ)", font=("Roboto", 12, "bold")).pack(anchor="w", pady=(10, 5))
        e_output = ctk.CTkTextbox(parent, height=80, font=("Consolas", 12), text_color="#00FF41", state="disabled")
        e_output.pack(fill="x", pady=5)


    def setup_decrypt_tab(self, parent):
        """Çözme sekmesi içeriği"""
        # Girdi
        ctk.CTkLabel(parent, text="ŞİFRELİ METİN (HEXCRYPTED TEXT)", font=("Roboto", 12, "bold")).pack(anchor="w", pady=(10, 5))
        d_input = ctk.CTkTextbox(parent, height=120, font=("Consolas", 12))
        d_input.pack(fill="x", pady=5)

        # Şifre
        ctk.CTkLabel(parent, text="GÜVENLİK ANAHTARI", font=("Roboto", 12, "bold")).pack(anchor="w", pady=(15, 5))
        d_pass = ctk.CTkEntry(parent, show="•", placeholder_text="Şifreleme anahtarı...")
        d_pass.pack(fill="x", pady=5)

        # Buton
        btn = ctk.CTkButton(parent, text="ÇÖZ VE GÖSTER", 
                            font=("Roboto", 14, "bold"), 
                            fg_color="#003366", hover_color="#004080", height=40,
                            command=lambda: self.perform_decryption(d_input, d_pass, d_output))
        btn.pack(pady=20, fill="x")

        # Çıktı
        ctk.CTkLabel(parent, text="ORİJİNAL METİN", font=("Roboto", 12, "bold")).pack(anchor="w", pady=(10, 5))
        d_output = ctk.CTkTextbox(parent, height=80, font=("Consolas", 12), text_color="white", state="disabled")
        d_output.pack(fill="x", pady=5)

    # --- İş Mantığı Bağlantıları ---

    def perform_encryption(self, widget_in, widget_pass, widget_out):
        text = widget_in.get("1.0", "end-1c").strip()
        pwd = widget_pass.get()

        if not text or not pwd:
            self.show_message("⚠ Lütfen metin ve şifre girin.", error=True)
            return

        try:
            result = self.engine.encrypt(text, pwd)
            self.update_output(widget_out, result)
            
            # Otomatik Kopyala
            self.clipboard_clear()
            self.clipboard_append(result)
            self.show_message("✓ Şifrelendi ve Panoya Kopyalandı!")
            
        except Exception as e:
            self.show_message(f"⚠ Hata: {str(e)}", error=True)

    def perform_decryption(self, widget_in, widget_pass, widget_out):
        token = widget_in.get("1.0", "end-1c").strip()
        pwd = widget_pass.get()

        if not token or not pwd:
            self.show_message("⚠ Şifreli metin ve anahtar gerekli.", error=True)
            return

        try:
            result = self.engine.decrypt(token, pwd)
            self.update_output(widget_out, result)
            self.show_message("✓ Başarıyla Çözüldü!")
            
        except Exception as e:
            self.show_message("⚠ Şifre yanlış veya veri bozuk!", error=True)

    def update_output(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def show_message(self, msg, error=False):
        color = "#FF4444" if error else "#00FF41"
        self.status_label.configure(text=msg, text_color=color)
        # 3 saniye sonra temizle
        self.after(4000, lambda: self.status_label.configure(text=""))

if __name__ == "__main__":
    app = HexcryptedGUI()
    app.mainloop()
