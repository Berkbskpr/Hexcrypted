import customtkinter as ctk
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import sys
import tempfile
from PIL import Image, ImageTk
import ctypes

# Tema ayarları
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

# AppUserModelID Ayarı (Görev çubuğu ikonu için kritik)
myappid = 'antigravity.hexcrypted.encoder.1.0' 
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except Exception:
    pass

# İkon Base64 Verisi (Multi-size, Neon Yeşil Altıgen)
# Bu veri güncellenmiş create_icon.py betiğinden alındı.
ICON_BASE64 = """
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
"""

def get_icon_path():
    try:
        if hasattr(sys, '_MEIPASS'):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
            
        icon_path = os.path.join(tempfile.gettempdir(), "hexcrypted_v2.ico")
        
        # Her çalıştığında yaz, belki ikon güncellenmiştir.
        with open(icon_path, "wb") as f:
            f.write(base64.b64decode(ICON_BASE64))
        return icon_path
    except Exception as e:
        print(f"İkon yüklenemedi: {e}")
        return None

class HexcryptedApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # İkon Ayarı
        self.icon_path = get_icon_path()
        if self.icon_path:
            try:
                # Pencere ikonu (Title bar ve Taskbar)
                self.iconbitmap(self.icon_path)
                
                # Ekstra güvenlik: wm_iconbitmap
                self.after(200, lambda: self.iconbitmap(self.icon_path))
            except Exception as e:
                print(f"İkon atama hatası: {e}")

        # Pencere Ayarları
        self.title("HEXCRYPTED")
        self.geometry("700x600")
        self.resizable(False, False)

        # Arkaplan
        self.configure(fg_color="#1a1a1a") # Koyu antrasit

        # Grid Ayarı (1x2)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0) # Başlık
        self.grid_rowconfigure(1, weight=1) # İçerik

        # --- HEADER ---
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="#111111", height=80)
        self.header_frame.grid(row=0, column=0, sticky="ew")
        
        # Logo ve İsim
        # Logo olarak da Unicode yerine küçük bir image icon koyabiliriz ama şimdilik metin kalsın, kullanıcı onu sevmişti.
        self.logo_label = ctk.CTkLabel(self.header_frame, text="⬢ HEXCRYPTED", font=("Roboto", 28, "bold"), text_color="#00FF41")
        self.logo_label.place(relx=0.5, rely=0.5, anchor="center")

        # --- CONTENT ---
        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#2b2b2b")
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Giriş Metni
        self.input_label = ctk.CTkLabel(self.content_frame, text="GİRİŞ METNİ", font=("Roboto", 12, "bold"), text_color="#aaaaaa")
        self.input_label.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 5))
        
        self.text_input = ctk.CTkTextbox(self.content_frame, height=100, corner_radius=10, fg_color="#1a1a1a", text_color="white", font=("Consolas", 12))
        self.text_input.grid(row=1, column=0, sticky="ew", padx=20, pady=5)

        # Şifre Alanı
        self.key_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.key_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=15)
        
        self.key_label = ctk.CTkLabel(self.key_frame, text="GÜVENLİK ANAHTARI (ŞİFRE)", font=("Roboto", 12, "bold"), text_color="#aaaaaa")
        self.key_label.pack(side="left", padx=(0, 10))
        
        self.password_entry = ctk.CTkEntry(self.key_frame, show="•", width=250, placeholder_text="Anahtar giriniz...", corner_radius=10, fg_color="#1a1a1a", text_color="white")
        self.password_entry.pack(side="left", fill="x", expand=True)

        # Butonlar
        self.btn_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.btn_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=10)
        self.btn_frame.grid_columnconfigure((0, 1), weight=1)

        self.encrypt_btn = ctk.CTkButton(self.btn_frame, text="ŞİFRELE (ENCRYPT)", command=self.encrypt_text, height=40, corner_radius=20, font=("Roboto", 14, "bold"), fg_color="#006400", hover_color="#008000")
        self.encrypt_btn.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        self.decrypt_btn = ctk.CTkButton(self.btn_frame, text="ÇÖZ (DECRYPT)", command=self.decrypt_text, height=40, corner_radius=20, font=("Roboto", 14, "bold"), fg_color="#003366", hover_color="#004080")
        self.decrypt_btn.grid(row=0, column=1, padx=(10, 0), sticky="ew")

        # Çıktı Metni
        self.output_label = ctk.CTkLabel(self.content_frame, text="SONUÇ", font=("Roboto", 12, "bold"), text_color="#aaaaaa")
        self.output_label.grid(row=4, column=0, sticky="w", padx=20, pady=(20, 5))
        
        self.text_output = ctk.CTkTextbox(self.content_frame, height=100, corner_radius=10, fg_color="#1a1a1a", text_color="#00FF41", font=("Consolas", 12))
        self.text_output.grid(row=5, column=0, sticky="ew", padx=20, pady=5)
        self.text_output.configure(state="disabled")

        # Kopyala Butonu
        self.copy_btn = ctk.CTkButton(self.content_frame, text="SONUCU KOPYALA", command=self.copy_result, height=30, corner_radius=15, font=("Roboto", 10, "bold"), fg_color="#444444", hover_color="#555555")
        self.copy_btn.grid(row=6, column=0, pady=15)

    def get_key_from_password(self, password):
        salt = b'sabit_tuz_degeri_basitlik_icin' 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_text(self):
        text = self.text_input.get("1.0", "end-1c").strip()
        password = self.password_entry.get()

        if not text:
            self.show_error("Lütfen metin girin.")
            return
        if not password:
            self.show_error("Anahtar giriniz.")
            return

        try:
            key = self.get_key_from_password(password)
            f = Fernet(key)
            encrypted_text = f.encrypt(text.encode())
            
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", encrypted_text.decode())
            self.text_output.configure(state="disabled")
            self.show_success("Şifrelendi!")
        except Exception as e:
            self.show_error(f"Hata: {str(e)}")

    def decrypt_text(self):
        encrypted_text = self.text_input.get("1.0", "end-1c").strip()
        password = self.password_entry.get()

        if not encrypted_text:
            self.show_error("Şifreli metni girin.")
            return
        if not password:
            self.show_error("Anahtar giriniz.")
            return

        try:
            key = self.get_key_from_password(password)
            f = Fernet(key)
            decrypted_text = f.decrypt(encrypted_text.encode())
            
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", decrypted_text.decode())
            self.text_output.configure(state="disabled")
            self.show_success("Çözüldü!")
        except Exception as e:
            self.show_error("Şifre Yanlış veya Veri Bozuk")

    def copy_result(self):
        result = self.text_output.get("1.0", "end-1c").strip()
        if result:
            self.clipboard_clear()
            self.clipboard_append(result)
            self.show_success("Kopyalandı!")
        else:
            self.show_error("Kopyalanacak veri yok.")

    def show_error(self, message):
        self.logo_label.configure(text=f"⚠ {message}", text_color="#FF4444")
        self.after(3000, lambda: self.logo_label.configure(text="⬢ HEXCRYPTED", text_color="#00FF41"))

    def show_success(self, message):
        self.logo_label.configure(text=f"✓ {message}", text_color="#00FF41")
        self.after(3000, lambda: self.logo_label.configure(text="⬢ HEXCRYPTED", text_color="#00FF41"))

if __name__ == "__main__":
    app = HexcryptedApp()
    app.mainloop()
