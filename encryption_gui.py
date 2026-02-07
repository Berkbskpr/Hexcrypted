import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Basit Şifreleyici")
        self.root.geometry("600x500")
        self.root.configure(bg="#f0f0f0")

        # Başlık
        title_label = tk.Label(root, text="Metin Şifreleme & Çözme", font=("Helvetica", 16, "bold"), bg="#f0f0f0")
        title_label.pack(pady=10)

        # Metin Giriş Alanı
        input_label = tk.Label(root, text="Metninizi buraya girin:", font=("Helvetica", 10), bg="#f0f0f0")
        input_label.pack(anchor="w", padx=20)
        
        self.text_input = tk.Text(root, height=8, width=70)
        self.text_input.pack(padx=20, pady=5)

        # Şifre Alanı
        password_frame = tk.Frame(root, bg="#f0f0f0")
        password_frame.pack(pady=10)
        
        pass_label = tk.Label(password_frame, text="Anahtar (Şifre):", font=("Helvetica", 10), bg="#f0f0f0")
        pass_label.pack(side=tk.LEFT, padx=5)
        
        self.password_entry = tk.Entry(password_frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5)

        # Butonlar
        btn_frame = tk.Frame(root, bg="#f0f0f0")
        btn_frame.pack(pady=10)

        encrypt_btn = tk.Button(btn_frame, text="Şifrele", command=self.encrypt_text, bg="#4CAF50", fg="white", font=("Helvetica", 10, "bold"), width=15)
        encrypt_btn.pack(side=tk.LEFT, padx=10)

        decrypt_btn = tk.Button(btn_frame, text="Çöz", command=self.decrypt_text, bg="#2196F3", fg="white", font=("Helvetica", 10, "bold"), width=15)
        decrypt_btn.pack(side=tk.LEFT, padx=10)

        # Sonuç Alanı
        output_label = tk.Label(root, text="Sonuç:", font=("Helvetica", 10), bg="#f0f0f0")
        output_label.pack(anchor="w", padx=20)
        
        self.text_output = tk.Text(root, height=8, width=70)
        self.text_output.pack(padx=20, pady=5)

        # Kopyala Butonu
        copy_btn = tk.Button(root, text="Sonucu Kopyala", command=self.copy_result, bg="#FF9800", fg="white", font=("Helvetica", 9), width=15)
        copy_btn.pack(pady=5)

    def get_key_from_password(self, password):
        # Şifreden güvenli bir anahtar (key) türetme
        salt = b'sabit_tuz_degeri_basitlik_icin' # Normalde her seferinde rastgele olmalı ama basitlik için sabitledik
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_text(self):
        text = self.text_input.get("1.0", tk.END).strip()
        password = self.password_entry.get()

        if not text:
            messagebox.showerror("Hata", "Lütfen şifrelenecek bir metin girin.")
            return
        if not password:
            messagebox.showerror("Hata", "Lütfen bir şifre (anahtar) belirleyin.")
            return

        try:
            key = self.get_key_from_password(password)
            f = Fernet(key)
            encrypted_text = f.encrypt(text.encode())
            
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", encrypted_text.decode())
        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme hatası: {str(e)}")

    def decrypt_text(self):
        encrypted_text = self.text_input.get("1.0", tk.END).strip()
        password = self.password_entry.get()

        if not encrypted_text:
            messagebox.showerror("Hata", "Lütfen çözülecek şifreli metni girin.")
            return
        if not password:
            messagebox.showerror("Hata", "Lütfen şifreyi (anahtarı) girin.")
            return

        try:
            key = self.get_key_from_password(password)
            f = Fernet(key)
            decrypted_text = f.decrypt(encrypted_text.encode())
            
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", decrypted_text.decode())
        except Exception as e:
            messagebox.showerror("Hata", "Şifre çözülemedi. Yanlış şifre veya bozuk veri.")

    def copy_result(self):
        result = self.text_output.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Bilgi", "Sonuç panoya kopyalandı!")
        else:
            messagebox.showwarning("Uyarı", "Kopyalanacak bir sonuç yok.")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
