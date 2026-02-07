import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from utils import logger

class EncryptionEngine:
    """
    Tüm şifreleme ve çözme mantığını yöneten sınıf.
    Güvenlik: AES (Fernet) + PBKDF2HMAC (SHA256) + Dynamic Salt
    """
    
    def __init__(self):
        pass

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Kullanıcı şifresinden ve verilen salt'tan güvenli bir anahtar türetir.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, plain_text: str, password: str) -> str:
        """
        Metni şifreler.
        Çıktı formatı: base64(salt + encrypted_data)
        """
        if not plain_text or not password:
            raise ValueError("Metin ve şifre boş olamaz.")

        try:
            # 1. Rastgele Salt Üret (16 byte)
            salt = os.urandom(16)
            
            # 2. Anahtarı Türet
            key = self._derive_key(password, salt)
            f = Fernet(key)
            
            # 3. Şifrele
            encrypted_data = f.encrypt(plain_text.encode())
            
            # 4. Salt'ı verinin başına ekle ve hepsini base64'e çevir
            # Final Paket: SALT (16 byte) + Şifreli Veri
            combined = salt + encrypted_data
            result_token = base64.urlsafe_b64encode(combined).decode('utf-8')
            
            logger.info("Şifreleme başarılı.")
            return result_token
            
        except Exception as e:
            logger.error(f"Şifreleme hatası: {e}")
            raise e

    def decrypt(self, token: str, password: str) -> str:
        """
        Şifreli metni (token) çözer.
        Token içinden önce salt okunur, sonra anahtar türetilir ve çözülür.
        """
        if not token or not password:
            raise ValueError("Şifreli veri ve şifre boş olamaz.")

        try:
            # 1. Base64'ten decode et
            decoded_data = base64.urlsafe_b64decode(token)
            
            # 2. Salt'ı ayıkla (İlk 16 byte)
            if len(decoded_data) < 16:
                raise ValueError("Veri formatı geçersiz (çok kısa).")
                
            salt = decoded_data[:16]
            encrypted_data = decoded_data[16:]
            
            # 3. Anahtarı Türet (Aynı salt ve password ile)
            key = self._derive_key(password, salt)
            f = Fernet(key)
            
            # 4. Çöz
            decrypted_text = f.decrypt(encrypted_data).decode('utf-8')
            
            logger.info("Şifre çözme başarılı.")
            return decrypted_text
            
        except Exception as e:
            logger.error(f"Şifre çözme hatası: {e}")
            raise ValueError("Şifre yanlış veya veri bozuk.")
