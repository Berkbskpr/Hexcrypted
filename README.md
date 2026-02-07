# Basit Şifreleyici (Simple Encryptor)

Bu proje, Python ve Tkinter kullanılarak geliştirilmiş, metinleri şifrelemek ve şifresini çözmek için kullanılan basit bir masaüstü uygulamasıdır. Kleopatra/PGP mantığına benzer şekilde çalışır.

## Özellikler
- **Metin Şifreleme:** Girdiğiniz metni belirlediğiniz bir şifre (anahtar) ile şifreler.
- **Şifre Çözme:** Şifrelenmiş metni, doğru şifreyi girerek orijinal haline döndürür.
- **Güvenli:** `Fernet` (Simetrik şifreleme - AES) kullanır.
- **Taşınabilir:** Tek bir `.exe` dosyası olarak çalışabilir, kurulum gerektirmez.

## Kurulum ve Çalıştırma (Geliştiriciler İçin)

Eğer kaynak kodunu çalıştırmak veya geliştirmek isterseniz:

1. Python'u yükleyin.
2. Gerekli kütüphaneleri yükleyin:
   ```bash
   pip install -r requirements.txt
   ```
3. Uygulamayı başlatın:
   ```bash
   python encryption_gui.py
   ```

## EXE Oluşturma
Uygulamayı tek bir çalıştırılabilir dosya (.exe) haline getirmek için:

```bash
pyinstaller --onefile --windowed --name "Sifreleyici" encryption_gui.py
```
Oluşan dosya `dist` klasöründe yer alır.

## Nasıl Kullanılır?
1. Uygulamayı açın.
2. Metni ve şifrenizi girin.
3. **Şifrele** veya **Çöz** butonuna basın.
4. Sonucu kopyalayıp kullanın.
