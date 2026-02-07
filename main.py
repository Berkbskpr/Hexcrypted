import sys
from gui_manager import HexcryptedGUI
from utils import logger
import traceback

def main():
    try:
        logger.info("Uygulama başlatılıyor...")
        app = HexcryptedGUI()
        app.mainloop()
        logger.info("Uygulama kapatıldı.")
    except Exception as e:
        logger.critical(f"Kritik Hata: {e}")
        logger.critical(traceback.format_exc())
        input("Uygulama kritik bir hata nedeniyle durdu. Log dosyasını kontrol edin. Çıkmak için Enter'a basın.")

if __name__ == "__main__":
    main()
