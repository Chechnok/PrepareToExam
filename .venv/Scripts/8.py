import ssl
import socket
import hashlib


def get_certificate_hash(hostname, port=443):
    try:
        # Налаштування безпечного контексту SSL
        context = ssl.create_default_context()

        # Встановлення зв'язку через сокет
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Отримання SSL-сертифіката у бінарному вигляді
                cert_bin = ssock.getpeercert(binary_form=True)

                # Отримання хешу SHA-256 для сертифіката
                cert_hash = hashlib.sha256(cert_bin).hexdigest()

                # Вивід результатів
                print(f"Connected to: {hostname}:{port}")
                print(f"Certificate SHA-256 Hash: {cert_hash}")
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    # Домен, до якого ми підключаємось
    hostname = input("Enter the hostname (e.g., www.google.com): ").strip()
    get_certificate_hash(hostname)
