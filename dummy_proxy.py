import socket


def start_dummy_proxy(port=18081):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(1)
        print(f"[*] Dummy Proxy слушает на порту {port}...")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[*] Подключился мост: {addr}")
                data = conn.recv(1024)
                if data:
                    print(f"[*] Получено от моста:\n{data.decode(errors='replace')}")
                    response = b"HTTP/1.0 200 OK\r\nContent-Length: 15\r\n\r\n{'status':'ok'}"
                    conn.sendall(response)
                    print("[*] Ответ отправлен.")


if __name__ == "__main__":
    start_dummy_proxy()
