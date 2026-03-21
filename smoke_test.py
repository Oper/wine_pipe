import socket
import json


def run_smoke_test(host='127.0.0.1', port=18081):
    print(f"[*] Отправка тестового запроса на {host}:{port}...")

    test_json = {
        "mode": 1,
        "streamId": 777,
        "data": "Hello from Smoke Test"
    }
    body = json.dumps(test_json).encode('utf-8')
    header = f"POST / HTTP/1.0\r\nContent-Length: {len(body)}\r\n\r\n".encode('utf-8')

    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(header + body)
            response = s.recv(1024 * 1024)
            print("[+] Получен ответ:")
            print(response.decode('utf-8', errors='replace'))
    except Exception as e:
        print(f"[!] Тест провален: {e}")


if __name__ == "__main__":
    run_smoke_test()
