import socket
import threading
import requests
import json
import re

LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 18080
CARMA_URL = 'http://127.0.0.1:8080/'


def extract_content_length(headers: bytes) -> int:
    """Ищет Content-Length в сырых заголовках (аналог get_content_length на C)"""
    match = re.search(br'(?i)Content-Length:\s*(\d+)', headers)
    return int(match.group(1)) if match else 0


def process_mode_53(carma_json: dict, req_json: dict) -> dict:
    """Логика добавления штампа времени (Заглушка)"""
    print("=== Режим 53: Инъекция штампа времени ===")
    tsp_url = req_json.get("TSP_URL")
    alg_oid = req_json.get("TSP_HASH_ALG_OID")

    # 1. Достать подпись из carma_json['signInfo'][0]...
    # 2. Здесь будет вызов нативного Linux OpenSSL / КриптоПро для генерации TSP
    # 3. Модификация JSON ответа

    # Пока просто возвращаем JSON Кармы без изменений
    return carma_json


def process_mode_55(carma_json: dict, req_json: dict) -> dict:
    """Логика проверки штампа времени (Заглушка)"""
    print("=== Режим 55: Проверка штампа времени ===")
    # Аналогично: вытаскиваем sign_buffer55 из req_json, парсим CMS
    return carma_json


def handle_do_connection(conn):
    try:
        # 1. Читаем заголовки от DO до пустой строки
        header_data = b""
        while b"\n" not in header_data:  # Простая эвристика, в реале читаем до конца заголовка
            chunk = conn.recv(1)
            if not chunk: break
            header_data += chunk

        cl = extract_content_length(header_data)
        print(f"Получен заголовок, Content-Length: {cl}")

        # 2. Читаем тело запроса
        body_data = b""
        while len(body_data) < cl:
            chunk = conn.recv(min(4096, cl - len(body_data)))
            if not chunk: break
            body_data += chunk

        print(f"Получено тело запроса ({len(body_data)} байт)")

        # Определяем режим
        req_json = {}
        mode = 0
        try:
            req_json = json.loads(body_data.decode('utf-8'))
            mode = req_json.get("mode", 0)
        except json.JSONDecodeError:
            pass

        # 3. Отправляем запрос в Карму
        carma_headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept': 'application/json, text/javascript, */*; q=0.01'
        }
        carma_resp = requests.post(CARMA_URL, data=body_data, headers=carma_headers)

        # 4. Обрабатываем ответ
        response_json = carma_resp.json()

        if mode == 53:
            response_json = process_mode_53(response_json, req_json)
        elif mode == 55:
            response_json = process_mode_55(response_json, req_json)

        # 5. Формируем ответ для DO
        resp_body = json.dumps(response_json, separators=(',', ':')).encode('utf-8')
        resp_headers = f"HTTP/1.0 200 OK\r\nContent-Length: {len(resp_body)}\r\n\r\n".encode('utf-8')

        # Отправляем обратно в Wine
        conn.sendall(resp_headers + resp_body)
        print("Ответ отправлен клиенту.\n" + "-" * 40)

    except Exception as e:
        print(f"Ошибка обработки соединения: {e}")
    finally:
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(5)
    print(f"Linux Proxy слушает на {LISTEN_HOST}:{LISTEN_PORT}...")

    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_do_connection, args=(conn,), daemon=True)
        t.start()


if __name__ == '__main__':
    main()
