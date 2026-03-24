import argparse
import socket
import win32pipe
import win32file
import pywintypes
import time
import logging
import json
import re
import base64
import copy
from datetime import datetime

# --- НАСТРОЙКА ЛОГИРОВАНИЯ ---
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('wine_bridge_debug.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def generate_eid_stub() -> str:
    now = datetime.now()
    time_str = now.strftime("%d.%m.%Y %H:%M:%S")
    eid_raw = f'version="V1";UtcTime="{time_str}";LocalTime="{time_str}";GenTime="{time_str}";SerialNumber="001234567890";Policy="1.2.643.2.2.34.6";HashAlg="ГОСТ Р 34.11-2012 256 бит";HashValue="IMITATION_HASH_VALUE";Accuracy="";Ordering="Выкл.";Nonce="";Tsa="";'
    return base64.b64encode(eid_raw.encode('utf-16le')).decode('utf-8')

def translate_request(req_body: bytes) -> bytes:
    try:
        payload = json.loads(req_body.decode('utf-8'))
        mode = payload.get("mode")
        if mode == 53:
            payload["mode"] = 27 
            tsp_params = "TSP_CHECK_CERT=0;"
            if payload.get("TSP_URL"): tsp_params += f"TSP_URL={payload['TSP_URL']};"
            ext = payload.get("extInitParams", "")
            payload["extInitParams"] = (ext + (';' if ext and not ext.endswith(';') else '') + tsp_params)
        elif mode == 55:
            payload["mode"] = 29
        return json.dumps(payload, separators=(',', ':')).encode('utf-8')
    except: return req_body

def translate_response(resp_body: bytes, original_mode: int) -> bytes:
    if original_mode not in (53, 55): return resp_body
    try:
        payload = json.loads(resp_body.decode('utf-8'))
        if "signInfo" in payload:
            for info in payload["signInfo"]:
                info["Extensions"] = [{"ExtensionName": "Штамп времени", "ExtensionOID": "1.2.840.113549.1.9.16.2.14", "ExtensionInterpretedString": "Результат проверки подписи: Действительна; Результат проверки сертификата: Действителен;", "ExtensionInterpretedData": generate_eid_stub()}]
                info["CoSigners"] = []
        return json.dumps(payload, separators=(',', ':')).encode('utf-8')
    except: return resp_body

def process_http_message(data: bytes, is_request: bool = True, original_mode: int = 0) -> tuple[bytes, int]:
    header_end = data.find(b'\r\n\r\n')
    if header_end == -1: return data, 0 
    
    headers_raw, body = data[:header_end], data[header_end + 4:]
    current_mode = original_mode
    
    if is_request:
        try: current_mode = json.loads(body.decode('utf-8')).get("mode", 0)
        except: pass
        new_body = translate_request(body)
    else:
        new_body = translate_response(body, original_mode)

    headers_str = headers_raw.decode('utf-8', errors='ignore')
    new_headers_str = re.sub(r'(?i)Content-Length:\s*\d+', f'Content-Length: {len(new_body)}', headers_str)
    return new_headers_str.encode('utf-8') + b'\r\n\r\n' + new_body, current_mode

def read_full_data(pipe) -> bytes:
    data = b""
    # 1. Первичное чтение. Ждем появления хоть каких-то данных.
    try:
        # Даем Wine небольшую паузу перед чтением, чтобы буфер наполнился
        time.sleep(0.05) 
        hr, chunk = win32file.ReadFile(pipe, 1024*1024)
        data += chunk
    except pywintypes.error as e:
        if e.args[0] == 109: return b""
        raise

    # 2. Проверяем, нужны ли нам еще данные (ищем Content-Length)
    # Используем поиск без учета регистра
    match = re.search(br'(?i)Content-Length:\s*(\d+)', data)
    
    if match:
        content_length = int(match.group(1))
        # Находим, где закончились заголовки
        header_end = data.find(b'\r\n\r\n')
        if header_end == -1:
            header_end = data.find(b'\n\n') # На случай упрощенного HTTP

        if header_end != -1:
            actual_body_len = len(data) - (header_end + 4 if b'\r\n\r\n' in data else header_end + 2)
        else:
            actual_body_len = 0

        # 3. Дочитываем хвост, если он не пришел в первом пакете
        attempts = 0
        while actual_body_len < content_length and attempts < 20:
            try:
                # Проверяем наличие данных без блокировки
                _, avail, _, _ = win32pipe.PeekNamedPipe(pipe, 0)
                if avail > 0:
                    hr, chunk = win32file.ReadFile(pipe, avail)
                    data += chunk
                    actual_body_len += len(chunk)
                else:
                    time.sleep(0.05)
                    attempts += 1
            except:
                break
            
    # Сохраняем для финальной проверки
    with open('raw_pipe_data.bin', 'wb') as f:
        f.write(data)
        
    return data

def handle_client(pipe, karma_host, karma_port):
    try:
        req_data = read_full_data(pipe)
        if not req_data: return

        mod_req_data, original_mode = process_http_message(req_data, is_request=True)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(15.0)
            s.connect((karma_host, karma_port))
            s.sendall(mod_req_data)
            
            resp_data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                resp_data += chunk
        
        mod_resp_data, _ = process_http_message(resp_data, is_request=False, original_mode=original_mode)
        win32file.WriteFile(pipe, mod_resp_data)
        win32file.FlushFileBuffers(pipe)
        
    except pywintypes.error as e:
        if e.args[0] != 109: logging.error(f"Ошибка Pipe: {e}")
    except Exception as e:
        logging.exception(f"Ошибка сессии: {e}")
    finally:
        try:
            win32pipe.DisconnectNamedPipe(pipe)
            win32file.CloseHandle(pipe)
        except: pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--karma-host', default='127.0.0.1')
    parser.add_argument('--karma-port', type=int, default=8080)
    parser.add_argument('--pipe', default=r'\\.\pipe\carma')
    args = parser.parse_args()
    
    logging.info(f"Запуск глубокой диагностики. Pipe: {args.pipe}")
    
    while True:
        try:
            # Используем MESSAGE режим, но читаем как байты — это самый совместимый вариант
                        pipe = win32pipe.CreateNamedPipe(
                args.pipe,
                win32pipe.PIPE_ACCESS_DUPLEX,
                # Используем BYTE режим, так как программа шлет HTTP-поток
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                2*1024*1024, # 2MB буфер на выход
                2*1024*1024, # 2MB буфер на вход
                0,
                None
            )

            win32pipe.ConnectNamedPipe(pipe, None)
            handle_client(pipe, args.karma_host, args.karma_port)
        except KeyboardInterrupt: break
        except Exception as e:
            logging.error(f"Цикл: {e}")
            time.sleep(0.5)

if __name__ == '__main__':
    main()
