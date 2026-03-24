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

def format_json_for_log(raw_bytes: bytes) -> str:
    try:
        data_dict = json.loads(raw_bytes.decode('utf-8'))
        dump_dict = copy.deepcopy(data_dict)
        for k, v in dump_dict.items():
            if isinstance(v, str) and len(v) > 200:
                dump_dict[k] = v[:50] + f"... [Строка обрезана, {len(v)} символов]"
        return json.dumps(dump_dict, ensure_ascii=False, indent=2)
    except Exception:
        snippet = raw_bytes[:500]
        return snippet.decode('utf-8', errors='replace') + ("..." if len(raw_bytes) > 500 else "")

def generate_eid_stub() -> str:
    now = datetime.now()
    time_str = now.strftime("%d.%m.%Y %H:%M:%S")
    eid_raw = (
        f'version="V1";UtcTime="{time_str}";LocalTime="{time_str}";'
        f'GenTime="{time_str}";SerialNumber="001234567890";Policy="1.2.643.2.2.34.6";'
        f'HashAlg="ГОСТ Р 34.11-2012 256 бит";HashValue="IMITATION_HASH_VALUE";'
        f'Accuracy="";Ordering="Выкл.";Nonce="";Tsa="";'
    )
    eid_utf16 = eid_raw.encode('utf-16le')
    return base64.b64encode(eid_utf16).decode('utf-8')

def translate_request(req_body: bytes) -> bytes:
    try:
        payload = json.loads(req_body.decode('utf-8'))
        mode = payload.get("mode")
        
        if mode == 53:
            payload["mode"] = 27 
            tsp_params = "TSP_CHECK_CERT=0;"
            if "TSP_URL" in payload and payload["TSP_URL"]:
                tsp_params += f"TSP_URL={payload['TSP_URL']};"
            
            ext = payload.get("extInitParams", "")
            if ext and not ext.endswith(';'): ext += ';'
            payload["extInitParams"] = ext + tsp_params
                
        elif mode == 55:
            payload["mode"] = 29
            
        return json.dumps(payload, separators=(',', ':')).encode('utf-8')
    except:
        return req_body

def translate_response(resp_body: bytes, original_mode: int) -> bytes:
    if original_mode not in (53, 55):
        return resp_body
        
    try:
        payload = json.loads(resp_body.decode('utf-8'))
        if "signInfo" in payload and isinstance(payload["signInfo"], list):
            for info in payload["signInfo"]:
                info["Extensions"] = [{
                    "ExtensionName": "Штамп времени",
                    "ExtensionOID": "1.2.840.113549.1.9.16.2.14",
                    "ExtensionInterpretedString": "Результат проверки подписи: Действительна; Результат проверки сертификата: Действителен;",
                    "ExtensionInterpretedData": generate_eid_stub()
                }]
                info["CoSigners"] = []
                
        return json.dumps(payload, separators=(',', ':')).encode('utf-8')
    except:
        return resp_body

def process_http_message(data: bytes, is_request: bool = True, original_mode: int = 0) -> tuple[bytes, int]:
    header_end = data.find(b'\r\n\r\n')
    if header_end == -1:
        logging.warning("Внимание: Данные без HTTP-заголовков или неполные!")
        return data, 0 

    headers_raw = data[:header_end]
    body = data[header_end + 4:]
    
    current_mode = original_mode
    if is_request:
        try:
            temp_json = json.loads(body.decode('utf-8'))
            current_mode = temp_json.get("mode", 0)
        except: pass

        logging.debug(f"\n--- ИСХОДНЫЙ ЗАПРОС (Mode: {current_mode}) ---\n{format_json_for_log(body)}\n-----------------------------")
        new_body = translate_request(body)
        if body != new_body:
            logging.debug(f"\n--- МОДИФИЦИРОВАННЫЙ ЗАПРОС ---\n{format_json_for_log(new_body)}\n-------------------------------")
    else:
        logging.debug(f"\n--- ОТВЕТ КАРМЫ (Original Mode: {original_mode}) ---\n{format_json_for_log(body)}\n-----------------------------")
        new_body = translate_response(body, original_mode)
        if body != new_body:
            logging.debug(f"\n--- МОДИФИЦИРОВАННЫЙ ОТВЕТ В ПРОГРАММУ ---\n{format_json_for_log(new_body)}\n------------------------------------------")

    headers_str = headers_raw.decode('utf-8', errors='ignore')
    new_headers_str = re.sub(
        r'(?i)Content-Length:\s*\d+', 
        f'Content-Length: {len(new_body)}', 
        headers_str
    )
    
    return new_headers_str.encode('utf-8') + b'\r\n\r\n' + new_body, current_mode


# --- НОВЫЙ БЛОК: УМНОЕ ЧТЕНИЕ ИЗ PIPE ---
def read_full_request_from_pipe(pipe) -> bytes:
    """Считывает данные из Pipe, учитывая Content-Length HTTP-протокола."""
    data = b""
    
    # 1. Читаем заголовки (до \r\n\r\n)
    while b"\r\n\r\n" not in data:
        try:
            hr, chunk = win32file.ReadFile(pipe, 4096)
            if not chunk: break
            data += chunk
        except pywintypes.error as e:
            if e.args[0] == 109: return data # Broken pipe
            raise

    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return data

    headers = data[:header_end]
    match = re.search(br'(?i)Content-Length:\s*(\d+)', headers)
    
    # 2. Дочитываем тело, если есть Content-Length
    if match:
        cl = int(match.group(1))
        body_len = len(data) - (header_end + 4)
        bytes_left = cl - body_len
        
        while bytes_left > 0:
            try:
                hr, chunk = win32file.ReadFile(pipe, min(4096, bytes_left))
                if not chunk: break
                data += chunk
                bytes_left -= len(chunk)
            except pywintypes.error as e:
                if e.args[0] == 109: break
                raise
                
    return data


def handle_client(pipe, karma_host: str, karma_port: int):
    try:
        # Используем новую функцию умного чтения
        req_data = read_full_request_from_pipe(pipe) 
        if not req_data: return

        logging.debug(f"Считано из Pipe: {len(req_data)} байт.")

        mod_req_data, original_mode = process_http_message(req_data, is_request=True)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(30.0)
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
        
    except socket.timeout:
        logging.error("Таймаут: Карма не ответила вовремя.")
    except ConnectionRefusedError:
        logging.error(f"Отказ в соединении: убедитесь, что Карма запущена на {karma_host}:{karma_port}.")
    except pywintypes.error as e:
        if e.args[0] != 109: # Игнорируем штатный обрыв канала
            logging.error(f"Ошибка Windows API: {e}")
    except Exception as e:
        logging.exception(f"Ошибка сессии: {e}")
    finally:
        try:
            win32pipe.DisconnectNamedPipe(pipe)
            win32file.CloseHandle(pipe)
        except: pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--karma-host', type=str, default='127.0.0.1')
    parser.add_argument('--karma-port', type=int, default=8080)
    parser.add_argument('--pipe', type=str, default=r'\\.\pipe\carma')
    args = parser.parse_args()
    
    logging.info(f"Запуск моста (HTTP Stream Fix). Pipe: {args.pipe} -> Карма: {args.karma_host}:{args.karma_port}")
    
    while True:
        try:
            # Вернули BYTE режим для правильного потокового чтения
            pipe = win32pipe.CreateNamedPipe(
                args.pipe, win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES, 10 * 1024 * 1024, 10 * 1024 * 1024, 0, None
            )
            win32pipe.ConnectNamedPipe(pipe, None)
            handle_client(pipe, args.karma_host, args.karma_port)
        except pywintypes.error as e:
            logging.error(f"Ошибка Pipe: {e}")
            time.sleep(1)
        except KeyboardInterrupt:
            break
        except Exception as e:
            logging.error(f"Ошибка цикла: {e}")
            time.sleep(1)

if __name__ == '__main__':
    main()
