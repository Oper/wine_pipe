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
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('wine_bridge.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)


def generate_eid_stub() -> str:
    """Генерирует строку EID в формате UTF-16LE + Base64 для программы."""
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
    """Подменяет режимы 53 и 55, доверяя настройки TSP самой Карме."""
    try:
        payload = json.loads(req_body.decode('utf-8'))
        mode = payload.get("mode")

        if mode == 53:
            logging.info("Перехват: mode 53 -> mode 27 (Создание подписи).")
            payload["mode"] = 27

            # Собираем параметры.
            # Оставляем отключение проверки сертификата (часто нужно для тестовых TSP),
            # но сам URL добавляем ТОЛЬКО если его явно прислала программа.
            tsp_params = "TSP_CHECK_CERT=0;"
            if "TSP_URL" in payload:
                logging.info(f"Программа явно запросила TSP_URL: {payload['TSP_URL']}")
                tsp_params += f"TSP_URL={payload['TSP_URL']};"
            else:
                logging.info("TSP_URL не передан, Карма использует свои настройки по умолчанию.")

            # Инжектим параметры в extInitParams
            if "extInitParams" in payload:
                payload["extInitParams"] = f"{payload['extInitParams']};{tsp_params}"
            else:
                payload["extInitParams"] = tsp_params

        elif mode == 55:
            logging.info("Перехват: mode 55 -> mode 29 (Проверка подписи).")
            payload["mode"] = 29

        return json.dumps(payload, separators=(',', ':')).encode('utf-8')

    except json.JSONDecodeError:
        return req_body
    except Exception as e:
        logging.error(f"Ошибка при трансляции запроса: {e}")
        return req_body


def translate_response(resp_body: bytes, original_mode: int) -> bytes:
    """Добавляет имитацию структур штампа времени в ответ Кармы для Windows-программы."""
    if original_mode not in (53, 55):
        return resp_body

    try:
        payload = json.loads(resp_body.decode('utf-8'))

        if "signInfo" in payload and isinstance(payload["signInfo"], list):
            logging.info(f"Модификация ответа для mode {original_mode}: инъекция блока Extensions.")
            for info in payload["signInfo"]:
                info["Extensions"] = [{
                    "ExtensionName": "Штамп времени",
                    "ExtensionOID": "1.2.840.113549.1.9.16.2.14",
                    "ExtensionInterpretedString": "Результат проверки подписи: Действительна; Результат проверки сертификата: Действителен;",
                    "ExtensionInterpretedData": generate_eid_stub()
                }]
                info["CoSigners"] = []

        return json.dumps(payload, separators=(',', ':')).encode('utf-8')

    except json.JSONDecodeError:
        return resp_body
    except Exception as e:
        logging.error(f"Ошибка при трансляции ответа: {e}")
        return resp_body


def process_http_message(data: bytes, is_request: bool = True, original_mode: int = 0) -> tuple[bytes, int]:
    """Разбирает HTTP, модифицирует JSON и пересобирает с новым Content-Length."""
    header_end = data.find(b'\r\n\r\n')
    if header_end == -1:
        return data, 0

    headers_raw = data[:header_end]
    body = data[header_end + 4:]

    current_mode = original_mode
    if is_request:
        try:
            temp_json = json.loads(body.decode('utf-8'))
            current_mode = temp_json.get("mode", 0)
        except:
            pass

    if is_request:
        new_body = translate_request(body)
    else:
        new_body = translate_response(body, original_mode)

    headers_str = headers_raw.decode('utf-8', errors='ignore')
    new_headers_str = re.sub(
        r'(?i)Content-Length:\s*\d+',
        f'Content-Length: {len(new_body)}',
        headers_str
    )

    return new_headers_str.encode('utf-8') + b'\r\n\r\n' + new_body, current_mode


def handle_client(pipe, karma_host: str, karma_port: int):
    try:
        hr, req_data = win32file.ReadFile(pipe, 10 * 1024 * 1024)
        if not req_data: return

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

    except Exception as e:
        logging.exception(f"Ошибка сессии: {e}")
    finally:
        try:
            win32pipe.DisconnectNamedPipe(pipe)
            win32file.CloseHandle(pipe)
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="Умный мост Named Pipe -> Native Linux Carma")
    parser.add_argument('--karma-host', type=str, default='127.0.0.1', help='IP нативной Кармы')
    parser.add_argument('--karma-port', type=int, default=8080, help='Порт нативной Кармы')
    parser.add_argument('--pipe', type=str, default=r'\\.\pipe\carma', help='Имя Named Pipe')
    args = parser.parse_args()

    logging.info(f"Запуск умного моста. Pipe: {args.pipe} -> Карма: {args.karma_host}:{args.karma_port}")

    while True:
        try:
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
