import argparse
import os
import time

import win32pipe
import win32file
import requests
import json
import base64
import logging
import threading
from asn1crypto import cms, tsp, core
import gostcrypto

# --- НАСТРОЙКИ ---
PIPE_NAME = r'\\.\pipe\carma'
BACKEND_URL = "http://127.0.0.1:8080/"
LOG_FILE = "proxy_carma.log"
MANDATORY_TSP_URL = "http://127.0.0.1:87/tsp/tsp.srf"
DEBUG_MODE = False
DEBUG_DIR = "debug_dumps"

# --- НАСТРОЙКА ЛОГИРОВАНИЯ ---
logger = logging.getLogger("CarmaProxy")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s')

fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
fh.setFormatter(formatter)
ch = logging.StreamHandler()
ch.setFormatter(formatter)

logger.addHandler(fh)
logger.addHandler(ch)


# --- ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ ДЕБАГА ---

def dump_debug_file(req_id: str, stage: str, data: bytes):
    """Сохраняет бинарный дамп этапа обработки в файл."""
    if not DEBUG_MODE:
        return
    if not os.path.exists(DEBUG_DIR):
        os.makedirs(DEBUG_DIR)

    filename = os.path.join(DEBUG_DIR, f"{req_id}_{stage}")
    try:
        with open(filename, "wb") as f:
            f.write(data)
        logger.debug(f"[DEBUG] Дамп сохранен: {filename}")
    except Exception as e:
        logger.error(f"[DEBUG] Ошибка сохранения дампа {filename}: {e}")


# --- КРИПТОГРАФИЧЕСКИЕ ФУНКЦИИ (ГОСТ 2012) ---

def extract_signature_for_tsq(cms_der: bytes) -> bytes:
    content_info = cms.ContentInfo.load(bytes(cms_der))
    if content_info['content_type'].native != 'signed_data':
        raise ValueError("CMS не является SignedData.")
    signed_data = content_info['content']
    signer_info = signed_data['signer_infos'][0]
    return bytes(signer_info['signature'].native)


def create_tsq(sig_bytes: bytes) -> bytes:
    hasher = gostcrypto.gosthash.new('streebog256', data=sig_bytes)
    hash_value = hasher.digest()

    logger.debug(f"Вычислен ГОСТ-хеш подписи: {hash_value.hex()}")

    message_imprint = tsp.MessageImprint({
        'hash_algorithm': {
            'algorithm': '1.2.643.7.1.1.2.2',
        },
        'hashed_message': bytes(hash_value)
    })

    tsq = tsp.TimeStampReq({
        'version': 'v1',
        'message_imprint': message_imprint,
        'cert_req': True
    })
    return bytes(tsq.dump())


def inject_tsr_to_cms(cms_der: bytes, tsr_der: bytes) -> bytes:
    content_info = cms.ContentInfo.load(bytes(cms_der))
    signer_info = content_info['content']['signer_infos'][0]

    ts_resp = tsp.TimeStampResp.load(bytes(tsr_der))
    status = ts_resp['status']['status'].native
    if status not in ('granted', 'granted_with_mods'):
        fail_info = ts_resp['status']['fail_info'].native if ts_resp['status']['fail_info'] else "no_info"
        raise ValueError(f"TSA отказ: {status} ({fail_info})")

    ts_token = ts_resp['time_stamp_token']

    ts_attribute = cms.CMSAttribute({
        'type': '1.2.840.113549.1.9.16.2.14',
        'values': [ts_token]
    })

    if isinstance(signer_info['unsigned_attrs'], core.Void):
        signer_info['unsigned_attrs'] = cms.CMSAttributes([])

    signer_info['unsigned_attrs'].append(ts_attribute)
    return bytes(content_info.dump())


# --- ОБРАБОТКА MODE 53 ---

def process_mode_53(resp_body_bytes: bytes, incoming_tsp_url: str, req_id: str) -> bytes:
    tsp_url = MANDATORY_TSP_URL if MANDATORY_TSP_URL else incoming_tsp_url
    if not tsp_url:
        raise ValueError("Отсутствует URL-адрес TSP.")

    curr_data = bytes(resp_body_bytes)
    text_chunk = curr_data[:65536].decode('utf-8', errors='ignore')
    start_json_idx = text_chunk.find('{')
    if start_json_idx == -1:
        raise ValueError("Ответ от бэкэнда не в формате JSON.")

    decoder = json.JSONDecoder()
    data, end_idx_in_str = decoder.raw_decode(text_chunk[start_json_idx:])

    json_only_str = text_chunk[:start_json_idx + end_idx_in_str]
    byte_offset = len(json_only_str.encode('utf-8'))

    header_bytes = curr_data[:byte_offset]
    remainder = curr_data[byte_offset:]
    binary_tail = remainder.strip(b'\r\n\x00 ')

    cms_b64 = data.get("Signature") or data.get("signature")
    is_json_mode = False

    if cms_b64:
        cms_der = bytes(base64.b64decode(cms_b64))
        is_json_mode = True
    elif len(binary_tail) > 100:
        cms_der = bytes(binary_tail)
        is_json_mode = False
    else:
        raise ValueError("Подпись не найдена в ответе.")

    dump_debug_file(req_id, "03_original_signature.der", cms_der)

    # Получение штампа
    sig_val = extract_signature_for_tsq(cms_der)
    tsq_der = create_tsq(sig_val)
    dump_debug_file(req_id, "04_tsp_request.der", tsq_der)

    ts_resp = requests.post(
        tsp_url,
        data=tsq_der,
        headers={'Content-Type': 'application/timestamp-query'},
        timeout=15
    )
    ts_resp.raise_for_status()
    dump_debug_file(req_id, "05_tsp_response.der", ts_resp.content)

    updated_cms_der = inject_tsr_to_cms(cms_der, ts_resp.content)
    dump_debug_file(req_id, "06_updated_signature.der", updated_cms_der)

    # Сборка ответа
    if is_json_mode:
        field_name = "Signature" if "Signature" in data else "signature"
        data[field_name] = base64.b64encode(updated_cms_der).decode('ascii')
        return json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    else:
        idx = remainder.find(binary_tail)
        if idx != -1:
            gap = remainder[:idx]
            trailing_gap = remainder[idx + len(binary_tail):]
            return header_bytes + gap + updated_cms_der + trailing_gap
        else:
            return header_bytes + b'\r\n' + updated_cms_der


# --- ЛОГИКА ТРУБЫ (PIPE) ---

def handle_client(hPipe):
    # Генерируем уникальный ID для этого запроса (timestamp в миллисекундах)
    req_id = f"req_{int(time.time() * 1000)}"
    try:
        hr, raw_headers = win32file.ReadFile(hPipe, 65536)
        headers_str = raw_headers.decode('utf-8', errors='ignore')

        cl = 0
        for line in headers_str.split('\r\n'):
            if line.lower().startswith("content-length:"):
                cl = int(line.split(':')[1].strip())

        body_bytes = b""
        if cl > 0:
            while len(body_bytes) < cl:
                hr, chunk = win32file.ReadFile(hPipe, min(65536, cl - len(body_bytes)))
                body_bytes += chunk

        # Сохраняем входящий запрос от клиента (полностью) для дебага
        dump_debug_file(req_id, "01_client_request.bin", raw_headers + body_bytes)

        clean_input = body_bytes.replace(b'\x00', b'').strip()
        mode = 0
        tsp_url = ""

        try:
            body_str = clean_input.decode('utf-8', errors='ignore').lstrip()
            if body_str.startswith('{'):
                payload, _ = json.JSONDecoder().raw_decode(body_str)
                mode = payload.get("mode", 0)
                # Получаем адрес сервера штампа из запроса СДП, если его нет используем по умолчанию.
                tsp_url = payload.get("TSP_URL", "http://127.0.0.1:87/tsp/tsp.srf")
        except:
            if b'"mode":53' in clean_input or b'"mode": 53' in clean_input:
                mode = 53

        req_headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        resp = requests.post(BACKEND_URL, data=body_bytes, headers=req_headers, timeout=25)
        resp_content = resp.content

        # Сохраняем оригинальный ответ бэкенда
        dump_debug_file(req_id, "02_backend_response.bin", resp_content)

        original_content_type = resp.headers.get('Content-Type', 'application/json; charset=utf-8')

        status_line = "HTTP/1.1 200 OK"
        if mode == 53:
            try:
                resp_content = process_mode_53(resp_content, tsp_url, req_id)
                logger.info("Запрос Mode 53 успешно завершен со штампом.")
            except Exception as e:
                logger.error(f"ОТКАЗ В ШТАМПЕ: {e}")
                resp_content = json.dumps({
                    "success": False,
                    "error": "TIMESTAMP_ERROR",
                    "details": str(e)
                }).encode('utf-8')
                status_line = "HTTP/1.1 500 Internal Server Error"
                original_content_type = "application/json; charset=utf-8"

        http_response = (
                            f"{status_line}\r\n"
                            f"Content-Type: {original_content_type}\r\n"
                            f"Content-Length: {len(resp_content)}\r\n"
                            f"Connection: close\r\n\r\n"
                        ).encode('ascii') + resp_content

        # Сохраняем финальный ответ, который уйдет клиенту в трубу
        dump_debug_file(req_id, "07_final_proxy_response.bin", http_response)

        win32file.WriteFile(hPipe, http_response)

    except Exception as e:
        logger.error(f"Сбой в потоке: {e}")
    finally:
        try:
            win32file.FlushFileBuffers(hPipe)
            win32pipe.DisconnectNamedPipe(hPipe)
            win32file.CloseHandle(hPipe)
        except:
            pass


def main():
    global MANDATORY_TSP_URL, DEBUG_MODE, BACKEND_URL

    parser = argparse.ArgumentParser(description="Wine Proxy (Named Pipe: carma)")
    parser.add_argument('--carma-host', type=str, default=BACKEND_URL, help='Адрес сервера КАРМЫ')
    parser.add_argument('--tsp', type=str, default=MANDATORY_TSP_URL, help='Сервер штампа времени')
    parser.add_argument('--debug', action='store_true', help='Режим отладки')

    args = parser.parse_args()
    BACKEND_URL = args.carma_host
    MANDATORY_TSP_URL = args.tsp
    DEBUG_MODE = args.debug

    logger.info(f"=== Proxy Ready (Named Pipe: carma -> {BACKEND_URL}) ===")
    logger.info(f"=== Штам времени TSP: {args.tsp} ===")
    if DEBUG_MODE:
        logger.setLevel(logging.DEBUG)
        logger.info(f"=== Включен режим отладки (DEBUG_MODE). Дампы сохраняются в папку {DEBUG_DIR}/ ===")


    while True:
        try:
            hPipe = win32pipe.CreateNamedPipe(
                PIPE_NAME,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                65536, 65536, 0, None
            )
            win32pipe.ConnectNamedPipe(hPipe, None)
            t = threading.Thread(target=handle_client, args=(hPipe,))
            t.daemon = True
            t.start()
        except Exception as e:
            logger.error(f"Ошибка цикла: {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()
