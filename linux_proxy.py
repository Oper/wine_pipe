import argparse
import socket
import threading
import requests
import json
import re
import base64
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta

# Настройка логирования
logger = logging.getLogger("LinuxProxy")
logger.setLevel(logging.DEBUG)

# Формат логов: [Время] [Уровень] [Поток] Сообщение
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(threadName)s] %(message)s')

# Обработчик для записи в файл (максимум 5 МБ, храним 3 резервные копии)
file_handler = RotatingFileHandler('linux_proxy.log', maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

# Обработчик для вывода в консоль
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

try:
    import pycades
except ImportError:
    logger.critical("Модуль pycades не найден. Убедитесь, что КриптоПро установлен корректно.")
    exit(1)

# Константы CAdES
CADESCOM_CADES_BES = 1
CADESCOM_CADES_T = 5
CADESCOM_BASE64_TO_BINARY = 1
CARMA_URL = 'http://127.0.0.1:8080/'


def extract_content_length(headers: bytes) -> int:
    match = re.search(br'(?i)Content-Length:\s*(\d+)', headers)
    return int(match.group(1)) if match else 0


def get_eid_string(signer) -> str:
    try:
        ts_time_str = signer.SignatureTimeStampTime
        dt_utc = datetime.strptime(ts_time_str, "%d.%m.%Y %H:%M:%S")
        dt_local = dt_utc + timedelta(hours=3)
        local_time_str = dt_local.strftime("%d.%m.%Y %H:%M:%S")

        eid_raw = (
            f'version="V1";UtcTime="{ts_time_str}";LocalTime="{local_time_str}";'
            f'GenTime="{ts_time_str}";SerialNumber="";Policy="";HashAlg="GOST R 34.11-2012 256";HashValue="";'
        )
        eid_utf16 = eid_raw.encode('utf-16le')
        return base64.b64encode(eid_utf16).decode('utf-8')
    except Exception as e:
        logger.exception("Ошибка формирования EID")
        return ""


def process_mode_53(carma_json: dict, req_json: dict, default_tsp_url: str) -> dict:
    tsp_url = req_json.get("TSP_URL") or default_tsp_url
    logger.info(f"Режим 53: Запрос штампа CAdES-T у сервера {tsp_url}")

    try:
        sign_info = carma_json.get("signInfo", [{}])[0]
        signature_b64 = sign_info.get("sign_buffer", "")

        if not signature_b64:
            logger.error("Нет sign_buffer в ответе Кармы")
            return carma_json

        signed_data = pycades.SignedData()
        signed_data.VerifyCades(signature_b64, CADESCOM_CADES_BES, True)
        signed_data.EnhanceCades(CADESCOM_CADES_T, tsp_url, CADESCOM_BASE64_TO_BINARY)
        enhanced_signature = signed_data.SignCades(None, CADESCOM_CADES_T, True, CADESCOM_BASE64_TO_BINARY)

        sign_info["sign_buffer"] = enhanced_signature
        logger.info("Подпись успешно усовершенствована до CAdES-T")

    except Exception as e:
        logger.exception("Ошибка PyCAdES в Режиме 53")
        carma_json = {
            "errorCode": 999,
            "errorMessage": f"linux_proxy - ошибка формирования штампа: {str(e)}",
            "streamId": req_json.get("streamId", 0),
            "signInfo": [],
            "isAttached": False
        }
    return carma_json


def process_mode_55(carma_json: dict, req_json: dict) -> dict:
    logger.info("Режим 55: Проверка штампа времени и извлечение данных")
    signature_b64 = req_json.get("sendSignData", "")

    if not signature_b64:
        logger.warning("Нет sendSignData в запросе Режима 55")
        return carma_json

    try:
        signed_data = pycades.SignedData()
        signed_data.VerifyCades(signature_b64, CADESCOM_CADES_BES, True)

        signers = signed_data.Signers
        if signers.Count > 0:
            signer = signers.Item(1)
            eid_b64 = get_eid_string(signer)

            extensions = [{
                "ExtensionName": "Штамп времени",
                "ExtensionOID": "1.2.840.113549.1.9.16.2.14",
                "ExtensionInterpretedString": "Результат проверки подписи: Действительна; Результат проверки сертификата: Действителен;",
                "ExtensionInterpretedData": eid_b64
            }]

            if "signInfo" in carma_json and len(carma_json["signInfo"]) > 0:
                carma_json["signInfo"][0]["Extensions"] = extensions
                carma_json["signInfo"][0]["CoSigners"] = []

            logger.info("Данные штампа (EID) успешно извлечены")

    except Exception as e:
        logger.exception("Ошибка PyCAdES в Режиме 55")
        carma_json = {
            "errorCode": 999,
            "errorMessage": f"linux_proxy - ошибка проверки штампа: {str(e)}",
            "streamId": req_json.get("streamId", 0),
            "signInfo": [],
            "isAttached": False
        }
    return carma_json


def handle_do_connection(conn, addr, default_tsp_url: str):
    logger.info(f"Новое подключение от клиента: {addr}")
    try:
        header_data = b""
        while b"\r\n\r\n" not in header_data:
            chunk = conn.recv(1)
            if not chunk: break
            header_data += chunk

        cl = extract_content_length(header_data)
        logger.debug(f"Получены заголовки, ожидаемый размер тела: {cl} байт")

        body_data = b""
        while len(body_data) < cl:
            chunk = conn.recv(min(4096, cl - len(body_data)))
            if not chunk: break
            body_data += chunk

        req_json = {}
        mode = 0
        try:
            req_json = json.loads(body_data.decode('utf-8'))
            mode = req_json.get("mode", 0)
            logger.info(f"Получен запрос, режим (mode): {mode}")
        except json.JSONDecodeError:
            logger.warning("Не удалось распарсить тело запроса как JSON")

        carma_headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept': 'application/json, text/javascript, */*; q=0.01'
        }

        logger.debug("Отправка данных в Карму...")
        carma_resp = requests.post(CARMA_URL, data=body_data, headers=carma_headers)
        response_json = carma_resp.json()
        logger.debug("Получен ответ от Кармы")

        if mode == 53:
            response_json = process_mode_53(response_json, req_json, default_tsp_url)
        elif mode == 55:
            response_json = process_mode_55(response_json, req_json)

        resp_body = json.dumps(response_json, separators=(',', ':')).encode('utf-8')
        resp_headers = f"HTTP/1.0 200 OK\r\nContent-Length: {len(resp_body)}\r\n\r\n".encode('utf-8')

        conn.sendall(resp_headers + resp_body)
        logger.info("Ответ успешно отправлен клиенту")

    except Exception as e:
        logger.exception("Критическая ошибка при обработке соединения")
    finally:
        conn.close()
        logger.debug(f"Соединение с {addr} закрыто")


def main():
    parser = argparse.ArgumentParser(description="Linux Proxy для Carma (PyCAdES)")
    parser.add_argument('-t', '--tsp-url', type=str, required=True, help='URL сервера штампов времени')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='IP для прослушивания')
    parser.add_argument('-p', '--port', type=int, default=18081, help='Порт для прослушивания')

    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((args.host, args.port))
        server.listen(5)
        logger.info(f"Linux Proxy запущен на {args.host}:{args.port}")
        logger.info(f"Сервер штампов времени по умолчанию: {args.tsp_url}")
    except Exception as e:
        logger.critical(f"Не удалось запустить сервер: {e}")
        exit(1)

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_do_connection, args=(conn, addr, args.tsp_url), daemon=True)
            t.start()
        except KeyboardInterrupt:
            logger.info("Получен сигнал остановки (Ctrl+C). Завершение работы...")
            break
        except Exception as e:
            logger.exception("Ошибка в главном цикле сервера")

    server.close()


if __name__ == '__main__':
    main()
