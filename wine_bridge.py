import argparse
import socket
import win32pipe
import win32file
import pywintypes
import time
import logging
from logging.handlers import RotatingFileHandler

# Настройка логирования для моста
logger = logging.getLogger("WineBridge")
logger.setLevel(logging.INFO)

formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')

file_handler = RotatingFileHandler('wine_bridge.log', maxBytes=2 * 1024 * 1024, backupCount=2, encoding='utf-8')
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)


def handle_client(pipe, proxy_host: str, proxy_port: int):
    try:
        logger.info("Подключился клиент к Pipe. Чтение данных...")
        hr, data = win32file.ReadFile(pipe, 10 * 1024 * 1024)

        if not data:
            logger.warning("Прочитаны пустые данные из Pipe")
            return

        logger.info(f"Получено {len(data)} байт. Пересылаем на TCP прокси {proxy_host}:{proxy_port}...")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(30.0)  # Таймаут ожидания ответа от линукса (важно!)
            s.connect((proxy_host, proxy_port))
            s.sendall(data)

            response_data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response_data += chunk

        logger.info(f"Получен ответ от Linux прокси ({len(response_data)} байт). Запись обратно в Pipe...")
        win32file.WriteFile(pipe, response_data)
        win32file.FlushFileBuffers(pipe)
        logger.info("Цикл обмена успешно завершен.")

    except socket.timeout:
        logger.error("Таймаут: Linux-прокси не ответил вовремя.")
    except socket.error as e:
        logger.error(f"Ошибка сети (нет связи с Linux-прокси): {e}")
    except Exception as e:
        logger.exception("Непредвиденная ошибка при обработке клиента Pipe")
    finally:
        try:
            win32pipe.DisconnectNamedPipe(pipe)
            win32file.CloseHandle(pipe)
        except Exception as e:
            logger.debug(f"Ошибка при закрытии Pipe (можно игнорировать): {e}")


def main():
    parser = argparse.ArgumentParser(description="Wine Bridge (Named Pipe -> TCP Proxy)")
    parser.add_argument('--proxy-host', type=str, default='127.0.0.1', help='IP адрес Linux-прокси')
    parser.add_argument('--proxy-port', type=int, default=18081, help='Порт Linux-прокси')
    parser.add_argument('--pipe', type=str, default=r'\\.\pipe\carma', help='Имя Named Pipe')

    args = parser.parse_args()

    logger.info("Запуск Wine Bridge...")
    logger.info(f"Слушаем Pipe: {args.pipe}")
    logger.info(f"Перенаправляем на TCP: {args.proxy_host}:{args.proxy_port}")

    while True:
        try:
            pipe = win32pipe.CreateNamedPipe(
                args.pipe,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                10 * 1024 * 1024,
                10 * 1024 * 1024,
                0,
                None
            )

            win32pipe.ConnectNamedPipe(pipe, None)
            handle_client(pipe, args.proxy_host, args.proxy_port)

        except pywintypes.error as e:
            logger.error(f"Ошибка Windows API: {e}")
            time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Остановка моста...")
            break
        except Exception as e:
            logger.exception("Критическая ошибка в главном цикле")
            time.sleep(1)


if __name__ == '__main__':
    main()