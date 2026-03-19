import win32pipe
import win32file
import pywintypes
import socket
import threading
import sys

PIPE_NAME = r'\\.\pipe\carma'
LINUX_HOST = '127.0.0.1'
LINUX_PORT = 18080


def tcp_to_pipe(sock, pipe):
    """Читает из TCP и пишет в Pipe"""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            win32file.WriteFile(pipe, data)
        except Exception:
            break


def handle_client(pipe):
    print("Клиент подключился к pipe.")
    try:
        # Подключаемся к нативному Linux-серверу
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((LINUX_HOST, LINUX_PORT))
        print(f"Соединение с Linux-сервером {LINUX_HOST}:{LINUX_PORT} установлено.")

        # Запускаем поток для чтения ответов от Linux
        t = threading.Thread(target=tcp_to_pipe, args=(sock, pipe), daemon=True)
        t.start()

        # Читаем запросы из Pipe и шлем в Linux
        while True:
            try:
                hr, data = win32file.ReadFile(pipe, 4096)
                if not data:
                    break
                sock.sendall(data)
            except pywintypes.error as e:
                # Ошибка 109 - pipe был закрыт на другом конце
                if e.winerror != 109:
                    print(f"Ошибка чтения pipe: {e}")
                break
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        sock.close()
        win32file.FlushFileBuffers(pipe)
        win32pipe.DisconnectNamedPipe(pipe)
        win32file.CloseHandle(pipe)
        print("Клиент отключен.")


def main():
    print(f"Ожидание подключений на {PIPE_NAME}...")
    while True:
        pipe = win32pipe.CreateNamedPipe(
            PIPE_NAME,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            65536, 65536,
            0,
            None
        )

        if pipe == win32file.INVALID_HANDLE_VALUE:
            print("Ошибка создания Named Pipe")
            sys.exit(1)

        win32pipe.ConnectNamedPipe(pipe, None)
        # Обрабатываем клиента в отдельном потоке, чтобы не блокировать pipe
        client_thread = threading.Thread(target=handle_client, args=(pipe,), daemon=True)
        client_thread.start()


if __name__ == '__main__':
    main()