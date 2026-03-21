import pytest
import socket
from unittest.mock import MagicMock, patch

# Имитируем модули, которых нет на Linux, чтобы скрипт вообще смог импортироваться
import sys

mock_win32 = MagicMock()
sys.modules["win32pipe"] = mock_win32
sys.modules["win32file"] = mock_win32
sys.modules["pywintypes"] = mock_win32

from wine_bridge import handle_client


@patch('socket.socket')
def test_handle_client_data_flow(mock_socket_class):
    """
    Проверяем полный цикл:
    Pipe Read -> Socket Send -> Socket Recv -> Pipe Write
    """
    # 1. Настраиваем мок для Named Pipe
    mock_pipe = MagicMock()

    # Имитируем чтение из пайпа (ReadFile возвращает кортеж (код_ошибки, данные))
    test_request = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nTEST"
    mock_win32.ReadFile.return_value = (0, test_request)

    # 2. Настраиваем мок для TCP сокета (Proxy)
    mock_socket_inst = mock_socket_class.return_value.__enter__.return_value
    test_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    # Сокет сначала читает данные (chunk), потом получает пустой чанк (закрытие)
    mock_socket_inst.recv.side_effect = [test_response, b""]

    # 3. Запускаем функцию
    handle_client(mock_pipe, "127.0.0.1", 18081)

    # ПРОВЕРКИ:

    # Проверяем, что мост попытался подключиться к правильному адресу
    mock_socket_inst.connect.assert_called_once_with(("127.0.0.1", 18081))

    # Проверяем, что данные из пайпа ушли в сокет
    mock_socket_inst.sendall.assert_called_once_with(test_request)

    # Проверяем, что ответ из сокета записан обратно в пайп
    mock_win32.WriteFile.assert_called_once_with(mock_pipe, test_response)

    # Проверяем, что пайп был закрыт в конце
    mock_win32.DisconnectNamedPipe.assert_called_once_with(mock_pipe)


def test_handle_client_network_error(mock_socket_class):
    """Проверяем поведение при обрыве сети"""
    mock_pipe = MagicMock()
    mock_win32.ReadFile.return_value = (0, b"some data")

    # Имитируем ошибку подключения
    mock_socket_inst = mock_socket_class.return_value.__enter__.return_value
    mock_socket_inst.connect.side_effect = socket.error("Connection refused")

    # Функция не должна «падать», она должна обработать исключение и закрыть пайп
    handle_client(mock_pipe, "127.0.0.1", 18081)

    mock_win32.DisconnectNamedPipe.assert_called_once()
