import pytest
import json
from unittest.mock import MagicMock, patch
from linux_proxy import extract_content_length, process_mode_53


# Тест парсинга Content-Length из сырых заголовков
def test_extract_content_length():
    headers = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 42\r\n\r\n"
    assert extract_content_length(headers) == 42

    headers_case = b"content-length: 100\r\n\r\n"
    assert extract_content_length(headers_case) == 100

    headers_none = b"GET / HTTP/1.1\r\n\r\n"
    assert extract_content_length(headers_none) == 0


# Тест логики режима 53 (усовершенствование подписи) с моком pycades
@patch('linux_proxy.pycades')
def test_process_mode_53_success(mock_pycades):
    # Настраиваем моки для объектов pycades
    mock_signed_data = MagicMock()
    mock_pycades.SignedData.return_value = mock_signed_data
    mock_signed_data.SignCades.return_value = "ENHANCED_SIGNATURE_B64"

    carma_json = {
        "signInfo": [{"sign_buffer": "ORIGINAL_B64"}]
    }
    req_json = {"mode": 53, "TSP_URL": "http://test-tsp.ru"}
    default_tsp = "http://default.ru"

    result = process_mode_53(carma_json, req_json, default_tsp)

    # Проверяем, что вызвались методы верификации и усовершенствования
    mock_signed_data.VerifyCades.assert_called_once_with("ORIGINAL_B64", 1, True)
    mock_signed_data.EnhanceCades.assert_called_once_with(5, "http://test-tsp.ru", 1)

    # Проверяем результат
    assert result["signInfo"][0]["sign_buffer"] == "ENHANCED_SIGNATURE_B64"


def test_process_mode_53_empty_data():
    carma_json = {"signInfo": []}  # Нет данных
    req_json = {"mode": 53}
    result = process_mode_53(carma_json, req_json, "http://tsp.ru")
    assert result == carma_json  # Должен вернуть исходный объект без изменений


@patch('linux_proxy.requests.post')
def test_handle_do_connection_flow(mock_post):
    from linux_proxy import handle_do_connection

    # Имитируем ответ от сервера Кармы
    mock_carma_resp = MagicMock()
    mock_carma_resp.json.return_value = {"errorCode": 0, "status": "ok"}
    mock_post.return_value = mock_carma_resp

    # Имитируем сокет клиента
    mock_conn = MagicMock()
    # Данные, которые приходят от Wine: HTTP-заголовок + JSON
    request_body = json.dumps({"mode": 1, "data": "test"}).encode('utf-8')
    request_data = f"POST / HTTP/1.0\r\nContent-Length: {len(request_body)}\r\n\r\n".encode('utf-8') + request_body

    # Настраиваем последовательное чтение из сокета
    mock_conn.recv.side_effect = [bytes([b]) for b in request_data]

    handle_do_connection(mock_conn, ("127.0.0.1", 12345), "http://tsp.ru")

    # Проверяем, что прокси отправил запрос в Карму
    assert mock_post.called
    # Проверяем, что прокси отправил ответ обратно в сокет
    assert mock_conn.sendall.called
