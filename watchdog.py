import ipaddress
import json
import logging
import math
import os
import re
import ssl
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import quote, urlencode


CONFIG_PATH = Path("/etc/cheburcheck-watchdog/config.json")
INTERVALS = {
    3600: "Раз в час",
    10800: "Раз в 3 часа",
    21600: "Раз в 6 часов",
    43200: "Раз в 12 часов",
    86400: "Раз в сутки",
    172800: "Раз в 2 суток",
    604800: "Раз в неделю",
}
DEFAULT_INTERVAL = 21600
BETWEEN_TARGETS = 5
API_HOST = "cheburcheck.ru"
API_ROOT = "/api/v1"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SSE_TIMEOUT = 90
VERDICTS = {
    "ok": "доступен",
    "uncertain": "неясно",
    "cdn_block": "блокировка CDN",
    "sni_block": "блокировка SNI",
    "dns_spoofing": "подмена DNS",
    "tspu_block": "блокировка ТСПУ",
    "whitelist": "исключение CDN",
}
LOG = logging.getLogger("cheburcheck-watchdog")


@dataclass
class Config:
    token: str = field(default="", repr=False)
    targets: tuple = ()
    interval: int = DEFAULT_INTERVAL


def normalize_ip(raw):
    if not isinstance(raw, str) or "%" in raw:
        raise ValueError("Введите публичный IPv4- или IPv6-адрес.")
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise ValueError("Введите публичный IPv4- или IPv6-адрес.") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError("Для сетевого сканирования нужен публичный IP-адрес.")
    return str(address)


def valid_token(token):
    return isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,1024}", token)


def load_config(path=CONFIG_PATH, *, allow_missing=False):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if allow_missing:
            return Config()
        raise
    if not isinstance(data, dict):
        raise ValueError("Некорректная конфигурация.")
    token = data.get("token", "")
    targets = data.get("targets", [])
    interval = data.get("interval", DEFAULT_INTERVAL)
    if (token != "" and not valid_token(token)) or not isinstance(targets, list):
        raise ValueError("Некорректный токен или список адресов в конфигурации.")
    if type(interval) is not int or interval not in INTERVALS:
        raise ValueError("Некорректный период проверки в конфигурации.")
    return Config(token, tuple(dict.fromkeys(map(normalize_ip, targets))), interval)


def save_config(config, path=CONFIG_PATH):
    path.parent.mkdir(mode=0o700, exist_ok=True)
    staged = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            staged = Path(stream.name)
            json.dump(vars(config), stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        staged.replace(path)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


class APIError(Exception):
    def __init__(self, stage, status, retry_after=0):
        super().__init__(f"{stage}: HTTP {status}")
        self.status = status
        self.stage = stage
        self.retry_after = retry_after


class ResponseError(Exception):
    pass


def retry_delay(value):
    if not value:
        return 0
    try:
        if value.isascii() and value.isdigit():
            return min(int(value), int(timedelta.max.total_seconds()))
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return max(0, math.ceil((date - datetime.now(timezone.utc)).total_seconds()))
    except (ValueError, OverflowError, TypeError):
        return 0


@contextmanager
def request(stage, path, media_type, token=None):
    headers = {"Accept": media_type, "User-Agent": "Cheburcheck-Watchdog"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    connection = HTTPSConnection(API_HOST, timeout=20, context=ssl.create_default_context())
    try:
        connection.request("GET", API_ROOT + path, headers=headers)
        with connection.getresponse() as response:
            if response.status != 200:
                raise APIError(stage, response.status, retry_delay(response.getheader("Retry-After")))
            if response.headers.get_content_type() != media_type:
                raise ResponseError(f"{stage}: неожиданный тип ответа")
            yield response
    except (OSError, HTTPException) as error:
        raise ResponseError(f"{stage}: сбой соединения ({type(error).__name__})") from None
    finally:
        connection.close()


def decode_object(raw, stage):
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise ResponseError(f"{stage}: некорректный JSON") from None
    if not isinstance(data, dict):
        raise ResponseError(f"{stage}: ожидался объект JSON")
    return data


def check_lists(target):
    query = urlencode({"target": target})
    with request("Проверка по спискам", f"/check?{query}", "application/json") as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ResponseError("Проверка по спискам: превышен размер ответа")
    result = decode_object(raw, "Проверка по спискам")
    if type(result.get("blocked")) is not bool:
        raise ResponseError("Проверка по спискам: отсутствует признак блокировки")
    return result


def sse_events(response):
    event = ""
    data = []
    remaining = MAX_RESPONSE_BYTES
    deadline = time.monotonic() + SSE_TIMEOUT
    while remaining and time.monotonic() < deadline:
        line = response.readline(min(remaining, 65536) + 1)
        if not line:
            return
        remaining -= len(line)
        if remaining < 0 or len(line) > 65536:
            raise ResponseError("Сканеры: превышен размер ответа SSE")
        line = line.rstrip(b"\r\n")
        if not line:
            if event and data:
                yield event, b"\n".join(data)
            event, data = "", []
            continue
        field_name, _, value = line.partition(b":")
        if value.startswith(b" "):
            value = value[1:]
        if field_name == b"event":
            event = value.decode("ascii", errors="replace")
        elif field_name == b"data":
            data.append(value)
    raise ResponseError("Сканеры: превышен лимит размера или времени ожидания SSE")


def scan_ip(context_id, token):
    path = "/probe/" + quote(context_id, safe="")
    results = {}
    with request("Сканеры", path, "text/event-stream", token) as response:
        for event, raw in sse_events(response):
            if event == "result":
                result = decode_object(raw, "Ответ сканера")
                probe_id = result.get("probe_id")
                verdicts = result.get("verdicts")
                if type(probe_id) not in (str, int) or not isinstance(verdicts, list):
                    raise ResponseError("Сканеры: некорректный результат")
                results[str(probe_id)] = result
            elif event == "done":
                done = decode_object(raw, "Завершение сканирования")
                online = done.get("online_probes")
                received = done.get("response_count")
                if any(type(count) is not int or count < 0 for count in (online, received)):
                    raise ResponseError("Сканеры: отсутствует число ответов")
                return results, received, online
    raise ResponseError("Сканеры: поток SSE закрылся до события done")


def check_target(target, token):
    lists = check_lists(target)
    LOG.log(logging.WARNING if lists["blocked"] else logging.INFO, "%s — по спискам: %s", target,
            "найдена блокировка" if lists["blocked"] else "блокировка не найдена")
    context_id = lists.get("id")
    if not isinstance(context_id, str) or not context_id:
        LOG.warning("%s — контекст для сетевых сканеров недоступен", target)
        return

    results, received, online = scan_ip(context_id, token)
    counts = Counter()
    for result in results.values():
        counts.update({verdict for verdict in result["verdicts"]
                       if isinstance(verdict, str) and verdict in VERDICTS})
    summary = ", ".join(f"{VERDICTS[verdict]}: {counts[verdict]}"
                        for verdict in VERDICTS if counts[verdict]) or "вердиктов нет"
    cached = sum(result.get("cached") is True for result in results.values())
    incomplete = not results or received < online or received != len(results)
    level = logging.WARNING if incomplete or counts["tspu_block"] else logging.INFO
    LOG.log(level, "%s — сканеры: %d из %d, из кеша: %d. %s%s", target, len(results), online,
            cached, summary, " (неполный результат)" if incomplete else "")


def check_batch(config):
    for index, target in enumerate(config.targets):
        if index:
            time.sleep(BETWEEN_TARGETS)
        try:
            check_target(target, config.token)
        except APIError as error:
            LOG.warning("%s — %s", target, error)
            if error.status == 429:
                delay = max(config.interval, error.retry_after)
                LOG.warning("Лимит API: следующий цикл не ранее чем через %d сек.", delay)
                return delay
            if error.status == 401 and error.stage == "Сканеры":
                LOG.warning("Проверьте API-токен и его срок действия.")
                break
        except ResponseError as error:
            LOG.warning("%s — %s", target, error)
    return 0


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        config = load_config(Path(os.environ["CREDENTIALS_DIRECTORY"]) / "config.json")
    except (KeyError, OSError, ValueError, RecursionError):
        LOG.error("Не удалось загрузить конфигурацию службы.")
        return 78
    if not config.token or not config.targets:
        LOG.error("Укажите API-токен и хотя бы один IP-адрес через меню Watchdog.")
        return 78
    LOG.info("Адресов для проверки: %d. Период: %s.", len(config.targets), INTERVALS[config.interval])
    while True:
        retry_after = check_batch(config)
        wake_at = time.monotonic() + max(config.interval, retry_after)
        while (remaining := wake_at - time.monotonic()) > 0:
            time.sleep(min(3600, remaining))


if __name__ == "__main__":
    raise SystemExit(main())
