import fcntl
import ipaddress
import json
import logging
import math
import os
import re
import ssl
import time
import unicodedata
from collections import Counter
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional, Union
from urllib.parse import quote, urlencode


CONFIG_PATH = Path("/etc/cheburcheck-watchdog/config.json")
CHECK_DIR = Path("/run/cheburcheck-watchdog")
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
TELEGRAM_HOST = "api.telegram.org"
TELEGRAM_MESSAGE_LIMIT = 4096
TELEGRAM_MESSAGE_GAP = 4
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
    telegram_token: str = field(default="", repr=False)
    telegram_chat_id: str = ""
    telegram_topic_id: Optional[int] = None


def normalize_target(raw):
    if not isinstance(raw, str) or "%" in raw:
        raise ValueError("Введите публичный IP-адрес или домен.")
    raw = raw.strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return normalize_domain(raw)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError("Для сетевого сканирования нужен публичный IP-адрес.")
    return str(address)


def normalize_domain(raw):
    domain = unicodedata.normalize("NFC", raw.removesuffix(".").lower())
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
        if not domain.isascii() and ascii_domain.encode("ascii").decode("idna") != domain:
            raise ValueError("Введите этот домен в формате Punycode.")
    except UnicodeError:
        raise ValueError("Введите полное доменное имя, например example.com.") from None
    labels = ascii_domain.split(".")
    if (len(ascii_domain) > 253 or len(labels) < 2 or labels[-1].isdigit() or
            any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
        raise ValueError("Введите полное доменное имя, например example.com.")
    return ascii_domain


def is_domain(target):
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return True
    return False


def valid_token(token):
    return isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,1024}", token)


def valid_telegram_token(token):
    return isinstance(token, str) and re.fullmatch(r"[0-9]{1,20}:[A-Za-z0-9_-]{1,128}", token)


def normalize_chat_id(value):
    if isinstance(value, str):
        if re.fullmatch(r"-?[1-9][0-9]{0,15}", value) and abs(int(value)) < 2**52:
            return value
        if re.fullmatch(r"@[A-Za-z0-9_]{1,32}", value):
            return value.lower()
    raise ValueError("Укажите числовой Chat ID или @username группы либо канала.")


def normalize_topic_id(value):
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,10}", value):
        value = int(value)
    if type(value) is not int or not 0 < value < 2**31:
        raise ValueError("Укажите Topic ID от 1 до 2147483647.")
    return value


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
    telegram_token = data.get("telegram_token", "")
    telegram_chat_id = data.get("telegram_chat_id", "")
    telegram_topic_id = data.get("telegram_topic_id")
    if (token != "" and not valid_token(token)) or not isinstance(targets, list):
        raise ValueError("Некорректный токен Cheburcheck или список проверок в конфигурации.")
    if type(interval) is not int or interval not in INTERVALS:
        raise ValueError("Некорректный период проверки в конфигурации.")
    if telegram_token != "" or telegram_chat_id != "" or telegram_topic_id is not None:
        if not valid_telegram_token(telegram_token):
            raise ValueError("Некорректный токен бота Telegram в конфигурации.")
        telegram_chat_id = normalize_chat_id(telegram_chat_id)
        if telegram_topic_id is not None:
            telegram_topic_id = normalize_topic_id(telegram_topic_id)
    return Config(token, tuple(dict.fromkeys(map(normalize_target, targets))), interval,
                  telegram_token, telegram_chat_id, telegram_topic_id)


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


@dataclass
class CheckResult:
    target: str
    blocked: Optional[bool] = None
    scanners: str = ""
    scanner_warning: bool = False
    error: Optional[Union[APIError, ResponseError]] = None


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
def request(stage, path, media_type, *, token=None, host=API_HOST, body=None):
    headers = {"Accept": media_type, "User-Agent": "Cheburcheck-Watchdog"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        with closing(HTTPSConnection(host, timeout=20, context=ssl.create_default_context())) as connection:
            connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
            with connection.getresponse() as response:
                if response.status != 200:
                    raise APIError(stage, response.status, retry_delay(response.getheader("Retry-After")))
                if response.headers.get_content_type() != media_type:
                    raise ResponseError(f"{stage}: неожиданный тип ответа")
                yield response
    except (OSError, HTTPException) as error:
        raise ResponseError(f"{stage}: сбой соединения ({type(error).__name__})") from None


def decode_object(raw, stage):
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise ResponseError(f"{stage}: некорректный JSON") from None
    if not isinstance(data, dict):
        raise ResponseError(f"{stage}: ожидался объект JSON")
    return data


def read_json(response, stage):
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ResponseError(f"{stage}: превышен размер ответа")
    return decode_object(raw, stage)


def check_lists(target):
    stage = "Проверка по спискам"
    query = urlencode({"target": target})
    with request(stage, f"{API_ROOT}/check?{query}", "application/json") as response:
        result = read_json(response, stage)
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


def scan_target(context_id, token):
    path = f"{API_ROOT}/probe/" + quote(context_id, safe="")
    results = {}
    with request("Сканеры", path, "text/event-stream", token=token) as response:
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
    report = CheckResult(target)
    try:
        lists = check_lists(target)
        report.blocked = lists["blocked"]
        LOG.log(logging.WARNING if report.blocked else logging.INFO, "%s — по спискам: %s", target,
                "найдена блокировка" if report.blocked else "блокировка не найдена")
        context_id = lists.get("id")
        if not isinstance(context_id, str) or not context_id:
            raise ResponseError("Контекст для сетевых сканеров недоступен")
        results, received, online = scan_target(context_id, token)
    except (APIError, ResponseError) as error:
        report.error = error
        LOG.warning("%s — %s", target, error)
        return report

    counts = Counter()
    for result in results.values():
        counts.update({verdict for verdict in result["verdicts"]
                       if isinstance(verdict, str) and verdict in VERDICTS})
    summary = ", ".join(f"{VERDICTS[verdict]}: {counts[verdict]}"
                        for verdict in VERDICTS if counts[verdict]) or "вердиктов нет"
    cached = sum(result.get("cached") is True for result in results.values())
    incomplete = not results or received < online or received != len(results)
    report.scanners = f"{len(results)} из {online}, из кеша: {cached}. {summary}"
    if incomplete:
        report.scanners += " (неполный результат)"
    report.scanner_warning = incomplete or any(
        counts[key] for key in ("uncertain", "cdn_block", "sni_block", "dns_spoofing", "tspu_block")
    )
    level = logging.WARNING if report.scanner_warning else logging.INFO
    LOG.log(level, "%s — сканеры: %s", target, report.scanners)
    return report


def send_telegram(token, chat_id, text, *, topic_id=None):
    message = {
        "chat_id": chat_id if chat_id.startswith("@") else int(chat_id),
        "text": text,
        "link_preview_options": {"is_disabled": True},
    }
    if topic_id is not None and topic_id != 1:
        message["message_thread_id"] = topic_id
    body = json.dumps(message, ensure_ascii=False).encode("utf-8")
    with request("Telegram", f"/bot{token}/sendMessage", "application/json",
                 host=TELEGRAM_HOST, body=body) as response:
        result = read_json(response, "Telegram")
    if result.get("ok") is not True:
        raise ResponseError("Telegram не подтвердил отправку сообщения")


def report_messages(reports, total, notice, *, manual):
    time_label = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    label = "Разовая проверка" if manual else "Проверка по расписанию"
    header = (f"🛡 Cheburcheck Watchdog\n🕒 {label} · {time_label}"
              f"\n🔎 Целей обработано: {len(reports)} из {total}")
    if notice:
        header += f"\n⚠️ {notice}"
    message = header
    for report in reports:
        lines = [f"🌐 {report.target}"]
        if report.blocked is not None:
            lines.append("🚫 По спискам: найдена блокировка" if report.blocked
                         else "✅ По спискам: блокировка не найдена")
        if report.scanners:
            icon = "⚠️" if report.scanner_warning else "📡"
            lines.append(f"{icon} Сканеры: {report.scanners}")
        if report.error:
            lines.append(f"⚠️ {report.error}")
        block = "\n\n" + "\n".join(lines)
        if len((message + block).encode("utf-16-le")) // 2 > TELEGRAM_MESSAGE_LIMIT:
            yield message
            message = header
        message += block
    yield message


@contextmanager
def check_lock(*, wait):
    if not wait:
        CHECK_DIR.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(CHECK_DIR, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ResponseError("Уже выполняется проверка. Повторите попытку после её завершения.") from None
        yield
    finally:
        os.close(fd)


def check_batch(config, *, manual=False):
    reports = []
    delay = 0
    notice = ""
    for index, target in enumerate(config.targets):
        if index:
            time.sleep(BETWEEN_TARGETS)
        report = check_target(target, config.token)
        if config.telegram_token:
            reports.append(report)
        error = report.error
        if isinstance(error, APIError):
            if error.status == 429:
                delay = max(config.interval, error.retry_after)
                notice = f"Лимит Cheburcheck. Следующий цикл не ранее чем через {delay} сек."
                LOG.warning("%s", notice)
                break
            if error.status == 401 and error.stage == "Сканеры":
                notice = "Проверьте API-токен cheburcheck.ru и его срок действия."
                LOG.warning("%s", notice)
                break
    if reports:
        try:
            for index, message in enumerate(report_messages(reports, len(config.targets), notice, manual=manual)):
                if index:
                    time.sleep(TELEGRAM_MESSAGE_GAP)
                send_telegram(config.telegram_token, config.telegram_chat_id, message,
                              topic_id=config.telegram_topic_id)
        except (APIError, ResponseError) as error:
            if manual:
                raise ResponseError(f"Проверка завершена. Не удалось отправить отчёт. {error}") from None
            LOG.warning("Не удалось отправить отчёт: %s", error)
    return delay


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        config = load_config(Path(os.environ["CREDENTIALS_DIRECTORY"]) / "config.json")
    except (KeyError, OSError, ValueError, RecursionError):
        LOG.error("Не удалось загрузить конфигурацию службы.")
        return 78
    if not config.token or not config.targets:
        LOG.error("Укажите API-токен и добавьте хотя бы один IP-адрес или домен через меню Watchdog.")
        return 78
    LOG.info("Целей для проверки: %d. Период: %s.", len(config.targets), INTERVALS[config.interval])
    while True:
        with check_lock(wait=True):
            retry_after = check_batch(config)
        wake_at = time.monotonic() + max(config.interval, retry_after)
        while (remaining := wake_at - time.monotonic()) > 0:
            time.sleep(min(3600, remaining))


if __name__ == "__main__":
    raise SystemExit(main())
