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
STATE_DIR = Path("/var/lib/cheburcheck-watchdog")
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
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SSE_TIMEOUT = 180
SSE_READ_TIMEOUT = 90
# Cheburcheck 1.6.3 uses this order for each scanner's vote and for ties.
VERDICTS = {
    "tspu_block": "ТСПУ блок",
    "sni_block": "SNI блок",
    "dns_spoofing": "Подмена DNS",
    "whitelist": "Исключение для CDN",
    "cdn_block": "CDN блок (16–20 КБ)",
    "ok": "Доступен",
    "uncertain": "Неясно",
}
BLOCKING_VERDICTS = {"tspu_block", "sni_block", "dns_spoofing", "cdn_block"}
VERDICT_STATUS = {
    "blocked": ("🚫", "Заблокирован по спискам Cheburcheck"),
    "tspu_block": ("🚫", "Заблокирован — TCP на уровне ТСПУ"),
    "sni_block": ("🚫", "Заблокирован — по имени домена в SNI"),
    "dns_spoofing": ("🚫", "Заблокирован — подмена DNS"),
    "cdn_block": ("🚫", "Недоступен — ограничение CDN (16–20 КБ)"),
    "whitelist": ("🟡", "Исключение для CDN"),
    "ok": ("✅", "Ограничений не обнаружено сканерами"),
    "uncertain": ("⚠️", "Недостаточно данных"),
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
    write_json(vars(config), path)


def write_json(data, path, *, mode=0o600):
    path.parent.mkdir(mode=0o700, exist_ok=True)
    staged = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            staged = Path(stream.name)
            json.dump(data, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if mode != 0o600:
            staged.chmod(mode)
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
class ProbeScan:
    results: dict = field(default_factory=dict)
    online: Optional[int] = None
    received: Optional[int] = None
    error: Optional[ResponseError] = None


@dataclass
class CheckResult:
    target: str
    blocked: Optional[bool] = None
    verdict: str = "uncertain"
    scanners: str = ""
    incomplete: bool = False
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
def request(stage, path, media_type, *, token=None, host=API_HOST, body=None, timeout=20, statuses=(200,)):
    headers = {"Accept": media_type, "User-Agent": "Cheburcheck-Watchdog"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        with closing(HTTPSConnection(host, timeout=timeout, context=ssl.create_default_context())) as connection:
            connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
            with connection.getresponse() as response:
                if response.status not in statuses:
                    raise APIError(stage, response.status, retry_delay(response.getheader("Retry-After")))
                if response.headers.get_content_type() != media_type:
                    raise ResponseError(f"{stage}: неожиданный тип ответа")
                yield response
    except TimeoutError:
        raise ResponseError(f"{stage}: истекло время ожидания данных") from None
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
    while time.monotonic() < deadline:
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
    raise ResponseError("Сканеры: истекло время ожидания события done")


def scan_target(context_id, token):
    path = f"{API_ROOT}/probe/" + quote(context_id, safe="")
    scan = ProbeScan()
    try:
        with request("Сканеры", path, "text/event-stream", token=token, timeout=SSE_READ_TIMEOUT) as response:
            for event, raw in sse_events(response):
                if event == "result":
                    result = decode_object(raw, "Ответ сканера")
                    probe_id = result.get("probe_id")
                    if type(probe_id) not in (str, int) or not isinstance(result.get("verdicts"), list):
                        raise ResponseError("Сканеры: некорректный результат")
                    scan.results[str(probe_id)] = result
                elif event in ("started", "done"):
                    status = decode_object(raw, "Статус сканирования")
                    online = status.get("online_probes")
                    if type(online) is not int or online < 0:
                        raise ResponseError("Сканеры: отсутствует число ожидаемых ответов")
                    scan.online = online
                    if event == "done":
                        received = status.get("response_count")
                        if type(received) is not int or received < 0:
                            raise ResponseError("Сканеры: отсутствует итоговое число ответов")
                        scan.received = received
                        return scan
        raise ResponseError("Сканеры: поток SSE закрылся до события done")
    except ResponseError as error:
        if scan.online is None and not scan.results:
            raise
        scan.error = error
    return scan


def count_scanner_verdicts(results, listed_cdn):
    counts = Counter()
    votes = Counter()
    for result in results:
        verdicts = {code for code in result["verdicts"] if isinstance(code, str) and code in VERDICTS}
        if not listed_cdn and "cdn_block" in verdicts:
            verdicts.remove("cdn_block")
            verdicts.add("ok")
        if listed_cdn and not result.get("cdn_unblocked") and result.get("host_results") != [] and "ok" in verdicts:
            verdicts.add("cdn_block")
        if verdicts & BLOCKING_VERDICTS:
            verdicts.discard("ok")
        counts.update(verdicts)
        vote = next((code for code in VERDICTS if code in verdicts), None)
        if vote is not None:
            votes[vote] += 1
    winner = max(VERDICTS, key=votes.__getitem__)
    return counts, winner if votes[winner] and winner != "uncertain" else None


def check_target(target, token):
    report = CheckResult(target)
    try:
        lists = check_lists(target)
        report.blocked = lists["blocked"]
        LOG.log(logging.WARNING if report.blocked else logging.INFO, "%s — по спискам: %s", target,
                "есть совпадение" if report.blocked else "совпадений нет")
        if isinstance(lists.get("whitelist"), dict) and not lists.get("rkn_domain"):
            report.verdict = "whitelist"
        elif report.blocked:
            report.verdict = "blocked"
        context_id = lists.get("id")
        if not isinstance(context_id, str) or not context_id:
            raise ResponseError("Контекст для сетевых сканеров недоступен")
        scan = scan_target(context_id, token)
    except (APIError, ResponseError) as error:
        report.error = error
        LOG.warning("%s — %s", target, error)
        return report

    results = scan.results.values()
    total = len(results)
    counts, winner = count_scanner_verdicts(results, listed_cdn=bool(lists.get("cdn_providers")))
    report.verdict = winner or report.verdict
    report.incomplete = scan.received is None or not (total == scan.received == scan.online)
    report.error = scan.error
    cached = sum(result.get("cached") is True for result in results)
    answer_count = f"{total} из {scan.online}" if scan.online is not None else str(total)
    report.scanners = f"{answer_count} ответов, из кеша: {cached}"
    if report.incomplete:
        report.scanners += " (неполный результат)"
    if scan.received is not None and scan.received < scan.online:
        report.scanners += ". API завершил ожидание остальных сканеров"
    if scan.received is not None and scan.received != total:
        report.scanners += f". Число ответов по данным API: {scan.received}"
    if counts:
        summary = ", ".join(f"{VERDICTS[code]}: {counts[code]}/{total}" for code in VERDICTS if counts[code])
        report.scanners += f". {summary}"
    level = logging.WARNING if report.incomplete or counts.keys() & BLOCKING_VERDICTS else logging.INFO
    LOG.log(level, "%s — %s. Сканеры API: %s", target, VERDICT_STATUS[report.verdict][1], report.scanners)
    if report.error:
        LOG.warning("%s — %s", target, report.error)
    return report


def send_telegram(token, chat_id, text, *, topic_id=None, message_id=None):
    message = {
        "chat_id": chat_id if chat_id.startswith("@") else int(chat_id),
        "text": text,
        "link_preview_options": {"is_disabled": True},
    }
    method = "sendMessage"
    statuses = (200,)
    if message_id is not None:
        method = "editMessageText"
        statuses = (200, 400)
        message["message_id"] = message_id
    elif topic_id is not None and topic_id != 1:
        message["message_thread_id"] = topic_id
    body = json.dumps(message, ensure_ascii=False).encode("utf-8")
    with request("Telegram", f"/bot{token}/{method}", "application/json",
                 host=TELEGRAM_HOST, body=body, statuses=statuses) as response:
        result = read_json(response, "Telegram")
        if response.status == 400:
            description = str(result.get("description", "")).lower().removeprefix("bad request: ")
            if description.partition(":")[0] == "message is not modified":
                return True
            if description in ("message to edit not found", "message_id_invalid"):
                return None
            raise APIError("Telegram", response.status)
    if result.get("ok") is not True:
        raise ResponseError("Telegram не подтвердил отправку сообщения")
    return result.get("result", True)


def publish_report(config, text):
    path = STATE_DIR / "telegram-report.json"
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    destination = [config.telegram_token.partition(":")[0], config.telegram_chat_id,
                   None if config.telegram_topic_id == 1 else config.telegram_topic_id]
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        state = {}
    except (ValueError, RecursionError):
        raise ResponseError("Некорректный файл состояния отчёта Telegram") from None
    if not isinstance(state, dict):
        raise ResponseError("Некорректный файл состояния отчёта Telegram")
    if state.get("destination") == destination:
        message_id = state.get("message_id")
        chat_id = state.get("chat_id")
        if type(message_id) is not int or message_id <= 0 or type(chat_id) is not int or chat_id == 0:
            raise ResponseError("Некорректный идентификатор сохранённого отчёта Telegram")
        if send_telegram(config.telegram_token, str(chat_id), text, message_id=message_id) is not None:
            return

    message = send_telegram(config.telegram_token, config.telegram_chat_id, text, topic_id=config.telegram_topic_id)
    if not isinstance(message, dict) or not isinstance(message.get("chat"), dict):
        raise ResponseError("Telegram не вернул данные отправленного отчёта")
    message_id = message.get("message_id")
    chat_id = message["chat"].get("id")
    if type(message_id) is not int or message_id <= 0 or type(chat_id) is not int or chat_id == 0:
        raise ResponseError("Telegram не вернул идентификатор отправленного отчёта")
    # The admin and the DynamicUser both read this file inside the private state directory.
    write_json({"destination": destination, "chat_id": chat_id, "message_id": message_id}, path, mode=0o644)


def telegram_length(text):
    return len(text.encode("utf-16-le")) // 2


def report_message(reports, total, notice, *, manual):
    time_label = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    label = "Разовая проверка" if manual else "Проверка по расписанию"
    header = (f"🛡 Cheburcheck Watchdog\n🕒 {label} · {time_label}"
              f"\n🔎 Целей обработано: {len(reports)} из {total}")
    if notice:
        header += f"\n⚠️ {notice}"
    blocks = []
    compact = []
    for report in reports:
        lines = [f"🌐 {report.target}"]
        verdict_icon, status = VERDICT_STATUS[report.verdict]
        label = "Итог по полученным данным" if report.incomplete else "Итог"
        lines.append(f"{verdict_icon} {label}: {status}")
        if report.blocked is not None:
            listed = "есть совпадение" if report.blocked else "совпадений нет"
            lines.append(f"📋 Списки Cheburcheck: {listed}")
        if report.scanners:
            icon = "⚠️" if report.incomplete else "📡"
            lines.append(f"{icon} Сканеры API: {report.scanners}")
        if report.error:
            lines.append(f"⚠️ {report.error}")
        blocks.append("\n".join(lines))
        summary = f"{verdict_icon} {report.target} — {status}"
        if report.error:
            summary += f" ({report.error})"
        elif report.incomplete:
            summary += " (неполные данные)"
        compact.append(summary)
    message = "\n\n".join([header, *blocks])
    if telegram_length(message) <= TELEGRAM_MESSAGE_LIMIT:
        return message
    message = header + "\n\n" + "\n".join(compact)
    if telegram_length(message) <= TELEGRAM_MESSAGE_LIMIT:
        return message

    totals = Counter(VERDICT_STATUS[report.verdict][0] for report in reports)
    header += "\n" + " · ".join(f"{icon} {count}" for icon, count in totals.items())
    message = header + "\n"
    for index, line in enumerate(compact):
        footer = f"\n\nСокращено целей: {len(reports) - index}."
        if telegram_length(message + "\n" + line + footer) > TELEGRAM_MESSAGE_LIMIT:
            return message + footer
        message += "\n" + line
    return message


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


def check_batch(config, *, manual=False, update_report=True):
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
            message = report_message(reports, len(config.targets), notice, manual=manual)
            if update_report:
                publish_report(config, message)
            else:
                send_telegram(config.telegram_token, config.telegram_chat_id, message,
                              topic_id=config.telegram_topic_id)
        except (APIError, OSError, ResponseError) as error:
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
