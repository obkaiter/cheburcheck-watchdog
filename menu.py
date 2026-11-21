import fcntl
import getpass
import math
import os
import select
import shutil
import subprocess
import sys
import termios
import tty
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from watchdog import (
    APIError,
    CHECK_DIR,
    CONFIG_PATH,
    CheckInProgress,
    INTERVALS,
    STATE_DIR,
    ResponseError,
    check_batch,
    check_delay,
    check_lock,
    is_domain,
    load_config,
    normalize_chat_id,
    normalize_target,
    normalize_topic_id,
    save_config,
    send_telegram,
    valid_telegram_token,
    valid_token,
    wait_for_next_check,
)


APP_DIR = Path("/opt/cheburcheck-watchdog")
COMMAND_LINK = Path("/usr/local/bin/cheburcheck-watchdog")
UNIT = "cheburcheck-watchdog.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT
LOCK_FILE = Path("/run/lock/cheburcheck-watchdog.lock")
VERSION = Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
BLUE = "\033[34m"
DIM = "\033[2m"
BACK = ("back", "Назад", BLUE)
TOKEN_TITLE = "API-токен cheburcheck.ru"
TELEGRAM_TITLE = "Отчёты в Telegram"


def screen(title=None):
    print(f"\033[2J\033[H\033[1;36mCheburcheck Watchdog{RESET} v{VERSION}")
    print(f"{DIM}Автор: github.com/obkaiter\nПри поддержке BITWIRE.ME{RESET}\n")
    if title:
        print(f"\033[1m{title}{RESET}\n")


def read_key(fd, timeout):
    def read(wait):
        return os.read(fd, 1) if select.select([fd], [], [], wait)[0] else None

    key = read(timeout)
    if key != b"\x1b":
        return key
    if read(0.15) not in (b"[", b"O"):
        return b"\x1b"
    while True:
        key = read(0.15)
        if not key or not b" " <= key <= b"?":
            return b"\x1b" + (key or b"")


def choose(title, items, *, detail=None, default=0, numbered=False):
    fd = sys.stdin.fileno()
    attributes = termios.tcgetattr(fd)
    selected = default
    refresh_status = callable(detail)
    message = detail() if refresh_status else detail
    try:
        tty.setcbreak(fd)
        while True:
            screen(title)
            detail_lines = 0
            if message:
                print(message, "\n", sep="")
                detail_lines = 2 + message.count("\n")
            height = shutil.get_terminal_size((80, 24)).lines
            visible = max(1, height - 7 - 2 * bool(title) - detail_lines)
            first = min(max(0, selected - visible + 1), max(0, len(items) - visible))
            for index in range(first, min(len(items), first + visible)):
                item = items[index]
                pointer = f"{GREEN}→{RESET}" if index == selected else " "
                number = f"{index + 1}. " if numbered else ""
                color = item[2] if len(item) == 3 else ""
                print(f"  {pointer} {color}{number}{item[1]}{RESET}")
            hint = "↑/↓ — перемещение, Enter — выбрать"
            if len(items) > visible:
                hint += f"  ({selected + 1}/{len(items)})"
            print(f"{DIM}{hint}{RESET}", flush=True)

            while True:
                key = read_key(fd, 3 if refresh_status else None)
                if key is None:
                    latest = detail()
                    if latest != message:
                        message = latest
                        break
                    continue
                if key in (b"\n", b"\r"):
                    return items[selected][0]
                if key in (b"", b"\x04"):
                    return "back"
                if key == b"\x1bA":
                    selected = (selected - 1) % len(items)
                    break
                if key == b"\x1bB":
                    selected = (selected + 1) % len(items)
                    break
                if numbered and key and key in b"123456789" and int(key) <= len(items):
                    selected = int(key) - 1
                    break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, attributes)


def pause():
    input(f"\n{DIM}Enter — вернуться в меню{RESET}")


def confirm(title, description):
    screen(title)
    print(description)
    return input(f"\n{DIM}Enter — подтвердить, 0 — назад: {RESET}").strip() == ""


def systemctl(*args):
    subprocess.run(["systemctl", *args], check=True)


def is_active():
    return subprocess.run(["systemctl", "is-active", "--quiet", UNIT]).returncode == 0


def service_status():
    if is_active():
        return f"Статус: {GREEN}работает{RESET}"
    return f"Статус: {RED}остановлен{RESET}"


@contextmanager
def install_lock():
    with LOCK_FILE.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        if not (APP_DIR / "VERSION").is_file():
            raise ValueError("Cheburcheck Watchdog уже удалён.")
        yield


def get_config():
    return load_config(allow_missing=True)


def change_config(change):
    with install_lock():
        current = get_config()
        updated = change(current)
        if updated != current:
            save_config(updated)
            if not updated.targets and current.targets:
                systemctl("disable", "--now", UNIT)
            elif updated.targets and updated.token:
                systemctl("try-restart", UNIT)


def token_menu():
    screen(TOKEN_TITLE)
    print("Токен сохранён." if get_config().token else "Токен ещё не задан.")
    print("Ввод скрыт. Enter без ввода — назад.\n")
    token = getpass.getpass("API-токен: ").strip()
    if not token:
        return False
    if not valid_token(token):
        raise ValueError("Токен содержит недопустимые символы.")
    change_config(lambda config: replace(config, token=token))
    print("Токен сохранён.")
    return True


def configure_telegram(config):
    screen("Настроить отчёты в Telegram")
    print("Добавьте бота в нужный чат и разрешите ему отправлять сообщения.\n")
    hint = "Enter — оставить сохранённый" if config.telegram_token else "Enter без ввода — назад"
    token = getpass.getpass(f"Токен бота ({hint}): ").strip() or config.telegram_token
    if not token:
        return
    if not valid_telegram_token(token):
        raise ValueError("Введите токен бота в формате, который выдаёт @BotFather.")
    hint = f"Enter — оставить {config.telegram_chat_id}" if config.telegram_chat_id else "Enter без ввода — назад"
    chat_id = input(f"Chat ID или @username ({hint}): ").strip() or config.telegram_chat_id
    if not chat_id:
        return
    chat_id = normalize_chat_id(chat_id)
    topic_id = config.telegram_topic_id if chat_id == config.telegram_chat_id else None
    hint = f"Enter — оставить {topic_id}, 0 — сбросить" if topic_id is not None else "Enter — пропустить"
    topic_input = input(f"Topic ID ({hint}): ").strip()
    if topic_input == "0":
        topic_id = None
    elif topic_input:
        topic_id = normalize_topic_id(topic_input)
    change_config(lambda current: replace(current, telegram_token=token, telegram_chat_id=chat_id,
                                          telegram_topic_id=topic_id))
    print("Отчёты в Telegram включены.")
    pause()


def telegram_destination(config):
    destination = config.telegram_chat_id
    if config.telegram_topic_id is not None:
        destination += f" · тема {config.telegram_topic_id}"
    return destination


def telegram_menu():
    while True:
        config = get_config()
        items = [("configure", "Настроить бота и чат")]
        detail = "Отчёты отключены."
        if config.telegram_token:
            detail = f"Чат для отчётов: {telegram_destination(config)}"
            items.extend([("test", "Отправить тестовое сообщение"),
                          ("disable", "Отключить отчёты", RED)])
        selected = choose(TELEGRAM_TITLE, items + [BACK], detail=detail)
        if selected == "back":
            return
        try:
            if selected == "configure":
                configure_telegram(config)
            elif selected == "test" and confirm("Отправить тестовое сообщение",
                                                f"Watchdog отправит сообщение в чат {telegram_destination(config)}."):
                send_telegram(config.telegram_token, config.telegram_chat_id,
                              "🛡 Cheburcheck Watchdog\n✅ Тестовое сообщение. Доставка отчётов работает.",
                              topic_id=config.telegram_topic_id)
                print("Тестовое сообщение отправлено.")
                pause()
            elif selected == "disable" and confirm("Отключить отчёты", "Настройки Telegram будут удалены. "
                                                   "Проверки продолжат записываться в журнал."):
                change_config(lambda current: replace(current, telegram_token="", telegram_chat_id="",
                                                      telegram_topic_id=None))
                print("Отчёты в Telegram отключены.")
                pause()
        except (APIError, ResponseError, ValueError) as error:
            print(f"{RED}[x]{RESET} {error}")
            pause()


def start_watchdog():
    if not confirm("Запустить", "Watchdog начнёт проверять настроенные IP-адреса и домены через Cheburcheck. "
                   "Служба будет запускаться при загрузке сервера."):
        return
    if not get_config().token and not token_menu():
        return
    if not get_config().targets:
        print("Добавьте хотя бы один IP-адрес или домен для запуска.")
        input(f"\n{DIM}Enter — открыть список проверок{RESET}")
        targets_menu()
        if not get_config().targets:
            return
    with install_lock():
        config = get_config()
        if not config.token or not config.targets:
            raise ValueError("Укажите токен и добавьте хотя бы один IP-адрес или домен.")
        systemctl("enable", "--now", UNIT)
    print("Watchdog запущен.")
    pause()


def stop_watchdog():
    if confirm("Остановить", "Проверки будут остановлены. Автозапуск при загрузке сервера "
                "будет выключен. Настройки сохранятся."):
        with install_lock():
            systemctl("disable", "--now", UNIT)
        print("Watchdog остановлен.")
        pause()


def add_target():
    screen("Добавить IP-адрес или домен")
    value = input("Публичный IPv4, IPv6 или домен (Enter без ввода — назад): ").strip()
    if not value:
        return
    target = normalize_target(value)

    def add(config):
        if target in config.targets:
            raise ValueError("Этот IP-адрес или домен уже в списке.")
        return replace(config, targets=config.targets + (target,))

    change_config(add)
    print(f"{target} добавлен в список проверок.")
    pause()


def edit_target(target):
    if choose(target, [("remove", "Удалить из списка", RED), BACK], default=1) != "remove":
        return
    if confirm("Удалить из списка", f"{target} будет удалён из списка проверок. "
               "Если список опустеет, служба остановится, а автозапуск отключится."):
        change_config(lambda config: replace(config, targets=tuple(item for item in config.targets if item != target)))
        print(f"{target} удалён из списка проверок.")
        pause()


def targets_menu():
    while True:
        targets = get_config().targets
        items = [(target, target) for target in targets] + [("add", "Добавить IP-адрес или домен"), BACK]
        selected = choose("Проверяемые IP и домены", items, default=len(targets),
                          detail=None if targets else "Список пуст.")
        if selected == "back":
            return
        try:
            if selected == "add":
                add_target()
            else:
                edit_target(selected)
        except ValueError as error:
            print(f"{RED}[x]{RESET} {error}")
            pause()


def interval_menu():
    interval = get_config().interval
    items = list(INTERVALS.items()) + [BACK]
    selected = choose("Период проверки", items, detail=f"Текущий период: {INTERVALS[interval]}",
                      default=list(INTERVALS).index(interval))
    if selected != "back":
        change_config(lambda config: replace(config, interval=selected))
        print(f"Период сохранён: {INTERVALS[selected].lower()}.")
        pause()


def manual_check_menu():
    config = get_config()
    domains = tuple(target for target in config.targets if is_domain(target))
    if not domains:
        screen("Разовая проверка")
        print("Добавьте домен в разделе «Проверяемые IP и домены».")
        pause()
        return
    items = [("all", f"Все домены ({len(domains)})")]
    items.extend((domain, domain) for domain in domains)
    selected = choose("Разовая проверка", items + [BACK], default=len(items))
    if selected == "back":
        return
    if not config.token and not token_menu():
        return
    if not config.telegram_token:
        configure_telegram(config)

    config = get_config()
    if not config.token or not config.telegram_token:
        return
    targets = tuple(
        target for target in config.targets if is_domain(target) and (selected == "all" or target == selected)
    )
    if not targets:
        raise ValueError("Выбранных доменов больше нет в списке проверок.")
    all_domains = selected == "all"
    destination = telegram_destination(config)
    if all_domains:
        description = f"Будут проверены все сохранённые домены. Общий отчёт в чате {destination} обновится."
    else:
        description = f"Будет проверен {selected}. Отчёт будет отправлен в чат {destination}."
    if not confirm("Разовая проверка", description):
        return
    wait = False
    while True:
        try:
            with check_lock(wait=wait), install_lock():
                if get_config() != config:
                    raise ResponseError("Настройки изменились. Запустите разовую проверку ещё раз.")
                if wait and (remaining := math.ceil(check_delay())) > 0:
                    print(f"До следующего запроса к Cheburcheck осталось {remaining} сек.", flush=True)
                wait_for_next_check(wait=wait)
                print("Выполняется проверка…", flush=True)
                check_batch(replace(config, targets=targets), manual=True, update_report=all_domains)
            break
        except CheckInProgress:
            if not confirm("Уже выполняется цикл проверок", "Разовая проверка начнётся после текущего цикла "
                           "и обязательной паузы Cheburcheck. Оставьте меню открытым."):
                return
            print("Ожидаю завершения текущего цикла. Ctrl+C — отменить ожидание.", flush=True)
            wait = True
    print("Общий отчёт в Telegram обновлён." if all_domains else "Отчёт о проверке отправлен в Telegram.")
    pause()


def uninstall():
    if not confirm("Удалить Cheburcheck Watchdog", "Служба будет остановлена и удалена вместе с командой "
                   "cheburcheck-watchdog, настройками и сохранёнными токенами."):
        return False
    with install_lock():
        if UNIT_PATH.exists():
            systemctl("disable", "--now", UNIT)
            UNIT_PATH.unlink()
        elif is_active():
            systemctl("stop", UNIT)
        systemctl("daemon-reload")
        if COMMAND_LINK.is_symlink() and COMMAND_LINK.readlink() == APP_DIR / "cheburcheck-watchdog":
            COMMAND_LINK.unlink()
        if CONFIG_PATH.parent.exists():
            shutil.rmtree(CONFIG_PATH.parent)
        if CHECK_DIR.exists():
            CHECK_DIR.rmdir()
        if STATE_DIR.is_symlink():
            STATE_DIR.unlink()
        for path in (STATE_DIR, STATE_DIR.parent / "private" / STATE_DIR.name):
            if path.is_dir():
                shutil.rmtree(path)
        shutil.rmtree(APP_DIR)
    print("Cheburcheck Watchdog удалён.")
    return True


def main(update_notice=""):
    items = [
        ("start", "Запустить"),
        ("stop", "Остановить"),
        ("token", TOKEN_TITLE),
        ("telegram", TELEGRAM_TITLE),
        ("targets", "Проверяемые IP и домены"),
        ("interval", "Период проверки"),
        ("manual", "Разовая проверка"),
        ("uninstall", "Удалить Cheburcheck Watchdog", RED),
        ("back", "Выход", BLUE),
    ]
    actions = {"start": start_watchdog, "stop": stop_watchdog, "telegram": telegram_menu,
               "targets": targets_menu, "interval": interval_menu, "manual": manual_check_menu}

    def detail():
        status = service_status()
        return f"{status}\n{DIM}{update_notice}{RESET}" if update_notice else status

    default = 0
    while True:
        selected = choose(None, items, detail=detail, default=default, numbered=True)
        if selected == "back":
            return
        default = next(index for index, item in enumerate(items) if item[0] == selected)
        try:
            if selected in actions:
                actions[selected]()
            elif selected == "token":
                if token_menu():
                    pause()
            elif selected == "uninstall" and uninstall():
                return
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"{RED}[x]{RESET} Операция не завершена: {error}")
            pause()
        except (APIError, ResponseError, ValueError, RecursionError) as error:
            print(f"{RED}[x]{RESET} {error}")
            pause()
        update_notice = ""


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) > 1 else "")
    except (EOFError, KeyboardInterrupt):
        print()
