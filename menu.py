import fcntl
import getpass
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

from watchdog import CONFIG_PATH, INTERVALS, load_config, normalize_ip, save_config, valid_token


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
    screen("API-токен Watchdog")
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


def start_watchdog():
    title = "Запустить watchdog"
    if not confirm(title, "Watchdog начнёт проверять настроенные IP через Cheburcheck и будет "
                    "автоматически запускаться при загрузке сервера."):
        return
    if not get_config().token and not token_menu():
        return
    if not get_config().targets:
        print("Добавьте хотя бы один IP-адрес для запуска.")
        input(f"\n{DIM}Enter — открыть список IP-адресов{RESET}")
        ip_menu()
        if not get_config().targets:
            return
    with install_lock():
        config = get_config()
        if not config.token or not config.targets:
            raise ValueError("Укажите токен и хотя бы один IP-адрес.")
        systemctl("enable", "--now", UNIT)
    print("Watchdog запущен.")
    pause()


def stop_watchdog():
    if confirm("Остановить watchdog", "Проверки будут остановлены. Автозапуск при загрузке сервера "
                "будет выключен. Настройки сохранятся."):
        with install_lock():
            systemctl("disable", "--now", UNIT)
        print("Watchdog остановлен.")
        pause()


def add_ip():
    screen("Добавить IP-адрес")
    value = input("Публичный IPv4 или IPv6 (Enter без ввода — назад): ").strip()
    if not value:
        return
    target = normalize_ip(value)

    def add(config):
        if target in config.targets:
            raise ValueError("Этот IP-адрес уже в списке.")
        return replace(config, targets=config.targets + (target,))

    change_config(add)
    print(f"Адрес {target} добавлен.")
    pause()


def edit_ip(target):
    if choose(target, [("remove", "Удалить IP-адрес", RED), BACK], default=1) != "remove":
        return
    if confirm("Удалить IP-адрес", f"Адрес {target} будет удалён из списка проверок. "
               "При удалении последнего адреса watchdog будет остановлен, а автозапуск отключён."):
        change_config(lambda config: replace(config, targets=tuple(ip for ip in config.targets if ip != target)))
        print(f"Адрес {target} удалён.")
        pause()


def ip_menu():
    while True:
        targets = get_config().targets
        items = [(target, target) for target in targets] + [("add", "Добавить IP-адрес"), BACK]
        selected = choose("Проверяемые IP-адреса", items, default=len(targets),
                          detail="Настроенные адреса" if targets else "Список пуст.")
        if selected == "back":
            return
        if selected == "add":
            add_ip()
        else:
            edit_ip(selected)


def interval_menu():
    interval = get_config().interval
    items = list(INTERVALS.items()) + [BACK]
    selected = choose("Период проверки", items, detail=f"Текущий период: {INTERVALS[interval]}",
                      default=list(INTERVALS).index(interval))
    if selected != "back":
        change_config(lambda config: replace(config, interval=selected))
        print(f"Период сохранён: {INTERVALS[selected].lower()}.")
        pause()


def uninstall():
    if not confirm("Удалить Cheburcheck Watchdog", "Служба будет остановлена и удалена вместе с командой "
                   "cheburcheck-watchdog, списком адресов, периодом проверки и API-токеном."):
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
        shutil.rmtree(APP_DIR)
    print("Cheburcheck Watchdog удалён.")
    return True


def main(update_notice=""):
    items = [
        ("start", "Запустить watchdog"),
        ("stop", "Остановить watchdog"),
        ("token", "API-токен Watchdog"),
        ("ip", "Проверяемые IP-адреса"),
        ("interval", "Период проверки"),
        ("uninstall", "Удалить Cheburcheck Watchdog", RED),
        ("back", "Выход", BLUE),
    ]
    actions = {"start": start_watchdog, "stop": stop_watchdog, "ip": ip_menu, "interval": interval_menu}

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
        except (ValueError, RecursionError) as error:
            print(f"{RED}[x]{RESET} {error}")
            pause()
        update_notice = ""


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) > 1 else "")
    except (EOFError, KeyboardInterrupt):
        print()
