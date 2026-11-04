import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor
import threading
import platform

INPUT_FILE = "cidrs.txt"
OUTPUT_FILE = "working-16-05-2026-beeline.txt"
# На Windows десятки одновременных ping быстро упираются в лимиты процессов/дескрипторов.
THREADS = 64

lock = threading.Lock()

is_windows = platform.system().lower() == "windows"

# CREATE_NO_WINDOW (только Windows) — без отдельного окна на каждый ping.
_SUBPROCESS_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def ping(ip):

    if is_windows:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            creationflags=_SUBPROCESS_FLAGS,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False

    return result.returncode == 0


def _representative_ip(net):
    """Первый «хостовый» адрес сети; для /32 и пустого hosts() — network_address."""
    h = net.hosts()
    try:
        return str(next(h))
    except StopIteration:
        return str(net.network_address)


def check_cidr(cidr, out_fp):

    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        ip = _representative_ip(net)
        cidr_out = net.with_prefixlen
        if ping(ip):
            with lock:
                print("[WORKING]", cidr_out)
                out_fp.write(cidr_out + "\n")
                out_fp.flush()
        else:
            print("[FAIL]", ip)

    except Exception as e:
        print("error:", cidr, e)


def main():

    with open(INPUT_FILE) as f:
        cidrs = [line.strip() for line in f if line.strip()]

    print("CIDRs:", len(cidrs))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out_fp:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            list(executor.map(lambda c: check_cidr(c, out_fp), cidrs))


if __name__ == "__main__":
    main()
