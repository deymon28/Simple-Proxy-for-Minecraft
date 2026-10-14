"""Simple TCP proxy for Minecraft with an IP/CIDR whitelist.

Only clients whose address matches an entry of the whitelist file are forwarded
to the destination server; everyone else is dropped immediately.
"""
import argparse
import datetime
import ipaddress
import json
import logging
import os
import shutil
import signal
import socket
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# === Default configuration (override with command-line options) ===
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 25565
DEST_HOST = '127.0.0.1'
DEST_PORT = 25566
ALLOWED_IPS_FILE = os.path.join(BASE_DIR, 'allowed_ips.json')
LOG_DIR = os.path.join(BASE_DIR, 'logs')
MAX_CONNECTIONS = 200
CONNECT_TIMEOUT = 5.0
IDLE_TIMEOUT = 0.0            # seconds; 0 disables the idle timeout
REJECT_LOG_INTERVAL = 60.0    # log repeated rejections of one IP at most this often
RELOAD_CHECK_INTERVAL = 2.0   # seconds between whitelist file modification checks
BUFFER_SIZE = 65536

logger = logging.getLogger('minecraft_proxy')


# === Logging ===
def setup_logging(log_dir: str):
    """Rotate the previous proxy.log and log to console and file."""
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'proxy.log')
    if os.path.exists(log_file):
        timestamp = datetime.datetime.fromtimestamp(os.path.getmtime(log_file)).strftime('%Y%m%d_%H%M%S')
        shutil.move(log_file, os.path.join(log_dir, f'proxy_{timestamp}.log'))

    formatter = logging.Formatter('[%(asctime)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    logger.setLevel(logging.INFO)
    for handler in (logging.StreamHandler(), logging.FileHandler(log_file, encoding='utf-8')):
        handler.setFormatter(formatter)
        logger.addHandler(handler)


# === IP Whitelist Management ===
class Whitelist:
    """Thread-safe whitelist backed by a JSON list of IPs / CIDR networks."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._networks = []
        self._mtime = None
        self._last_check = 0.0
        self.reload(initial=True)

    @staticmethod
    def _parse(entries):
        return [ipaddress.ip_network(str(entry).strip(), strict=False) for entry in entries]

    def reload(self, initial=False) -> bool:
        """Load the file. On any error the previous list stays active."""
        if not os.path.exists(self.path):
            if initial:
                logger.warning(f"Whitelist file {self.path} not found: nobody is allowed until entries are added")
            return False
        try:
            mtime = os.path.getmtime(self.path)
            with open(self.path, 'r', encoding='utf-8') as f:
                networks = self._parse(json.load(f))
        except (OSError, ValueError, TypeError) as e:
            logger.error(f"Error loading allowed IPs (keeping previous list): {e}")
            return False
        with self._lock:
            self._networks = networks
            self._mtime = mtime
        if not initial:
            logger.info(f"Whitelist reloaded: {len(networks)} entries")
        return True

    def _maybe_reload(self):
        now = time.monotonic()
        if now - self._last_check < RELOAD_CHECK_INTERVAL:
            return
        self._last_check = now
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return
        if mtime != self._mtime:
            self.reload()

    def _save(self):
        # Write atomically so a crash never leaves a truncated file.
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump([str(net) for net in self._networks], f, indent=2)
        os.replace(tmp, self.path)
        self._mtime = os.path.getmtime(self.path)

    def is_allowed(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        self._maybe_reload()
        with self._lock:
            return any(ip_obj.version == net.version and ip_obj in net for net in self._networks)

    def add(self, net_str: str):
        net = ipaddress.ip_network(net_str.strip(), strict=False)
        with self._lock:
            if net in self._networks:
                return net, False
            self._networks.append(net)
            self._save()
        return net, True

    def remove(self, net_str: str):
        net = ipaddress.ip_network(net_str.strip(), strict=False)
        with self._lock:
            if net not in self._networks:
                return net, False
            self._networks.remove(net)
            self._save()
        return net, True

    def list(self):
        with self._lock:
            return list(self._networks)


# === Traffic Forwarding ===
class Pipe:
    """One proxied connection: two forwarding directions sharing both sockets."""

    def __init__(self, client, server, label_c2s, label_s2c, limiter):
        self.client = client
        self.server = server
        self.labels = (label_c2s, label_s2c)
        self.limiter = limiter
        self._remaining = 2
        self._lock = threading.Lock()

    def start(self):
        threading.Thread(target=self._forward, args=(self.client, self.server, self.labels[0]), daemon=True).start()
        threading.Thread(target=self._forward, args=(self.server, self.client, self.labels[1]), daemon=True).start()

    def _forward(self, source, destination, label):
        total_bytes = 0
        start = time.monotonic()
        try:
            while True:
                data = source.recv(BUFFER_SIZE)
                if not data:
                    break
                destination.sendall(data)
                total_bytes += len(data)
        except OSError:
            pass
        finally:
            # Propagate EOF so the peer can finish; fully close once both directions ended.
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            logger.info(f"{label} closed | Bytes: {total_bytes} | Duration: {time.monotonic() - start:.2f}s")
            with self._lock:
                self._remaining -= 1
                done = self._remaining == 0
            if done:
                self.client.close()
                self.server.close()
                self.limiter.release()


# === Handle Client ===
class RejectThrottle:
    """Collapses floods of rejected connections into periodic summary lines."""

    def __init__(self):
        self._lock = threading.Lock()
        self._state = {}  # ip -> [last_logged_monotonic, suppressed_count]

    def check(self, ip):
        """Return the number of attempts to report now, or None to stay silent."""
        now = time.monotonic()
        with self._lock:
            entry = self._state.get(ip)
            if entry is None:
                if len(self._state) > 10000:
                    self._state.clear()
                self._state[ip] = [now, 0]
                return 1
            if now - entry[0] >= REJECT_LOG_INTERVAL:
                count = entry[1] + 1
                entry[0], entry[1] = now, 0
                return count
            entry[1] += 1
            return None


def handle_client(client_sock, client_addr, whitelist, limiter, throttle, dest):
    ip, port = client_addr[0], client_addr[1]

    if not whitelist.is_allowed(ip):
        attempts = throttle.check(ip)
        if attempts is not None:
            logger.info(f"Rejected: {ip} is not in the allowed list | Attempts: {attempts}")
        client_sock.close()
        return

    logger.info(f"Connection attempt from {ip}:{port}")

    if not limiter.acquire(blocking=False):
        logger.warning(f"Rejected: {ip}:{port}, connection limit reached")
        client_sock.close()
        return

    try:
        server_sock = socket.create_connection(dest, timeout=CONNECT_TIMEOUT)
    except OSError as e:
        logger.error(f"Error connecting to destination: {e}")
        client_sock.close()
        limiter.release()
        return

    timeout = IDLE_TIMEOUT if IDLE_TIMEOUT > 0 else None
    for s in (client_sock, server_sock):
        s.settimeout(timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    logger.info(f"Connection from {ip} accepted and forwarded")
    logger.info(f"{ip}:{port} connected -> {dest[0]}:{dest[1]}")
    Pipe(client_sock, server_sock, f"{ip}:{port} -> DEST", f"DEST -> {ip}:{port}", limiter).start()


# === Start Proxy ===
def start_proxy(stop_event, args, whitelist):
    limiter = threading.BoundedSemaphore(args.max_connections)
    throttle = RejectThrottle()
    dest = (args.dest_host, args.dest_port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((args.listen_host, args.listen_port))
        except OSError as e:
            logger.error(f"Cannot bind {args.listen_host}:{args.listen_port}: {e}")
            return False
        s.listen(128)
        logger.info(f"Proxy listening on {args.listen_port} -> {dest[0]}:{dest[1]}")
        s.settimeout(1.0)
        while not stop_event.is_set():
            try:
                client_sock, client_addr = s.accept()
            except socket.timeout:
                continue
            except OSError as e:
                logger.error(f"Accept failed: {e}")
                time.sleep(0.5)
                continue
            threading.Thread(target=handle_client,
                             args=(client_sock, client_addr, whitelist, limiter, throttle, dest),
                             daemon=True).start()
    return True


# === Command Interface ===
HELP = "Available commands: add [ip or cidr], remove [ip or cidr], list, reload, help, stop"


def command_interface(stop_event, whitelist):
    while not stop_event.is_set():
        try:
            cmd = input("> ").strip()
        except EOFError:
            return  # no console attached (e.g. run as a service): keep proxying
        except KeyboardInterrupt:
            stop_event.set()
            return
        if not cmd:
            continue
        action, _, arg = cmd.partition(' ')
        arg = arg.strip()
        try:
            if action == "add" and arg:
                net, changed = whitelist.add(arg)
                if changed:
                    logger.info(f"{net} added to allowed list")
                else:
                    print(f"{net} is already in the allowed list")
            elif action == "remove" and arg:
                net, changed = whitelist.remove(arg)
                if changed:
                    logger.info(f"{net} removed from allowed list")
                else:
                    print(f"{net} not found in allowed list")
            elif action == "list":
                print("Allowed IPs / Networks:")
                for net in whitelist.list():
                    print(" -", net)
            elif action == "reload":
                if not whitelist.reload():
                    print("Reload failed or file missing; see log")
            elif action in ("exit", "quit", "stop"):
                logger.info("Stopping server via command")
                stop_event.set()
                return
            else:
                print(HELP)
        except ValueError:
            print(f"Invalid IP or network format: {arg}")
        except OSError as e:
            logger.error(f"Cannot save allowed list: {e}")


# === Main ===
def parse_args():
    p = argparse.ArgumentParser(description="Simple whitelist TCP proxy for Minecraft")
    p.add_argument('--listen-host', default=LISTEN_HOST)
    p.add_argument('--listen-port', type=int, default=LISTEN_PORT)
    p.add_argument('--dest-host', default=DEST_HOST)
    p.add_argument('--dest-port', type=int, default=DEST_PORT)
    p.add_argument('--allowed-file', default=ALLOWED_IPS_FILE, help="JSON list of allowed IPs / CIDR networks")
    p.add_argument('--log-dir', default=LOG_DIR)
    p.add_argument('--max-connections', type=int, default=MAX_CONNECTIONS)
    p.add_argument('--connect-timeout', type=float, default=CONNECT_TIMEOUT)
    p.add_argument('--idle-timeout', type=float, default=IDLE_TIMEOUT,
                   help="close connections idle for this many seconds (0 = never)")
    return p.parse_args()


def main():
    global CONNECT_TIMEOUT, IDLE_TIMEOUT
    args = parse_args()
    CONNECT_TIMEOUT, IDLE_TIMEOUT = args.connect_timeout, args.idle_timeout

    stop_event = threading.Event()

    def signal_handler(sig, frame):
        print("\nShutting down...")
        logger.info("Stopped by Ctrl+C")
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    setup_logging(args.log_dir)
    whitelist = Whitelist(args.allowed_file)
    threading.Thread(target=command_interface, args=(stop_event, whitelist), daemon=True).start()
    start_proxy(stop_event, args, whitelist)
    logger.info("Server stopped.")


if __name__ == '__main__':
    main()
