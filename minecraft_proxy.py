import socket
import threading
import signal
import os
import json
import datetime
import shutil
import ipaddress

# === Configuration ===
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 25565
DEST_HOST = '127.0.0.1'
DEST_PORT = 25566
ALLOWED_IPS_FILE = 'allowed_ips.json'
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'proxy.log')


# === Logging ===
def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    if os.path.exists(LOG_FILE):
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        shutil.move(LOG_FILE, os.path.join(LOG_DIR, f'proxy_{timestamp}.log'))

def log_event(message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# === IP Whitelist Management ===
def load_allowed_networks():
    if not os.path.exists(ALLOWED_IPS_FILE):
        return []
    with open(ALLOWED_IPS_FILE, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
            return [ipaddress.ip_network(entry.strip()) for entry in data]
        except Exception as e:
            print("Error loading allowed IPs:", e)
            return []

def save_allowed_networks(networks):
    with open(ALLOWED_IPS_FILE, 'w', encoding='utf-8') as f:
        json.dump([str(net) for net in networks], f, indent=2)


# === Global Variables ===
allowed_networks = load_allowed_networks()
allowed_lock = threading.Lock()


# === Traffic Forwarding ===
def forward(source, destination, label):
    total_bytes = 0
    start_time = datetime.datetime.now()
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
            total_bytes += len(data)
    except:
        pass
    finally:
        duration = (datetime.datetime.now() - start_time).total_seconds()
        log_event(f"{label} closed | Bytes: {total_bytes} | Duration: {duration:.2f}s")
        source.close()
        destination.close()



# === Handle Client ===
def is_allowed(ip_str: str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        with allowed_lock:
            return any(ip_obj in net for net in allowed_networks)
    except ValueError:
        return False

def handle_client(client_sock, client_addr):
    ip, port = client_addr
    log_event(f"Connection attempt from {ip}:{port}")

    if not is_allowed(ip):
        log_event(f"Rejected: {ip} is not in the allowed list")
        client_sock.close()
        return

    try:
        server_sock = socket.create_connection((DEST_HOST, DEST_PORT))
    except Exception as e:
        log_event(f"Error connecting to destination: {e}")
        client_sock.close()
        return

    log_event(f"Connection from {ip} accepted and forwarded")
    log_event(f"{ip}:{port} connected -> {DEST_HOST}:{DEST_PORT}")

    # threading.Thread(target=forward, args=(client_sock, server_sock), daemon=True).start()
    # threading.Thread(target=forward, args=(server_sock, client_sock), daemon=True).start()
    threading.Thread(target=forward, args=(client_sock, server_sock, f"{ip}:{port} -> DEST"), daemon=True).start()
    threading.Thread(target=forward, args=(server_sock, client_sock, f"DEST -> {ip}:{port}"), daemon=True).start()



# === Start Proxy ===
def start_proxy(stop_event):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((LISTEN_HOST, LISTEN_PORT))
        s.listen(5)
        log_event(f"Proxy listening on {LISTEN_PORT} -> {DEST_HOST}:{DEST_PORT}")
        s.settimeout(1.0)
        while not stop_event.is_set():
            try:
                client_sock, client_addr = s.accept()
                threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True).start()
            except socket.timeout:
                continue


# === Command Interface ===
def command_interface(stop_event):
    global allowed_networks
    while not stop_event.is_set():
        try:
            cmd = input("> ").strip()
            if cmd.startswith("add "):
                net_str = cmd[4:].strip()
                try:
                    new_net = ipaddress.ip_network(net_str)
                    with allowed_lock:
                        if new_net in allowed_networks:
                            print(f"{net_str} is already in the allowed list")
                        else:
                            allowed_networks.append(new_net)
                            save_allowed_networks(allowed_networks)
                            log_event(f"{net_str} added to allowed list")
                            print(f"{net_str} added")
                except ValueError:
                    print(f"Invalid IP or network format: {net_str}")
            elif cmd.startswith("remove "):
                net_str = cmd[7:].strip()
                try:
                    net_to_remove = ipaddress.ip_network(net_str)
                    with allowed_lock:
                        if net_to_remove in allowed_networks:
                            allowed_networks.remove(net_to_remove)
                            save_allowed_networks(allowed_networks)
                            log_event(f"{net_str} removed from allowed list")
                            print(f"{net_str} removed")
                        else:
                            print(f"{net_str} not found in allowed list")
                except ValueError:
                    print(f"Invalid IP or network format: {net_str}")
            elif cmd == "list":
                with allowed_lock:
                    print("Allowed IPs / Networks:")
                    for net in allowed_networks:
                        print(" -", net)
            elif cmd in ("exit", "quit", "stop"):
                log_event("Stopping server via command")
                stop_event.set()
                break
            else:
                print("Available commands: add [ip or cidr], remove [ip or cidr], list, stop")
        except (EOFError, KeyboardInterrupt):
            stop_event.set()


# === Ctrl+C Handler ===
def signal_handler(sig, frame):
    print("\nShutting down...")
    log_event("Stopped by Ctrl+C")
    stop_event.set()


# === Main ===
if __name__ == '__main__':
    stop_event = threading.Event()
    signal.signal(signal.SIGINT, signal_handler)

    setup_logging()
    threading.Thread(target=command_interface, args=(stop_event,), daemon=True).start()
    start_proxy(stop_event)
    log_event("Server stopped.")
