"""TLS + AES-256-GCM message server with ACK/retry and heartbeat.

mkdir -p certs

openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
  -keyout certs/ca.key \
  -out certs/ca.crt \
  -days 3650 \
  -subj "/CN=Private Server CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"




  
openssl req -new -newkey rsa:2048 -nodes \
  -keyout certs/server.key \
  -out certs/server.csr \
  -subj "/CN=141.11.190.106"


echo "subjectAltName=IP:141.11.190.106
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment" > certs/server.ext


openssl x509 -req \
  -in certs/server.csr \
  -CA certs/ca.crt \
  -CAkey certs/ca.key \
  -CAcreateserial \
  -out certs/server.crt \
  -days 365 \
  -sha256 \
  -extfile certs/server.ext


"""



from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import threading
import time
import uuid
from queue import Queue, Empty

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ----------------------------- Configuration -----------------------------
HOST = "0.0.0.0"
PORT = 7091
HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 35
ACK_TIMEOUT = 10
MAX_FRAME_SIZE = 8 * 1024 * 1024
CERT_FILE = "certs/server.crt"
KEY_FILE = "certs/server.key"

# Must exactly match client.py. Replace with a random secret >= 32 bytes.
PRE_SHARED_KEY = b"7mQx9VbK2pLwF4nYc8TjH6sRzA1eU5dG"

# ------------------------------- Crypto -----------------------------------

def derive_aes_key() -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"client-server-protocol-v1",
        info=b"application-aes-256-gcm",
    ).derive(PRE_SHARED_KEY)


AES_KEY = derive_aes_key()


def lrc(data: bytes) -> int:
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
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size <= 0 or size > MAX_FRAME_SIZE:
        raise ValueError(f"Ukuran frame tidak valid: {size}")
    return open_sealed(recv_exact(sock, size))


def send_message(sock: ssl.SSLSocket, lock: threading.Lock, message: dict) -> None:
    with lock:
        sock.sendall(seal(message))

# --------------------------- Client session -------------------------------

class ClientSession:
    def __init__(self, sock: ssl.SSLSocket, address):
        self.sock = sock
        self.address = address
        self.send_lock = threading.Lock()
        self.responses: dict[str, Queue] = {}
        self.response_lock = threading.Lock()
        self.last_seen = time.monotonic()
        self.running = threading.Event()
        self.running.set()

    def send(self, message: dict) -> None:
        send_message(self.sock, self.send_lock, message)

    def reader_loop(self) -> None:
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
                elif kind in ("RESPONSE", "NACK"):
                    message_id = msg.get("id")
                    with self.response_lock:
                        target = self.responses.get(message_id)
                    if target is not None:
                        target.put(msg)
        except (OSError, ssl.SSLError, ValueError, ConnectionError) as exc:
            print(f"[INFO] Client {self.address} terputus: {exc}")
        finally:
            self.close()

    def heartbeat_loop(self) -> None:
        while self.running.is_set():
            time.sleep(HEARTBEAT_INTERVAL)
            if not self.running.is_set():
                break
            if time.monotonic() - self.last_seen > HEARTBEAT_TIMEOUT:
                print(f"[WARNING] Heartbeat timeout: {self.address}")
                self.close()
                break
            try:
                self.send({"type": "PING", "id": str(uuid.uuid4())})
            except OSError:
                self.close()
                break

    def start(self) -> None:
        threading.Thread(target=self.reader_loop, daemon=True).start()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()

    def send_request(self, text: str) -> str:
        """Stop-and-wait delivery: retry the SAME message ID until response."""
        message_id = str(uuid.uuid4())
        response_queue: Queue = Queue()
        with self.response_lock:
            self.responses[message_id] = response_queue

        payload = text.encode("utf-8")
        packet = {"type": "MESSAGE", "id": message_id, "text": text, "lrc": lrc(payload)}
        try:
            while self.running.is_set():
                try:
                    self.send(packet)
                except OSError as exc:
                    raise ConnectionError("Koneksi terputus saat mengirim") from exc
                try:
                    response = response_queue.get(timeout=ACK_TIMEOUT)
                except Empty:
                    print(f"[RETRY] Belum ada ACK untuk {message_id}; kirim ulang pesan yang sama")
                    continue
                if response.get("type") == "NACK":
                    print("[NACK] Client menolak pesan:", response.get("reason"))
                    continue
                response_text = response.get("text", "")
                if lrc(response_text.encode("utf-8")) != response.get("lrc"):
                    print("[WARNING] LRC response tidak cocok; meminta pengiriman ulang")
                    continue
                return response_text
            raise ConnectionError("Session client sudah ditutup")
        finally:
            with self.response_lock:
                self.responses.pop(message_id, None)

    def close(self) -> None:
        if self.running.is_set():
            self.running.clear()
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass

# -------------------------------- Server ----------------------------------

class MessageServer:
    def __init__(self):
        self.sessions: list[ClientSession] = []
        self.sessions_lock = threading.Lock()

    def tls_context(self) -> ssl.SSLContext:
        if not os.path.isfile(CERT_FILE) or not os.path.isfile(KEY_FILE):
            raise FileNotFoundError(
                f"Sertifikat TLS tidak ditemukan. Diperlukan {CERT_FILE} dan {KEY_FILE}."
            )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(CERT_FILE, KEY_FILE)
        return context

    def accept_loop(self, listener: socket.socket, context: ssl.SSLContext) -> None:
        while True:
            try:
                raw, address = listener.accept()
                try:
                    tls_sock = context.wrap_socket(raw, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    print(f"[WARNING] TLS handshake gagal dari {address}: {exc}")
                    raw.close()
                    continue
                session = ClientSession(tls_sock, address)
                with self.sessions_lock:
                    self.sessions.append(session)
                session.start()
                print(f"[INFO] Client TLS terhubung: {address} ({tls_sock.version()})")
            except OSError as exc:
                print("[ERROR] accept:", exc)
                time.sleep(2)

    def active_sessions(self) -> list[ClientSession]:
        with self.sessions_lock:
            self.sessions = [s for s in self.sessions if s.running.is_set()]
            return list(self.sessions)

        
    def console(self):
        selected_session = None

        while True:
            # Mode belum memilih client
            if selected_session is None:
                command = input("server> ").strip()

                if command == "quit":
                    for session in self.active_sessions():
                        session.close()
                    break

                elif command == "list":
                    sessions = self.active_sessions()

                    for index, session in enumerate(sessions):
                        print(index, session.address)

                elif command.startswith("select "):
                    try:
                        index = int(command.split(maxsplit=1)[1])
                        sessions = self.active_sessions()
                        selected_session = sessions[index]

                        print(
                            f"[INFO] Terhubung ke client "
                            f"{selected_session.address}"
                        )
                        print("Ketik pesan untuk mengirim.")
                        print("Ketik 'back' untuk kembali.")

                    except (ValueError, IndexError):
                        print("[ERROR] Client tidak ditemukan.")

                else:
                    print("Perintah: list | select <nomor> | quit")

            # Mode sudah memilih client
            else:
                if not selected_session.running.is_set():
                    print("[WARNING] Client terputus.")
                    selected_session = None
                    continue

                try:
                    message = input(
                        f"client {selected_session.address[0]}> "
                    )

                    if message == "back":
                        selected_session = None
                        print("[INFO] Kembali ke menu server.")
                        continue

                    if message == "quit":
                        selected_session.close()
                        selected_session = None
                        continue

                    if not message:
                        continue

                    #response = selected_session.send_request(message)

                    #print("[CLIENT RESPONSE]", response)
                    #print("[CLIENT RESPONSE]", str(response).replace("\\n", "\n"))


                    response = selected_session.send_request(message)

                        

                    response = str(response).replace("b'", "").replace("'", "")
                    response = response.replace("\\n", "\n")



                    print("[CLIENT RESPONSE]", response)

                except (ConnectionError, OSError) as exc:
                    print("[ERROR] Koneksi terputus:", exc)
                    selected_session = None

        
    # def console(self) -> None:
    #     while True:
    #         sessions = self.active_sessions()
    #         command = input("server> ").strip()
    #         if command == "quit":
    #             for session in sessions:
    #                 session.close()
    #             break
    #         if command == "list":
    #             for index, session in enumerate(sessions):
    #                 print(index, session.address)
    #             continue
    #         if command.startswith("send "):
    #             try:
    #                 index_text, message = command[5:].split(" ", 1)
    #                 session = sessions[int(index_text)]
    #                 print("[CLIENT RESPONSE]", session.send_request(message))
    #             except (ValueError, IndexError) as exc:
    #                 print("Format: send <nomor_client> <pesan>", exc)
    #             except ConnectionError as exc:
    #                 print("[ERROR]", exc)
    #             continue
    #         print("Perintah: list | send <nomor_client> <pesan> | quit")

    def run(self) -> None:
        context = self.tls_context()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen(20)
        print(f"[INFO] TLS server listening on {HOST}:{PORT}")
        threading.Thread(target=self.accept_loop, args=(listener, context), daemon=True).start()
        self.console()


if __name__ == "__main__":
    MessageServer().run()
