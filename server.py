import socket
import csv
import os
import hashlib
import time
import threading
from datetime import datetime, timedelta

# File paths
USER_DB = "users.csv"
CHAT_LOG = "chat_log.txt"

# Global flag for stopping the server
stop_server = False

# Hash passwords using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Load users from CSV
def load_users():
    users = {}
    if os.path.exists(USER_DB):
        with open(USER_DB, "r") as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) == 2:
                    username, hashed_password = row
                    users[username] = hashed_password
    print(f"[DEBUG] Loaded {len(users)} users from database.")
    return users

# Read chat history (last 7 days)
def get_recent_chat_history():
    if not os.path.exists(CHAT_LOG):
        return ""

    recent_history = []
    last_date = None
    cutoff_time = datetime.now() - timedelta(days=7)

    with open(CHAT_LOG, "r") as file:
        for line in file:
            if line.strip():
                parts = line.split("] ", 1)
                if len(parts) == 2:
                    timestamp_str, message = parts
                    timestamp_str = timestamp_str.lstrip("[").strip()

                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M")
                        if timestamp.date() != last_date:
                            recent_history.append(f"\n--- {timestamp.date()} ---\n")
                            last_date = timestamp.date()
                        if timestamp >= cutoff_time:
                            recent_history.append(f"[{timestamp.strftime('%H:%M')}] {message}")
                    except ValueError:
                        recent_history.append(line)

    print(f"[DEBUG] Loaded last 7 days of chat history.")
    return "".join(recent_history)

# Log messages with timestamps
def log_message(sender, message):
    now = datetime.now()
    time_only = now.strftime("%H:%M")  # Format time as HH:MM
    formatted_message = f"[{time_only}] {sender}: {message}"

    with open(CHAT_LOG, "a") as file:
        file.write(formatted_message + "\n")

    print(f"[INFO] 📝 {formatted_message}")
    return formatted_message  # Return the formatted message to send to clients

# Function to start the server and auto-restart if it crashes
def start_server():
    global stop_server  # Access the global stop flag
    while not stop_server:
        try:
            print("[INFO] 🔄 Starting the chat server...")
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server.bind(("0.0.0.0", 2345))

            users = load_users()  # Load user accounts
            clients = {}  # {addr: username}
            pending_logins = {}  # Track clients in the login process

            print("[INFO] 🔹 Secure UDP Chat Server is running...")

            while not stop_server:
                server.settimeout(1)  # Prevents blocking when stopping the server
                try:
                    data, addr = server.recvfrom(1024)
                except socket.timeout:
                    continue  # Restart loop if there's no incoming message

                message = data.decode().strip()
                print(f"[DEBUG] Received data from {addr}: {message}")

                # Handle new user login (NO REGISTRATION)
                if addr not in clients and addr not in pending_logins:
                    pending_logins[addr] = {"step": "username"}
                    server.sendto("LOGIN".encode(), addr)
                    print(f"[DEBUG] Asking {addr} to log in.")
                    continue

                if addr in pending_logins:
                    login_step = pending_logins[addr]["step"]

                    if login_step == "username":
                        username = message
                        if username not in users:
                            server.sendto("ERROR: Username not found.".encode(), addr)
                            del pending_logins[addr]
                            continue

                        pending_logins[addr]["username"] = username
                        pending_logins[addr]["step"] = "password"
                        server.sendto("Enter password:".encode(), addr)
                        print(f"[DEBUG] {addr} provided username: {username}")

                    elif login_step == "password":
                        username = pending_logins[addr]["username"]
                        password = message
                        hashed_password = hash_password(password)

                        if users[username] == hashed_password:
                            clients[addr] = username
                            del pending_logins[addr]  # Remove from login tracking
                            chat_history = get_recent_chat_history()
                            server.sendto(f"Welcome back, {username}!\n\nChat History (Last 7 Days):\n{chat_history}".encode(),
                                          addr)
                            print(f"[INFO] User '{username}' logged in successfully from {addr}.")
                        else:
                            server.sendto("ERROR: Incorrect password.".encode(), addr)
                            print(f"[WARNING] Failed login attempt for '{username}' from {addr}.")
                            del pending_logins[addr]  # Reset login state

                    continue  # Go back to listening

                # Handle chat messages
                if addr in clients:
                    sender = clients[addr]
                    formatted_message = log_message(sender, message)  # Log and format message with timestamp

                    # Send to all users
                    for client_addr in clients:
                        server.sendto(formatted_message.encode(), client_addr)

                    print(f"[INFO] '{sender}' sent a message: {message}")

        except Exception as e:
            if stop_server:
                break  # Stop the loop if we received a shutdown command
            print(f"[ERROR] ⚠️ Server crashed! Restarting in 3 seconds...\n{e}")
            time.sleep(3)  # Wait before restarting

# Command listener for stopping or restarting the server
def command_listener():
    global stop_server
    while True:
        cmd = input("Enter command: ").strip().lower()
        if cmd == "stop":
            print("[INFO] 🔴 Stopping the server...")
            stop_server = True
            break
        elif cmd == "restart":
            print("[INFO] 🔄 Restarting the server...")
            stop_server = True
            time.sleep(2)
            stop_server = False
            start_server()
            break

# Start the server in a separate thread
server_thread = threading.Thread(target=start_server)
server_thread.start()

# Start the command listener
command_listener()
