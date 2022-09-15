#!/usr/bin/env python3

import socket

HOST = "0.0.0.0"
PORT = 8080

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen()
print(f"Listening on {HOST}:{PORT} for HTTP connections")

while True:
    conn, addr = s.accept()
    print(f"Connected to {addr}")
    data = conn.recv(1024)
    if not data:
        break
    conn.sendall(data)
    conn.close()