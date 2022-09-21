#!/usr/bin/env python3

import socket
import sys

def main(argv):
    HOST = "0.0.0.0"
    if not argv:
        PORT = 80
    else:
        PORT = int(argv[0])

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT} for HTTP connections")
    data = B""
    while True:
        conn, addr = s.accept()
        print(f"Connected to {addr}")
        while True:
            data_frag = conn.recv(1024)
            data += data_frag
            if len(data_frag) < 1024:   
                conn.sendall(data)
                conn.close()
                break
        break

if __name__ == "__main__":
    main(sys.argv[1:])