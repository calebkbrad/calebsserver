#!/usr/bin/env python3

import socket
import sys
import re

def validate_request(http_request: bytes) -> bool:
    print('validating http request')
    separate_lines = http_request.split(b'\n')

    # Ensure that there are newlines separating 
    if len(separate_lines) == 1:
        return False
    
    # Ensure Host header is included
    if b'Host: calebsserver' not in separate_lines:
        return False

    # Validate request line
    request_line = separate_lines[0].decode('utf-8')
    return bool(re.match(r"[A-Z]+ /[A-Za-z\./]* HTTP/1.1", request_line))

def get_request_info(http_request: bytes) -> list:
    print('oh woah')
    info = []
    separate_lines = http_request.split(b'\n')

    # Handle first element (info from request line)
    request_line = separate_lines[0].decode('utf-8')
    request_line_info = request_line.split(' ')
    info.append(request_line_info)
    
    # Eventually handle headers too

    return info

def main(argv):
    # HOST = "0.0.0.0"
    # if not argv:
    #     PORT = 80
    # else:
    #     PORT = int(argv[0])

    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # s.bind((HOST, PORT))
    # s.listen()
    # print(f"Listening on {HOST}:{PORT} for HTTP connections")
    # while True:
    #     data = B""
    #     while True:
    #         conn, addr = s.accept()
    #         print(f"Connected to {addr}")
    #         while True:
    #             data_frag = conn.recv(1024)
    #             data += data_frag
    #             if len(data_frag) < 1024:   
    #                 conn.sendall(data)
    #                 conn.close()
    #                 break
    #         break

    test_request1 = b"GET /myserver/whoaohdoashdo/img.html HTTP/1.1\nHost: calebserver\nConnection: close"
    print(validate_request(test_request1))

if __name__ == "__main__":
    main(sys.argv[1:])