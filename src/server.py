#!/usr/bin/env python3

import socket
import sys
import re
import string

# Validate whether a request is valid
def validate_request(http_request: bytes) -> bool:
    separate_lines = http_request.split(b'\n')

    # Ensure that there are newlines separating 
    if len(separate_lines) == 1:
        return False
    
    # Ensure Host header is included exactly once
    if sum(1 for line in separate_lines if b'Host: ' in line) != 1:
        return False

    # Ensure Host header is to my server?
    if b'Host: calebsserver' not in separate_lines:
        return False
    
    # Validate request line
    request_line = separate_lines[0].decode('utf-8')
    request_line_elements = request_line.split(' ')
    if len(request_line_elements) != 3:
        return False
    method = request_line_elements[0]
    uri = request_line_elements[1]
    http_version = request_line_elements[2]
    if not(method.isupper() and method.isalpha()):
        return False
    if not(re.match(r"/[A-Za-z\./]*", uri) or re.search("github.com/calebkbrad/calebsserver", uri)):
        return False
    return bool(re.match(r'HTTP/\d\.\d', http_version))


# Extract relevant info from a request, return it as a list
def get_request_info(http_request: bytes) -> list:
    info = []
    separate_lines = http_request.split(b'\n')

    # Handle first element (info from request line)
    request_line = separate_lines[0].decode('utf-8')
    request_line_info = request_line.split(' ')
    info.append(request_line_info)
    
    # Eventually handle headers too

    return info

def check_method(method: str) -> bool:
    # Check if a method is currently supported
    return method in ['GET', 'HEAD', 'OPTIONS', 'TRACE']



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

    test_request1 = b"GET www.github.com/calebkbrad/calebsserver.com HTTP/1.1\nHost: calebsserver\nConnection: close"
    print(validate_request(test_request1))

if __name__ == "__main__":
    main(sys.argv[1:])