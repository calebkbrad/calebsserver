#!/usr/bin/env python3

import socket
import sys
import re
import time
from os.path import exists

status_codes = {
    "200": "OK",
    "400": "Bad Request",
    "403": "Forbidden",
    "404": "Not Found",
    "500": "Internal Server Error",
    "501": "Not Implemented",
    "505": "HTTP Version not Supported"
}

# Validate whether a request is valid
def validate_request(http_request: bytes) -> bool:
    separate_lines = http_request.split(b'\r\n')

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

# Check if a method is currently supported
def check_method(method: str) -> bool:
    return method in ['GET', 'HEAD', 'OPTIONS', 'TRACE']

# Check if version 1.1 is being used
def check_version(http_version: bytes) -> bool:
    return http_version == b"HTTP/1.1"

# Generate date header with current time
def generate_date_header() -> bytes:
    current_time = time.strftime("%a, %d %b %Y %I:%M:%S %p GMT", time.gmtime())
    time_bytes = current_time.encode('utf-8')
    print(type(time_bytes))
    return b'Date: ' + time_bytes

# Check if a resource exists, given a normalized uri (relative path)
def check_resource(uri:bytes) -> bool:
    return exists(uri)

def generate_text_payload(valid_uri:bytes) -> bytes:
    print('generating payload')
    


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
    while True:
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



    test_request1 = b"GET www.github.com/calebkbrad/calebsserver.com HTTP/1.1\r\nHost: calebsserver\r\nConnection: close\r\n\r\n"
    print(validate_request(test_request1))
    print(check_resource(b'mypage.html'))

if __name__ == "__main__":
    main(sys.argv[1:])