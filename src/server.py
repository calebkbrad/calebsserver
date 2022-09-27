#!/usr/bin/env python3

import socket
import sys
import re
import time
from os.path import exists
import os

status_codes = {
    "200": b"200 OK",
    "400": b"400 Bad Request",
    "403": b"403 Forbidden",
    "404": b"404 Not Found",
    "500": b"500 Internal Server Error",
    "501": b"501 Not Implemented",
    "505": b"505 HTTP Version not Supported"
}

mime_types = {
    ".txt": b'text/plain',
    ".html": b'text/html',
    ".xml": b'text/xml',
    ".png": b'image/png',
    ".jpeg": b'image/jpeg',
    ".gif": b'image/gif',
    ".pdf": b'application/pdf',
    ".ppt": b'application/vnd.ms-powerpoint',
    ".doc": b'application/vnd.ms-word'
}

# Validate whether a request is valid
def validate_request(http_request: bytes) -> bool:
    separate_lines = http_request.split(b'\r\n')

    # Ensure that there are newlines separating 
    if len(separate_lines) == 1:
        # print('Fails 1 check')
        return False
    
    # Ensure Host header is included exactly once
    if sum(1 for line in separate_lines if b'Host: ' in line) != 1:
        # print('Fails 2 check')
        return False

    # Ensure Host header is to my server?
    if b'Host: calebsserver' not in separate_lines:
        # print('Fails 3 check')
        return False
    
    # Validate request line
    request_line = separate_lines[0].decode('utf-8')
    request_line_elements = request_line.split(' ')
    if len(request_line_elements) != 3:
        # print('Fails 4 check')
        return False
    method = request_line_elements[0]
    uri = request_line_elements[1]
    http_version = request_line_elements[2]
    if not(method.isupper() and method.isalpha()):
        # print('Fails 5 check')
        return False
    if not(re.match(r"\.*/[A-Za-z\./]*", uri) or re.search("github.com/calebkbrad/calebsserver", uri)):
        # print('Fails 6 check')
        return False
    return bool(re.match(r'HTTP/\d\.\d', http_version))


# Extract relevant info from a request, return it as a list
def get_request_info(http_request: bytes) -> list:
    info = []
    separate_lines = http_request.split(b'\r\n')

    # Handle first element (info from request line)
    request_line = separate_lines[0].decode('utf-8')
    request_line_info = request_line.split(' ')
    request_line_info[1] = "." + request_line_info[1]
    info.append(request_line_info)
    
    # Eventually handle headers too

    return info

# Check if a method is currently supported
def check_method(method: str) -> bool:
    return method in ['GET', 'HEAD', 'OPTIONS', 'TRACE']

# Check if version 1.1 is being used
def check_version(http_version: str) -> bool:
    return http_version == "HTTP/1.1"

# Generate date header with current time
def generate_date_header() -> bytes:
    current_time = time.strftime("%a, %d %b %Y %I:%M:%S %p GMT", time.gmtime())
    time_bytes = current_time.encode('ascii')
    return b'Date: ' + time_bytes + b'\r\n'

def generate_content_length(valid_uri: str) -> bytes:
    file_size = os.path.getsize(valid_uri)
    return b'Content-Length: ' + str(file_size).encode('ascii') + b'\r\n'

def generate_content_type(valid_uri: str) -> bytes:
    content_type = b''
    for mime_type in mime_types.keys():
        if valid_uri.endswith(mime_type):
            content_type += mime_types[mime_type]
    if content_type == b'':
        content_type += b'application/octet-stream'
    
    return b'Content-Type: ' + content_type + b'\r\n'

def generate_last_modified(valid_uri: str):
    time_since_epoch = os.path.getmtime(valid_uri)
    last_m_time = time.strftime("%a, %d %b %Y %I:%M:%S %p GMT", time.localtime(time_since_epoch))
    time_bytes = last_m_time.encode('ascii')
    return b'Last-Modified: ' + time_bytes + b'\r\n'

def generate_server() -> bytes:
    return b'Server: calebsserver' + b'\r\n'
    
def generate_allow() -> bytes:
    return b'Allow: GET, HEAD, OPTIONS, TRACE\r\n'

def generate_status_code(status_code: int) -> bytes:
    return b'HTTP/1.1 ' + status_codes[str(status_code)] + b'\r\n'

def generate_reponse(status: int, info: list) -> bytes:
    print('os')

def generate_error_response(status: int) -> bytes:
    full_response = b''
    full_response += generate_status_code(status)
    full_response += generate_date_header()
    full_response += generate_server()
    full_response += b'Connection: close' + b'\r\n'
    return full_response

def generate_success_response_headers(uri: str) -> bytes:
    headers = b''
    headers += generate_date_header()
    headers += generate_server()
    headers += generate_content_type(uri)
    headers += generate_last_modified(uri)
    headers += generate_content_length(uri)
    return headers

# Check if a resource exists, given a normalized uri (relative path)
def check_resource(uri: str) -> bool:
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
                    break
            data = data.decode('unicode_escape').encode("raw_unicode_escape")
            if validate_request(data):
                info = get_request_info(data)
                method = info[0][0]
                uri = info[0][1]
                version = info[0][2]

                # Return error responses if appropriate
                if not check_method(method):
                    conn.send(generate_error_response(501))
                    conn.close()
                    break
                if not check_resource(uri):
                    conn.send(generate_error_response(404))
                    conn.close()
                    break
                if not check_version(version):
                    conn.send(generate_error_response(505))
                    conn.close()
                    break

                # Handle OPTIONS execution
                if method == "OPTIONS":
                    conn.send(generate_error_response(200))
                    conn.send(generate_allow())
                # Handle HEAD execution
                elif method == "HEAD":
                    conn.send(generate_status_code(200))
                    conn.send(generate_success_response_headers(uri))
                # Handle TRACE execution
                elif method == "TRACE":
                    conn.send(generate_error_response(200))
                    conn.send(data)
                # Handle GET execution
                elif method == "GET":
                    conn.send(generate_status_code(200))
                    conn.send(generate_success_response_headers(uri))

            else:
                conn.send(generate_error_response(400))
            conn.close()
            break


    # OPTIONS /index.html HTTP/1.1\r\nHost: calebsserver\r\nConnection: close\r\n\r\n
    # test_request1 = b"GET www.github.com/calebkbrad/calebsserver HTTP/1.1\r\nHost: calebsserver\r\nConnection: close\r\n\r\n"
    # print(validate_request(test_request1))
    # print(check_resource(b'mypage.html'))
    # print(generate_content_type(b'/index.html'))

if __name__ == "__main__":
    main(sys.argv[1:])