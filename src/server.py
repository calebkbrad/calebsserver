#!/usr/bin/env python3

import socket
import sys
import re
import time
from os.path import exists
import os

# Dictionary of status codes
status_codes = {
    "200": b"200 OK",
    "400": b"400 Bad Request",
    "403": b"403 Forbidden",
    "404": b"404 Not Found",
    "500": b"500 Internal Server Error",
    "501": b"501 Not Implemented",
    "505": b"505 HTTP Version not Supported"
}

# Dictionary of mime types
mime_types = {
    ".txt": b'text/plain',
    ".html": b'text/html',
    ".xml": b'text/xml',
    ".png": b'image/png',
    ".jpeg": b'image/jpeg',
    ".gif": b'image/gif',
    ".pdf": b'application/pdf',
    ".ppt": b'application/vnd.ms-powerpoint',
    ".doc": b'application/vnd.ms-word',
    ".log": b'text/plain'
}

# Validate whether a request is valid
def validate_request(http_request: bytes) -> bool:
    separate_lines = http_request.split(b'\r\n')

    # Ensure that there are newlines separating 
    if len(separate_lines) == 1:
        print('Fails 1 check')
        return False
    
    # Ensure Host header is included exactly once
    if sum(1 for line in separate_lines if b'Host: ' in line) != 1:
        print('Fails 2 check')
        return False

    # Ensure Host header is to my server?
    if b'Host: cs531-cs_cbrad022' not in separate_lines:
        print('Fails 3 check')
        return False
    
    # Validate request line
    request_line = separate_lines[0].decode('utf-8')
    request_line_elements = request_line.split(' ')
    if len(request_line_elements) != 3:
        print('Fails 4 check')
        return False
    method = request_line_elements[0]
    uri = request_line_elements[1]
    http_version = request_line_elements[2]
    if not(method.isupper() and method.isalpha()):
        print('Fails 5 check')
        return False
    if not(uri == "*" or re.match(r"/[A-Za-z\./]*", uri) or 'cs531-cs_cbrad022' in uri):
        print('Fails 6 check')
        return False
    return bool(re.match(r'HTTP/\d\.\d', http_version))


# Extract relevant info from a request, return it as a list
def get_request_info(http_request: bytes) -> list:
    info = []
    separate_lines = http_request.split(b'\r\n')

    # Handle first element (info from request line)
    request_line = separate_lines[0].decode('utf-8')
    request_line_info = request_line.split(' ')

    if 'cs531-cs_cbrad022' in request_line_info[1]:
        request_line_info[1] = request_line_info[1].split("cs531-cs_cbrad022",1)[1]
    elif request_line_info[1] == "*":
        request_line_info[1] = "/"
    request_line_info[1] = "." + request_line_info[1]
    info.append(request_line_info)
    
    # Eventually handle request headers too

    return info

# Check if a method is currently supported
def check_method(method: str) -> bool:
    return method in ['GET', 'HEAD', 'OPTIONS', 'TRACE']

# Check if version 1.1 is being used
def check_version(http_version: str) -> bool:
    return http_version == "HTTP/1.1"

# Generate date header with current time
def generate_date_header() -> bytes:
    current_time = time.strftime("%a, %d %b %Y %I:%M:%S GMT", time.gmtime())
    time_bytes = current_time.encode('ascii')
    return b'Date: ' + time_bytes + b'\r\n'

# Generate Content-Length header given a valid uri
def generate_content_length(valid_uri: str) -> bytes:
    file_size = os.path.getsize(valid_uri)
    return b'Content-Length: ' + str(file_size).encode('ascii') + b'\r\n'

# Generate Content-Type header given a valid uri
def generate_content_type(valid_uri: str) -> bytes:
    content_type = b''
    for mime_type in mime_types.keys():
        if valid_uri.endswith(mime_type):
            content_type += mime_types[mime_type]
    if content_type == b'':
        content_type += b'application/octet-stream'
    
    return b'Content-Type: ' + content_type + b'\r\n'

# Generate Last-Modified header given a valid uri
def generate_last_modified(valid_uri: str):
    time_since_epoch = os.path.getmtime(valid_uri)
    last_m_time = time.strftime("%a, %d %b %Y %I:%M:%S GMT", time.localtime(time_since_epoch))
    time_bytes = last_m_time.encode('ascii')
    return b'Last-Modified: ' + time_bytes + b'\r\n'

# Generate Server header
def generate_server() -> bytes:
    return b'Server: calebsserver' + b'\r\n'
    
# Generate Allow header
def generate_allow() -> bytes:
    return b'Allow: GET, HEAD, OPTIONS, TRACE\r\n'

# Generate status code
def generate_status_code(status_code: int) -> bytes:
    return b'HTTP/1.1 ' + status_codes[str(status_code)] + b'\r\n'

# Generate generic response headers not associated with content
def generate_error_response(status: int) -> bytes:
    full_response = b''
    full_response += generate_status_code(status)
    full_response += generate_date_header()
    full_response += generate_server()
    full_response += b'Connection: close' + b'\r\n'
    return full_response

# Generate respones headers associated with found content
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

def generate_text_payload(valid_uri: str) -> bytes:
    with open(valid_uri, 'r') as f:
        file_contents = f.read()
    file_contents = file_contents.encode('ascii')
    return file_contents

def write_to_log(addr: str, request: bytes, status: int, uri: str):
    log_entry = b''
    log_entry += addr.encode('ascii') + b' '
    log_entry += time.strftime("[%d/%b/%Y:%H:%M:%S %z", time.gmtime()).encode('ascii') + b'] '
    log_entry += b'"' + request + b'" '
    log_entry += str(status).encode('ascii') + b' '
    if exists(uri):
        content_length = os.path.getsize(uri)
        log_entry += str(content_length).encode('ascii')
    log_entry += b'\n'
    with open('./.well-known/access.log', 'a') as f:
        f.write(log_entry.decode("utf-8"))
    
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
                request_line = data.split(b'\r\n')[0]
                info = get_request_info(data)
                method = info[0][0]
                uri = info[0][1]
                version = info[0][2]

                # Handle TRACE execution
                if method == "TRACE":
                    conn.send(generate_error_response(200))
                    conn.send(b'Content-Type: message/http\r\n\r\n')
                    conn.send(data)

                # Return error responses if appropriate
                if not check_method(method):
                    conn.send(generate_error_response(501) + b'\r\n')
                    conn.close()
                    break
                if not check_resource(uri):
                    conn.send(generate_error_response(404) + b'\r\n')
                    conn.close()
                    break
                if not check_version(version):
                    conn.send(generate_error_response(505) + b'\r\n')
                    conn.close()
                    break

                # Handle OPTIONS execution
                if method == "OPTIONS":
                    conn.send(generate_error_response(200))
                    conn.send(generate_allow() + b'\r\n')
                # Handle HEAD execution
                elif method == "HEAD":
                    conn.send(generate_status_code(200))
                    conn.send(generate_success_response_headers(uri))
                # Handle GET execution
                elif method == "GET":
                    conn.send(generate_status_code(200))
                    conn.send(generate_success_response_headers(uri) + b'\r\n')
                    if b'text' in generate_content_type(uri):
                        conn.send(b'\r\n' + generate_text_payload(uri))
                    write_to_log(addr[0], request_line, 200, uri)
            else:
                conn.send(generate_error_response(400) + b'\r\n')
            conn.close()
            break


    # GET /index.html HTTP/1.1\r\nHost: calebsserver\r\nConnection: close\r\n\r\n
    # GET /.well-known/access.log HTTP/1.1\r\nHost: calebsserver\r\nConnection: close\r\n\r\n
if __name__ == "__main__":
    main(sys.argv[1:])