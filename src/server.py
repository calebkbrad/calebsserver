#!/usr/bin/env python3

import socket
import sys
import re
import time
from os.path import exists, isdir
import os
import yaml
from urllib.parse import unquote

CRLF = b'\r\n'
CRLFCRLF = b'\r\n\r\n'

config = yaml.safe_load(open("./settings/config.yml"))
WEBROOT = config["WEBROOT"]
TIMEOUT = config["TIMEOUT"]
DEFAULTRESOURCE = config["DEFAULTRESOURCE"]

# Dictionary of status codes
status_codes = {
    "200": b"200 OK",
    "301": b"301 Moved Permanently",
    "302": b"302 Found",
    "304": b"304 Not Modified",
    "400": b"400 Bad Request",
    "403": b"403 Forbidden",
    "404": b"404 Not Found",
    "408": b"408 Request Timeout",
    "412": b"412 Precondition Failed",
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

virtual_uris = {
    WEBROOT + "/.well-known/access.log": "./access.log"
}

def validate_and_get_request_info(http_request: bytes) -> tuple:
    request_and_headers = http_request.split(CRLF)
    request = request_and_headers[0].decode('utf-8')
    headers = request_and_headers[1:]
    
    request_line_elements = request.split(' ')
    if len(request_line_elements) != 3:
        print('Fails 4 check')
        return ()
    method = request_line_elements[0]
    if 'cs531-cs_cbrad022' in request_line_elements[1]:
        request_line_elements[1] = request_line_elements[1].split("cs531-cs_cbrad022",1)[1]
    uri = unquote(WEBROOT + request_line_elements[1])
    http_version = request_line_elements[2]
    if not(method.isupper() and method.isalpha()):
        print('Fails 5 check')
        return ()
    if not(uri == "*" or re.match(r"\.*/[A-Za-z\./]*", uri) or 'cs531-cs_cbrad022' in uri):
        print('Fails 6 check')
        print(uri)
        return ()
    if not bool(re.match(r'HTTP/\d\.\d', http_version)):
        return ()
    
    # Ensure Host header is included exactly once
    if sum(1 for header in headers if b'Host: ' in header) != 1:
        print('Fails 2 check')
        return ()
    
    keep_alive = True
    
    if b'Connection: close' in headers:
        keep_alive = False
    else:
        print("keep alive is still true")
    
    return (method, uri, http_version, headers, keep_alive)

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
    return b'Date: ' + time_bytes + CRLF

# Generate Content-Length header given a valid uri
def generate_content_length(valid_uri: str) -> bytes:
    file_size = os.path.getsize(valid_uri)
    return b'Content-Length: ' + str(file_size).encode('ascii') + CRLF

# Generate Content-Type header given a valid uri
def generate_content_type(valid_uri: str) -> bytes:
    content_type = b''
    for mime_type in mime_types.keys():
        if valid_uri.endswith(mime_type):
            content_type += mime_types[mime_type]
    if content_type == b'':
        content_type += b'application/octet-stream'
    
    return b'Content-Type: ' + content_type + CRLF

# Generate Last-Modified header given a valid uri
def generate_last_modified(valid_uri: str):
    time_since_epoch = os.path.getmtime(valid_uri)
    last_m_time = time.strftime("%a, %d %b %Y %I:%M:%S GMT", time.localtime(time_since_epoch))
    time_bytes = last_m_time.encode('ascii')
    return b'Last-Modified: ' + time_bytes + CRLF

# Generate Server header
def generate_server() -> bytes:
    return b'Server: calebsserver' + CRLF
    
# Generate Allow header
def generate_allow() -> bytes:
    return b'Allow: GET, HEAD, OPTIONS, TRACE\r\n'

# Generate status code
def generate_status_code(status_code: int) -> bytes:
    return b'HTTP/1.1 ' + status_codes[str(status_code)] + CRLF

# Generate generic response headers not associated with content
def generate_error_response(status: int) -> bytes:
    full_response = b''
    full_response += generate_status_code(status)
    full_response += generate_date_header()
    full_response += generate_server()
    full_response += b'Connection: close' + CRLF
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

# Generate location header given the proper uri for a redirect
def generate_location(redirect_uri: str) -> bytes:
    return b'Location: ' + redirect_uri.encode('ascii') + CRLF

# Generate all response headers associated with a redirect status
def generate_redirect_headers(redirect_uri: str, status_code: int):
    real_uri = redirect_uri.split(WEBROOT)[1]
    headers = b''
    headers += generate_status_code(status_code)
    headers += generate_date_header()
    headers += generate_server()
    headers += generate_location(real_uri)
    return headers

# Check if a resource exists, given a normalized uri (relative path)
def check_resource(uri: str) -> bool:
    return exists(uri)

# def generate_directory_listing(directory_uri: str):


def generate_payload(valid_uri: str) -> bytes:
    with open(valid_uri, 'rb') as f:
        file_contents = b''
        byte = b''
        while True:
            byte = f.read(1)
            file_contents += byte
            if not byte:
                break
    return file_contents

def write_to_log(addr: str, request: bytes, status: int, uri: str):
    log_entry = b''
    log_entry += addr.encode('ascii') + b' - - '
    log_entry += time.strftime("[%d/%b/%Y:%H:%M:%S %z", time.gmtime()).encode('ascii') + b'] '
    log_entry += b'"' + request + b'" '
    log_entry += str(status).encode('ascii') + b' '
    if exists(uri):
        content_length = os.path.getsize(uri)
        log_entry += str(content_length).encode('ascii')
    log_entry += b'\n'
    with open('./access.log', 'a') as f:
        f.write(log_entry.decode("utf-8"))
    
def main(argv):
    HOST = config["ADDRESS"]
    if not argv:
         PORT = config["PORT"]
    else:
         PORT = int(argv[0])

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT} for HTTP connections")
    while True:
        keep_alive = False
        while True:
            try:
                if not keep_alive:
                    conn, addr = s.accept()
                    print(f"Connected to {addr}")
                data = b""
                conn.settimeout(float(TIMEOUT))
                while True:
                    data_frag = conn.recv(1024)
                    data += data_frag
                    if len(data_frag) < 1024:   
                        break
                data = data.decode('unicode_escape').encode("raw_unicode_escape")
                print(data)
                if b'\r\n\r\n\r\n' in data:
                    data = data[:-2]
                print(data)
                requests = data.split(CRLFCRLF)[:-1]
                print(requests)
                print(len(requests))
                print(requests)
                for request in requests:   
                    try:
                        method, uri, version, headers, keep_alive = validate_and_get_request_info(request)
                    except ValueError:
                        conn.send(generate_error_response(400) + CRLF)
                        conn.close()
                        break

                    request_line = data.split(CRLF)[0]
                    # Handle TRACE execution
                    if method == "TRACE":
                        conn.send(generate_error_response(200))
                        conn.send(b'Content-Type: message/http\r\n\r\n')
                        conn.send(data)
                        write_to_log(addr[0], request_line, 200, uri)
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    # Return error responses if appropriate
                    if not check_method(method):
                        conn.send(generate_error_response(501) + CRLF)
                        write_to_log(addr[0], request_line, 501, uri)
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    if not check_version(version):
                        conn.send(generate_error_response(505) + CRLF)
                        write_to_log(addr[0], request_line, 505, uri)
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    if uri in virtual_uris.keys():
                        conn.send(generate_status_code(200))
                        conn.send(generate_success_response_headers(virtual_uris[uri]) + CRLF)
                        conn.send(CRLF + generate_payload(virtual_uris[uri]))
                        write_to_log(addr[0], request_line, 200, virtual_uris[uri])
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    if not check_resource(uri):
                        conn.send(generate_error_response(404) + CRLF)
                        conn.send(uri.encode('ascii'))
                        write_to_log(addr[0], request_line, 404, uri)
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    if isdir(uri) and uri[-1] != '/':
                        conn.send(generate_redirect_headers(uri + '/', 301))
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    # Handle OPTIONS execution
                    if method == "OPTIONS":
                        conn.send(generate_error_response(200))
                        conn.send(generate_allow() + CRLF)
                        write_to_log(addr[0], request_line, 200, uri)
                    # Handle HEAD execution
                    elif method == "HEAD":
                        conn.send(generate_status_code(200))
                        conn.send(generate_success_response_headers(uri) + CRLF)
                        write_to_log(addr[0], request_line, 200, uri)
                    # Handle GET execution
                    elif method == "GET":
                        if isdir(uri):
                            if uri[-1] != '/':
                                conn.send(generate_redirect_headers(uri + '/', 301))
                                if not keep_alive:
                                    conn.close()
                                    break
                            elif exists(uri + DEFAULTRESOURCE):
                                uri = uri + DEFAULTRESOURCE
                                conn.send(generate_status_code(200))
                                conn.send(generate_success_response_headers(uri) + CRLF)
                                conn.send(generate_payload(uri))
                        else:
                            conn.send(generate_status_code(200))
                            conn.send(generate_success_response_headers(uri) + CRLF)
                            mime_type = generate_content_type(uri)
                            conn.send(generate_payload(uri))
                            
                        write_to_log(addr[0], request_line, 200, uri)
                    if not keep_alive:
                        conn.close()
                        break
            except socket.timeout:
                conn.send(generate_error_response(408))
                conn.send(b'Connection: close')
                conn.close()
                write_to_log(addr[0], b"", 408, b"")
                break
            except Exception as e:
                print(str(e))
                conn.send(generate_error_response(500) + CRLF)
                write_to_log(addr[0], request_line, 500, uri)
                conn.close()
                break


    # GET /caleb.jpeg HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
    # GET /indx.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\n\r\n
    # GET /test/ HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
    # HEAD /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\n\r\nGET /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
    # GET /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
    # GET /.well-known/access.log HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
if __name__ == "__main__":
    main(sys.argv[1:])