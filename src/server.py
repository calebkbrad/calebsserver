#!/usr/bin/env python3
import socket
import sys
import re
import time
from os.path import exists, isdir
from os import listdir
import os
import yaml
import string
import hashlib
from urllib.parse import unquote

CRLF = b'\r\n'
CRLFCRLF = b'\r\n\r\n'

config = yaml.safe_load(open("./settings/config.yml"))
WEBROOT = config["WEBROOT"]
TIMEOUT = config["TIMEOUT"]
DEFAULTRESOURCE = config["DEFAULTRESOURCE"]
REDIRECTFILE = config["REDIRECTS"]

with open(REDIRECTFILE, 'r') as f:
    redirects = []
    for line in f.readlines():
        redirect = line.split()
        redirect[0] = int(redirect[0][:-1])
        redirects.append(redirect)

# Dictionary of status codes
status_codes = {
    "200": b"200 OK",
    "206": b'206 Partial Content',
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

# Given an accept header, split it up into appropriate content describer and q values
def split_accepts(header: bytes) -> list:
    accept_header = header.decode('utf-8')
    options = accept_header.split(':')[1]
    list_options = options.split(',')
    accept = []
    for option in list_options:
        value_pair = []
        if ';' not in option:
            value_pair.append(option)
        else:
            print(option)
            attr, qval = option.split(';')
            qval = float(qval.split('q=')[1])
            value_pair.append(attr)
            value_pair.append(qval)
        accept.append(value_pair)
    return accept

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

    byte_range = []
    accept_headers = {}
    for header in headers:
        if b'Range:' in header:
            try:
                range_string = header.split(b': bytes=')[1].decode('utf-8')
            except IndexError:
                print('index error happened')
                continue
            range_string = range_string.split('-')
            if len(range_string) > 2:
                continue
            for num in range_string:
                byte_range.append(int(num))
            continue
        elif b'Accept' in header:
            try:
                key = header.decode('utf-8').split(':')[0]
                accept_headers.update({key: split_accepts(header)})
            except IndexError:
                print('index error happened')
                continue

    print(accept_headers)

    
            

    
    return (method, uri, http_version, headers, keep_alive, byte_range, accept_headers)

# Check if a method is currently supported
def check_method(method: str) -> bool:
    return method in ['GET', 'HEAD', 'OPTIONS', 'TRACE']

# Check if version 1.1 is being used
def check_version(http_version: str) -> bool:
    return http_version == "HTTP/1.1"

# Generate an etag using md5
def generate_etag(valid_uri: str) -> bytes:
    hash_md5 = hashlib.md5()
    with open(valid_uri, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return b'ETag: "' + hash_md5.hexdigest().encode('ascii') + b'"' + CRLF

# Get all conditional headers from list of headers
def get_conditionals(headers: list) -> list:
    allowed_conditional_headers = [b'If-Modified-Since: ', b'If-Unmodified-Since: ', b'If-Match', b'If-None-Match']
    conditionals = {}
    for header in headers:
        if b'If-' in header:
            conditional = header.decode('utf-8')
            conditional = conditional.split(": ")
            conditionals.update({conditional[0]: conditional[1]})
    return conditionals

# Return whether or not an If-Modified-Since header should be respected
def parse_if_modified_since(valid_uri: str, conditional_time: str) -> bool:
    parsed_conditional_time = time.strptime(conditional_time, "%a, %d %b %Y %I:%M:%S GMT")
    last_m_since_epoch = os.path.getmtime(valid_uri)
    last_m_time = time.localtime(last_m_since_epoch)
    
    return last_m_time >= parsed_conditional_time

def parse_if_match(valid_uri: str, etag: str):
    uri_etag = generate_etag(valid_uri)[6:-2]
    etag_bytes = etag.encode('ascii')
    
    return etag_bytes == uri_etag

def parse_accept(uri: str, accept_element: list) -> str:
    if len(accept_element) == 1:
        possible_uri = uri + accept_element[0].split('/')
        if exists(uri + accept_element[0]):


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

def generate_error_payload(status_code: int) -> bytes:
    page = f'./errorpages/{str(status_code)}.html'
    with open(page, 'rb') as f:
        file_contents = b''
        byte = b''
        while True:
            byte = f.read(1)
            file_contents += byte
            if not byte:
                break
    return file_contents

# Generate generic response headers not associated with content
def generate_error_response(status: int) -> bytes:
    full_response = b''
    full_response += generate_status_code(status)
    full_response += generate_date_header()
    full_response += generate_server()
    full_response += b'Connection: close' + CRLF
    if status != 200 and status != 304:
        full_response +=  b'Content-Type: text/html' + CRLFCRLF
        full_response += generate_error_payload(status)
    return full_response

# Generate respones headers associated with found content
def generate_success_response_headers(uri: str, length=0) -> bytes:
    headers = b''
    headers += generate_date_header()
    headers += generate_server()
    headers += generate_content_type(uri)
    headers += generate_last_modified(uri)
    if length == 0:
        headers += generate_content_length(uri)
    else:
        bytes_length = str(length).encode('ascii')
        headers += b'Content-Length: ' + bytes_length + CRLF
    headers += generate_etag(uri)
    return headers

# Generate location header given the proper uri for a redirect
def generate_location(redirect_uri: str) -> bytes:
    return b'Location: ' + redirect_uri.encode('ascii') + CRLF

# Generate all response headers associated with a redirect status
def generate_redirect_headers(redirect_uri: str, status_code: int):
    if WEBROOT in redirect_uri:
        real_uri = redirect_uri.split(WEBROOT)[1]
    else:
        real_uri = redirect_uri
    headers = b''
    headers += generate_status_code(status_code)
    headers += generate_date_header()
    headers += generate_server()
    headers += generate_location(real_uri) + CRLFCRLF
    headers += generate_error_payload(status_code)
    return headers + CRLF

# Check if a resource exists, given a normalized uri (relative path)
def check_resource(uri: str) -> bool:
    return exists(uri)

def generate_directory_listing(directory_uri: str) -> bytes:
    list_table_elements = []
    for f in listdir(directory_uri):
        file_uri = directory_uri + f
        time_since_epoch = os.path.getmtime(file_uri)
        last_m_time = time.strftime("%a, %d %b %Y %I:%M:%S GMT", time.localtime(time_since_epoch))
        file_size = str(os.path.getsize(file_uri))
        table_row = f"<tr><td>{f}</td><td>{last_m_time}</td><td>{file_size}</td></tr>"
        list_table_elements.append(table_row)
    table_elements = "".join(list_table_elements)
    table = f"<html><table><tr><th>Name</th><th>Last Modified</th><th>Size</th></tr>{table_elements}</table></html>"
    
    return table.encode('ascii') + CRLF

def generate_directory_response(directory_uri: str) -> bytes:
    response = b''
    response += generate_status_code(200)
    response += generate_date_header()
    response += generate_server()
    response += b'Content-Type: text/html' + CRLF
    response += generate_last_modified(directory_uri)
    response += generate_content_length(directory_uri)
    return response + CRLF


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
                if b'\r\n\r\n\r\n' in data:
                    data = data[:-2]
                requests = data.split(CRLFCRLF)[:-1]
        
                for request in requests:   
                    try:
                        method, uri, version, headers, keep_alive, byte_range, accept_headers = validate_and_get_request_info(request)
                    except ValueError as e:
                        conn.send(generate_error_response(400))
                        conn.send(generate_error_payload(400))
                        conn.close()
                        print(str(e))
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
                    conditional_headers = get_conditionals(headers)
                    already_processed = False
                    for conditional in conditional_headers.keys():
                        try:
                            print(conditional)
                            if "Modified" in conditional:
                                if parse_if_modified_since(uri, conditional_headers[conditional]):
                                    continue
                                else:
                                    conn.send(generate_error_response(304) + CRLF)
                                    already_processed = True
                                    break
                            elif "Unmodified" in conditional:
                                if not parse_if_modified_since(uri, conditional_headers[conditional]):
                                    continue
                                else:
                                    conn.send(generate_error_response(412) + CRLF)
                                    already_processed = True
                                    break
                            elif "None" in conditional:
                                if not parse_if_match(uri, conditional_headers[conditional]):
                                    continue
                                else:
                                    conn.send(generate_error_response(304) + CRLF)
                                    already_processed = True
                                    break
                            elif "Match" in conditional:
                                if parse_if_match(uri, conditional_headers[conditional]):
                                    continue
                                else:
                                    conn.send(generate_error_response(412) + CRLF)
                                    already_processed = True
                                    break
                        except ValueError:
                            continue
                    if already_processed:
                        if not keep_alive:
                            conn.close()
                            break
                        continue

                    # Return redirect response if appropriate
                    if isdir(uri) and uri[-1] != '/':
                        conn.send(generate_redirect_headers(uri + '/', 301))
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    test_uri = uri.split(WEBROOT)[1]
                    for redirect in redirects:
                        match_object = re.match(redirect[1], test_uri)
                        if match_object:
                            redirect_uri = re.sub(redirect[1], redirect[2], test_uri)
                            conn.send(generate_redirect_headers(redirect_uri, redirect[0]))
                            test_uri = ''
                            break
                    if test_uri == '':
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
                        if isdir(uri):
                            if exists(uri + DEFAULTRESOURCE):
                                uri = uri + DEFAULTRESOURCE
                                conn.send(generate_status_code(200))
                                conn.send(generate_success_response_headers(uri) + CRLF)
                            else:
                                conn.send(generate_directory_response(uri))
                        else:
                            conn.send(generate_status_code(200))
                            conn.send(generate_success_response_headers(uri) + CRLF)
                            write_to_log(addr[0], request_line, 200, uri)
                    # Handle GET execution
                    elif method == "GET":
                        if isdir(uri):
                            if exists(uri + DEFAULTRESOURCE):
                                uri = uri + DEFAULTRESOURCE
                                conn.send(generate_status_code(200))
                                conn.send(generate_success_response_headers(uri) + CRLF)
                                conn.send(generate_payload(uri))
                            else:
                                conn.send(generate_directory_response(uri))
                                conn.send(generate_directory_listing(uri))
                        else:
                            if not byte_range:
                                conn.send(generate_status_code(200))
                                conn.send(generate_success_response_headers(uri) + CRLF)
                                conn.send(generate_payload(uri))
                            else:
                                if len(byte_range) == 1:
                                    content_range = byte_range[0]
                                    payload = generate_payload(uri)[content_range:]
                                    length = len(payload)
                                    conn.send(generate_status_code(206))
                                    conn.send(generate_success_response_headers(uri, length) + CRLF)
                                    conn.send(payload)
                                else:
                                    content_range_lower, content_range_upper = byte_range
                                    payload = generate_payload(uri)[content_range_lower:content_range_upper+1]
                                    length = len(payload)
                                    conn.send(generate_status_code(206))
                                    content_range_lower = str(content_range_lower).encode('ascii')
                                    content_range_upper = str(content_range_upper).encode('ascii')
                                    file_size = os.path.getsize(uri)
                                    conn.send(b'Content-Range: bytes ' + content_range_lower + b'-' + content_range_upper + b'/' + str(file_size).encode('ascii') + CRLF)
                                    conn.send(generate_success_response_headers(uri, length) + CRLF)
                                    conn.send(payload)
                            
                        write_to_log(addr[0], request_line, 200, uri)
                    if not keep_alive:
                        conn.close()
                        break
            except socket.timeout:
                conn.send(generate_error_response(408) + CRLF)
                conn.close()
                write_to_log(addr[0], b"", 408, b"")
                break
            except Exception as e:
                print(str(e))
                sys.stderr.write(str(e))
                conn.send(generate_error_response(500) + CRLF)
                # write_to_log(addr[0], request_line, 500, uri)
                conn.send(str(e).encode('ascii'))
                conn.close()
                break


    # GET /caleb.jpeg HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\nRange: bytes=800-\r\n\r\n
    # GET /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nAccept: image/png; q=1.0\r\nAccept-Language: en; q=0.2, ja; q=0.8, ru\r\n\r\n
    # HEAD /test2/ HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
    # HEAD /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\n\r\nGET /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
    # GET /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nIf-Unmodified-Since: Sat, 01 Oct 2022 10:20:37 GMT\r\nConnection: close\r\n\r\n
    # HEAD /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nIf-None-Match: "49c11da52d38c0512fb8169340db16f3"\r\nConnection: close\r\n\r\n
    # GET /.well-known/access.log HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
#     GET http://cs531-cs_cbrad022/a2-test/ HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
if __name__ == "__main__":
    main(sys.argv[1:])