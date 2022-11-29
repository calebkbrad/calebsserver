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
import base64
import subprocess
from urllib.parse import unquote

CRLF = b'\r\n'
CRLFCRLF = b'\r\n\r\n'

config = yaml.safe_load(open("./settings/config.yml"))
WEBROOT = config["WEBROOT"]
TIMEOUT = config["TIMEOUT"]
DEFAULTRESOURCE = config["DEFAULTRESOURCE"]
REDIRECTFILE = config["REDIRECTS"]
LANGUAGES = config["LANGUAGES"]
CHARSETS = config["CHARSETS"]
DIRECTORYPROTECT = config["DIRECTORYPROTECT"]
PRIVATEKEY = config["PRIVATEKEY"].encode('ascii')

# Parse redirect regex config file
with open(REDIRECTFILE, 'r') as f:
    redirects = []
    for line in f.readlines():
        redirect = line.split()
        redirect[0] = int(redirect[0][:-1])
        redirects.append(redirect)

# Parse content language config file
with open(LANGUAGES, 'r') as f:
    languages = []
    for line in f.readlines():
        languages.append('.' + line.strip())

with open(CHARSETS, 'r') as f:
    charsets = {}
    for line in f.readlines():
        separate = line.split()
        charsets.update({separate[0]: separate[1]})

# Dictionary of status codes
status_codes = {
    "200": b"200 OK",
    "201": b'201 Created',
    "206": b'206 Partial Content',
    "300": b'300 Multiple Choice',
    "301": b"301 Moved Permanently",
    "302": b"302 Found",
    "304": b"304 Not Modified",
    "400": b"400 Bad Request",
    "401": b'401 Unauthorized',
    "403": b"403 Forbidden",
    "404": b"404 Not Found",
    "405": b'405 Method Not Allowed',
    "406": b'406 Not Acceptable',
    "408": b"408 Request Timeout",
    "411": b'411 Length Required',
    "412": b"412 Precondition Failed",
    "413": b'413 Request Entity Too Large',
    "414": b'414 Request-URI Too Long',
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
            # print(option)
            attr, qval = option.split(';')
            qval = float(qval.split('q=')[1])
            value_pair.append(attr)
            value_pair.append(qval)
        accept.append(value_pair)
    return accept

# Check if authentication is needed to access a resource. Return path to auth file if found
def check_if_auth(uri: str) -> str:
    uri_components = uri.split('/')[3:]
    # print(uri_components)
    dir_to_check = WEBROOT
    found_uri = ""
    if exists(dir_to_check +  '/' + DIRECTORYPROTECT):
        found_uri = dir_to_check + '/' + DIRECTORYPROTECT
    for component in uri_components:
        # print("in loop")
        dir_to_check = dir_to_check + '/' + component
        print(dir_to_check)
        if not isdir(dir_to_check):
            # print('breaking')
            continue
        if exists(dir_to_check + '/' + DIRECTORYPROTECT):
            found_uri = dir_to_check + '/' + DIRECTORYPROTECT

    return found_uri

# Given the path to an "auth" file, extract relevent information
def parse_auth_file(path_to_auth: str) -> tuple:
    with open(path_to_auth, 'r') as f:
        contents = f.readlines()
    contents = [line.strip() for line in contents if '#' not in line]

    auth_type = ""
    realm = ""
    users = []
    allow = ['GET', 'HEAD', 'TRACE', 'OPTIONS', 'POST']
    for line in contents:
        # print(line)
        if 'authorization-type' in line:
            auth_type = line.split('=')[1]
        elif 'realm' in line:
            realm = line.split('=')[1]
        elif 'ALLOW' in line:
            allow.append(line.split('ALLOW-')[1])
        else:
            users.append(line)
    if auth_type and realm and users:
        return (auth_type, realm, users, allow)
    return ()

def validate_and_get_request_info(http_request: bytes) -> tuple:
    request_and_headers = http_request.split(CRLF)
    request = request_and_headers[0].decode('utf-8')
    headers = request_and_headers[1:]
    
    request_line_elements = request.split(' ')
    if len(request_line_elements) != 3:
        print('Fails 4 check')
        return ()
    method = request_line_elements[0]
    orig_uri = request_line_elements[1]
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
    auth = b''
    auth_type = ""
    realm = ""
    users = []
    allow = []
    payload_length = -1
    print(exists(uri))
    print("auth_file is " + check_if_auth(uri))
    if (exists(uri) and check_if_auth(uri)) or method == "PUT" or method == "DELETE":
        try:
            path_to_auth = check_if_auth(uri)
            auth_type, realm, users, allow = parse_auth_file(path_to_auth)
        except:
            allow = ["GET", "HEAD", "TRACE", "OPTIONS", "POST"]
    else:
        allow = ["GET", "HEAD", "TRACE", "OPTIONS", "POST"]

    for header in headers:
        if b'Range:' in header:
            try:
                range_string = header.split(b': bytes=')[1].decode('utf-8')
            except IndexError:
                print('index error happened')
                continue
            if len(list(filter(None, range_string.split('-')))) != 1:
                range_string = range_string.split('-')
                if len(range_string) > 2:
                    continue
                print(range_string)
                for num in range_string:
                    try:
                        byte_range.append(int(num))
                    except:
                        continue
            else:
                byte_range.append(int(range_string))
            print(byte_range)
            continue
        elif b'Accept' in header:
            try:
                key = header.decode('utf-8').split(':')[0]
                accept_headers.update({key: split_accepts(header)})
            except IndexError:
                print('index error happened')
                continue
        elif b'Authorization:' in header:
            if auth:
                return ()
            if b'Basic' in header:
                auth = header.split(b'Basic')[1].decode('utf-8').strip().encode('ascii')
                auth = base64.b64decode(auth)
            elif b'Digest' in header:
                # print('checking digest header')
                auth = header.split(b'Digest')[1].decode('utf-8').strip()
                digest_auth = {}
                auth_details = auth.split(',')
                for detail in auth_details:
                    key, value = detail.split('=')
                    digest_auth.update({key: value})
                # print(digest_auth)
                auth = digest_auth
        elif b'Content-Length' in header:
            payload_length = int(header.split(b'Content-Length: ')[1].decode('utf-8'))
        
    # print(accept_headers)
    return (method, uri, orig_uri, http_version, headers, keep_alive, byte_range, accept_headers, auth, auth_type, realm, users, allow, payload_length)

def generate_digest_response(auth_digest: dict, credential: str, method: str, uri: str) -> bytes:
    username = auth_digest['username'][1:-1]
    realm = auth_digest[' realm'][1:-1]
    nonce = auth_digest[' nonce'][1:-1]
    ncount = auth_digest[' nc']
    cnonce = auth_digest[' cnonce'][1:-1]
    qop = auth_digest[' qop']
    a1 = credential
    a2 = f'{method}:{uri}'

    # print(f'username:{username}')
    # print(f'realm:{realm}')
    # print(f'nonce:{nonce}')
    # print(f'ncount:{ncount}')
    # print(f'cnonce:{cnonce}')
    # print(f'qop:{qop}')
    # print(f'a1:{a1}')
    # print(f'a2:{a2}')

    hashed_a1 = hashlib.md5(a1.encode('ascii')).hexdigest()
    hashed_a2 = hashlib.md5(a2.encode('ascii')).hexdigest()
    prehashed_digest = f'{hashed_a1}:{nonce}:{ncount}:{cnonce}:{qop}:{hashed_a2}'
    # print(prehashed_digest)
    hashed_digest = hashlib.md5(prehashed_digest.encode('ascii')).hexdigest()
    # print(hashed_digest)
    return hashed_digest

def check_digest_auth(auth_digest: dict, auth_file: str, method: str, uri: str) -> bool:
    auth_type, realm, credentials, allow = parse_auth_file(auth_file)
    user_credential = ""
    for detail in auth_digest.keys():
        if 'realm' in detail:
            if realm in auth_digest[detail]:
                continue
            return False
        elif 'username' in detail:
            verified = False
            for credential in credentials:
                if auth_digest[detail][1:-1] in credential:
                    user_credential = credential
                    break
            if user_credential:
                continue
            return False
    response = auth_digest[' response'][1:-1]
    if generate_digest_response(auth_digest, credential, method, uri) == response:
        return True
    return False

# Check if a method is currently supported
def check_method(method: str, allow: list) -> bool:
    return method in allow

# Check if version 1.1 is being used
def check_version(http_version: str) -> bool:
    return http_version == "HTTP/1.1"

def generate_etag(valid_uri):
    hash_md5 = hashlib.md5()
    with open(valid_uri, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest().encode('ascii')

# Generate an etag using md5
def generate_etag_header(valid_uri: str) -> bytes:
    hash_md5 = hashlib.md5()
    with open(valid_uri, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return b'ETag: "' + generate_etag(valid_uri) + b'"' + CRLF

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
    uri_etag = generate_etag_header(valid_uri)[6:-2]
    etag_bytes = etag.encode('ascii')
    
    return etag_bytes == uri_etag

# Check if a resouce has multiple representations given a uri
def check_if_multiple_reps(uri: str) -> list:
    index_last_slash = uri.rfind('/')
    directory_uri = uri[:index_last_slash]
    resource = uri[index_last_slash:]
    try:
        possible_uris = listdir(directory_uri)
    except:
        return []
    existing_uris = []
    for possible_uri in possible_uris:
        # print(possible_uri)
        # print(resource)
        if resource[1:] in possible_uri:
            existing_uris.append(possible_uri)
    return existing_uris

def normalize_accept_encoding(accept_pairs: list):
    for pair in accept_pairs:
        if pair[0].strip() == "gzip":
            pair[0] = "gz"
        elif pair[0].strip() == "compress":
            pair[0] = "Z"

def normalize_accept_charset(accept_pairs: list):
    for pair in accept_pairs:
        for charset in charsets.keys():
            if charsets[charset] == pair[0].strip():
                pair[0] = charset

def parse_other_accepts(accept_pairs: list, possible_uris: list) -> str:
    existing_uris = []
    for pair in accept_pairs:
        pair_type = pair[0].strip()
        for uri in possible_uris:
            if pair_type in uri:
                existing_uris.append(pair)
                break
    
    if existing_uris:
        current_q_val = -1.0
        current_type = ""
        for pair in existing_uris:
            if len(pair) == 2:
                q_val = pair[1]
                if q_val == 0.0:
                    continue
                if current_q_val < q_val:
                    current_q_val = q_val
                    current_type = pair[0].strip()
                elif q_val == current_q_val:
                    return "multiple"
            else:
                current_type = pair[0].strip()
                current_q_val = 3.0
                break
        if current_q_val == -1.0 or current_q_val == 0.0:
            return ""
        else:
            return current_type
    return ""
    
# Given a dictionary of accepts, determines the uri with the highest q value (if applicable)
def parse_accepts(accept_dict: dict, uri: str) -> str:
    possible_uris = check_if_multiple_reps(uri)
    if not possible_uris:
        return ""
    

def generate_alternates_header(alternates: list):
    header = b'Alternates: '
    for rep in alternates:
        header += rep.encode('ascii') + b' '
    return header + CRLF


# Generate date header with current time
def generate_date_header() -> bytes:
    current_time = time.strftime("%a, %d %b %Y %I:%M:%S GMT", time.gmtime())
    time_bytes = current_time.encode('ascii')
    return b'Date: ' + time_bytes + CRLF

# Generate Content-Length header given a valid uri
def generate_content_length(valid_uri: str) -> bytes:
    file_size = os.path.getsize(valid_uri)
    return b'Content-Length: ' + str(file_size).encode('ascii') + CRLF

# Generate Content-Type header given a valid uri. Also generate Content-Language, Content-Encoding, and Charset-Encoding
def generate_content_type(valid_uri: str) -> bytes:
    content_type = b''
    content_lang = b''
    content_encoding = b''
    charset_encoding = b''
    for mime_type in mime_types.keys():
        if mime_type in valid_uri:
            content_type += mime_types[mime_type]
    if content_type == b'':
        content_type += b'application/octet-stream'
    else:
        for lang in languages:
            if lang in valid_uri:
                content_lang = lang.encode('ascii')[1:]
        if valid_uri.endswith('.Z'):
            content_encoding += b'compress'
        elif valid_uri.endswith('.gz'):
            content_encoding += b'gzip'
        for charset in charsets.keys():
            if charset in valid_uri:
                charset_encoding +=b'; charset=' + charsets[charset].encode('ascii')


    full_headers = b'Content-Type: ' + content_type + charset_encoding + CRLF
    if content_lang:
        full_headers += b'Content-Language: ' + content_lang + CRLF
    if content_encoding:
        full_headers += b'Content-Encoding: ' + content_encoding + CRLF

    return full_headers

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
def generate_allow(allow: list) -> bytes:
    header = b'Allow: '
    for method in allow:
        header += method.encode('ascii')
        if method != allow[-1]:
            header += b', '
    header += CRLF
    return header

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
def generate_error_response(status: int, method: str, alternates=[], allowed=[]) -> bytes:
    full_response = b''
    full_response += generate_status_code(status)
    full_response += generate_date_header()
    full_response += generate_server()
    if method == "TRACE":
        full_response += b'Content-Type: message/http' + CRLF
    elif method == "OPTIONS" or status == 405:
        full_response += generate_allow(allowed)
    if status != 200 or method == "DELETE":
        full_response +=  b'Content-Type: text/html' + CRLF
        full_response += b'Transfer-Encoding: chunked' + CRLF
    if alternates:
        full_response += generate_alternates_header(alternates)
    full_response += b'Connection: close' + CRLFCRLF
    if status != 200 and status != 304 and method == "GET":
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
    headers += generate_etag_header(uri)
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

def generate_unauthorized_response(auth_uri: str, uri: str, method: str) -> bytes:
    auth_type, realm, users, allow = parse_auth_file(auth_uri)
    full_response = generate_status_code(401)
    full_response += generate_date_header()
    full_response += generate_server()
    full_response += b'Transfer-Encoding: chunked' + CRLF
    if 'Basic' in auth_type:
        full_response += b'WWW-Authenticate: ' + auth_type.encode('ascii') + b' realm=' + realm.encode('ascii') + CRLF
        full_response += b'Content-Type: text/html' + CRLFCRLF
    elif 'Digest' in auth_type:
        etag = generate_etag(uri)
        time_stamp = generate_date_header()
        to_hash = time_stamp + b':' + etag + b':' + PRIVATEKEY
        hashed_nonce = hashlib.md5(to_hash).hexdigest().encode('ascii')
        to_encode_nonce = time_stamp + b' ' + hashed_nonce
        nonce = base64.b64encode(to_encode_nonce)

        opaque_to_hash = uri.encode('ascii') + b':' + PRIVATEKEY
        opaque = hashlib.md5(opaque_to_hash).hexdigest().encode('ascii')

        full_response += b'WWW-Authenticate: Digest realm=' + realm.encode('ascii') + b', '
        full_response += b'domain="' + uri.split(WEBROOT)[1].encode('ascii') + b'", '
        full_response += b'qop="auth", '
        full_response += b'nonce="' + nonce + b'", '
        full_response += b'algorithm="MD5", '
        full_response += b'opaque="' + opaque +b'"' + CRLF
        full_response += b'Content-Type: text/html' + CRLFCRLF

    if method == "GET":
        full_response += generate_error_payload(401)
    return full_response

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

def execute_script(executable_uri: str)-> bytes:
    result = subprocess.run(executable_uri, capture_output=True, text=True)
    encoded_result = result.stdout.encode('ascii')
    return encoded_result

def delete_resource(uri: str):
    if exists(uri):
        os.remove(uri)

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
                payloads = []
                for itr, request in enumerate(requests):
                    request_line = request.split(CRLF)[0]
                    if re.match("[A-Z]* (.)* HTTP/\d\.\d", request_line.decode('utf-8')):
                        continue
                    payloads.append(request)
                    request.pop(itr)
                for request in requests:   
                    try:
                        method, uri, orig_uri, version, headers, keep_alive, byte_range, accept_headers, auth, auth_type, realm, users, allow, payload_length = validate_and_get_request_info(request)
                    except ValueError as e:
                        conn.send(generate_error_response(400, "GET"))
                        conn.send(str(e).encode('ascii'))
                        conn.close()
                        print(str(e))
                        break
                    print(allow)
                    # for thing in allow:
                    #     conn.send(thing.encode('ascii'))
                    
                    request_line = data.split(CRLF)[0]
                    # Handle TRACE execution
                    if method == "TRACE":
                        conn.send(generate_error_response(200, "TRACE"))
                        conn.send(data)
                        write_to_log(addr[0], request_line, 200, uri)
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    # Return error responses if appropriate
                    if not check_method(method, allow):
                        if method in ['PUT', 'DELETE']:
                            conn.send(generate_error_response(405, "GET", allowed=allow))
                        else:
                            conn.send(generate_error_response(501, "GET") + CRLF)
                        write_to_log(addr[0], request_line, 501, uri)
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    if not check_version(version):
                        conn.send(generate_error_response(505, method) + CRLF)
                        write_to_log(addr[0], request_line, 505, uri)
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    
                    auth_file = check_if_auth(uri)
                    if auth_file and not auth:
                        conn.send(generate_unauthorized_response(auth_file, uri, method))
                        if not keep_alive:
                            conn.close()
                            break
                        continue
                    elif auth_file and auth:
                        # print('checking auth')
                        auth_type, realm, credentials, allow = parse_auth_file(auth_file)
                        # print('done checking auth')
                        # conn.send(b'Auth from header = ' + base64.b64decode(auth) + CRLF)
                        if "Basic" in auth_type:
                            authorized = False
                            user, pw = auth.split(b':')
                            encrypted = hashlib.md5(pw).hexdigest().encode('ascii')
                            auth_credential = user + b':' + encrypted
                            for credential in credentials:
                                # conn.send(b'Auth from file = ' + credential.encode('ascii') + CRLF)
                                if auth_credential == credential.encode('ascii'):
                                    authorized = True
                                    break
                            if not authorized:
                                conn.send(generate_unauthorized_response(auth_file, uri, method))
                                if not keep_alive:
                                    conn.close()
                                    break
                                continue
                        elif 'Digest' in auth_type:
                            if not check_digest_auth(auth, auth_file, method, orig_uri):
                                conn.send(generate_unauthorized_response(auth_file, uri, method))
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
                    potential_reps = check_if_multiple_reps(uri)
                    if not isdir(uri) and potential_reps:
                        already_processed = False
                        if accept_headers and not uri.endswith(".Z") and not uri.endswith(".gzip"):
                            for accept_header in accept_headers.keys():
                                if accept_header == "Accept-Encoding":
                                    normalize_accept_encoding(accept_headers[accept_header]) 
                                    # print("Accept Headers :" + str(accept_headers[accept_header]))
                                elif accept_header == "Accept-Charset":
                                    normalize_accept_charset(accept_headers[accept_header])
                                    # print("Accept Headers :" + str(accept_headers[accept_header]))
                                if accept_header != "Accept":
                                    negotiation = parse_other_accepts(accept_headers[accept_header], potential_reps)
                                    if negotiation == "":
                                        conn.send(generate_error_response(406, method))
                                        already_processed = True
                                        break
                                    elif negotiation == "multiple":
                                        conn.send(generate_error_response(300, method, alternates=potential_reps))
                                        already_processed = True
                                        break
                                    else:
                                        for rep in potential_reps:
                                            if rep == negotiation:
                                                directory_uri = uri[:uri.rfind('/')]
                                                uri = directory_uri + rep
                            if already_processed:
                                if not keep_alive:
                                    conn.close()
                                    break
                                continue
                                    
                        if len(potential_reps) > 1:
                            conn.send(generate_error_response(300, method, alternates=potential_reps))
                            if not keep_alive:
                                conn.close()
                                break
                            continue
                    if not check_resource(uri):
                        conn.send(generate_error_response(404, method) + CRLF)
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
                            # print(conditional)
                            if "Modified" in conditional:
                                if parse_if_modified_since(uri, conditional_headers[conditional]):
                                    continue
                                else:
                                    conn.send(generate_error_response(304, method) + CRLF)
                                    already_processed = True
                                    break
                            elif "Unmodified" in conditional:
                                if not parse_if_modified_since(uri, conditional_headers[conditional]):
                                    continue
                                else:
                                    conn.send(generate_error_response(412, method) + CRLF)
                                    already_processed = True
                                    break
                            elif "None" in conditional:
                                if not parse_if_match(uri, conditional_headers[conditional]):
                                    continue
                                else:
                                    conn.send(generate_error_response(304, method) + CRLF)
                                    already_processed = True
                                    break
                            elif "Match" in conditional:
                                if parse_if_match(uri, conditional_headers[conditional]):
                                    continue
                                else:
                                    conn.send(generate_error_response(412, method) + CRLF)
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
                        conn.send(generate_error_response(200, method, allowed=allow))
                        write_to_log(addr[0], request_line, 200, uri)
                    elif method == "GET" or method == "HEAD":
                        if not isdir(uri) and os.access(uri, os.X_OK) and method in ["POST", "GET", "HEAD"]:
                            conn.send(execute_script(uri))
                        elif isdir(uri):
                            if exists(uri + DEFAULTRESOURCE):
                                uri = uri + DEFAULTRESOURCE
                                conn.send(generate_status_code(200))
                                conn.send(generate_success_response_headers(uri) + CRLF)
                                if method == "GET":
                                    conn.send(generate_payload(uri))
                            else:
                                conn.send(generate_directory_response(uri))
                                if method == "GET":
                                    conn.send(generate_directory_listing(uri))
                        else:
                            if not byte_range:
                                conn.send(generate_status_code(200))
                                conn.send(generate_success_response_headers(uri) + CRLF)
                                if method == "GET":
                                    conn.send(generate_payload(uri))
                            else:
                                if len(byte_range) == 1:
                                    content_range = byte_range[0]
                                    payload = generate_payload(uri)[content_range:]
                                    length = len(payload)
                                    conn.send(generate_status_code(206))
                                    conn.send(generate_success_response_headers(uri, length) + CRLF)
                                    if method == "GET":
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
                                    if method == "GET":
                                        conn.send(payload)
                        write_to_log(addr[0], request_line, 200, uri)
                    elif method == "PUT":
                        pass
                    elif method == "DELETE":
                        delete_resource(uri)
                        conn.send(generate_error_response(200, method))

                    if not keep_alive:
                        conn.close()
                        break
            except socket.timeout:
                conn.send(generate_error_response(408, "GET") + CRLF)
                conn.close()
                write_to_log(addr[0], b"", 408, b"")
                break
            except Exception as e:
                print(str(e))
                sys.stderr.write(str(e))
                conn.send(generate_error_response(500, "GET") + CRLF)
                # write_to_log(addr[0], request_line, 500, uri)
                conn.send(str(e).encode('ascii'))
                conn.close()
                break


    # GET /nested2/index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\nAuthorization: Digest username="mln", realm="Colonial Place", uri="http://cs531-cs_cbrad022/a4-test/limited2/foo/bar.txt", qop=auth, nonce="RGF0ZTogVGh1LCAxNyBOb3YgMjAyMiAwMzoxMDo0MyBHTVQNCiA4ZDk1MDAwZWQwMjFiNmE5ZDhkNjE0ZGVlMWY1ODRjZQ", nc=00000001, cnonce="014a54548c61ba03827ef6a4dc2f7b4c", response="42d4d11ad7d46e2777305e6f3d069870"\r\n\r\n
    # GET /nested2/index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
    # GET /index HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nAccept: image/png; q=1.0\r\nAccept-Language: en; q=0.2, ja; q=0.8, ru\r\n\r\n
    # HEAD /index HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\nAccept-Charset: euc-jp; q=1.0, iso-2022-jp; q=0.0\r\n\r\n
    # HEAD /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\n\r\nGET /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
    # GET /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nIf-Unmodified-Since: Sat, 01 Oct 2022 10:20:37 GMT\r\nConnection: close\r\n\r\n
    # HEAD /index.html HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nIf-None-Match: "49c11da52d38c0512fb8169340db16f3"\r\nConnection: close\r\n\r\n
    # GET /.well-known/access.log HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
#     GET http://cs531-cs_cbrad022/a2-test/ HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n\r\n
    # DELETE /nested2/to_delete.txt HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\nAuthorization: Basic YmRhOmJkYQ==\r\n\r\n
    # DELETE /a5-test/index.html.denmark HTTP/1.1\r\nHost: cs531-cs_cbrad022\r\nConnection: close\r\n
if __name__ == "__main__":
    main(sys.argv[1:])