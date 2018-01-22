
import subprocess
import requests
import json
import sys
import parsy

from base64 import b64encode, b64decode

SERVER_URL = 'http://127.0.0.1:5000/compilations'

def encode_bytes(data: bytes):
    return b64encode(data).decode()

def decode_bytes(data: str):
    return b64decode(data.encode())

def encode_file(path):
    with open(path, 'rb') as f:
        return encode_bytes(f.read())

def get_output_path(args):
    out = None
    any_string = parsy.regex(r'[0-9a-zA-Z_\-"/\\?.]*')
    output_switch = parsy.string('-o')
    previous = None
    for current in args:
        if previous is None:
            previous = current
            continue

        try:
            output_switch.parse(previous)
            out = any_string.parse(current)
            return out
        except:
            previous = current
    return 'a'


def try_to_remove_output_options(flags, input_paths):
    try:
        flags.remove('-o')
    except:
        pass
    try:
        input_paths.remove(output_path)
    except:
        pass

def add_if_unique(l, element):
    for elem in l:
        if elem == element:
            return
    l.append(element)

def send_headers_from_response(encoded_files, response_json):
    additional_headers = [decode_bytes(header) for header in response_json['requiredHeaders']]
    encoded_extra_headers = [{'path': path.decode(), 'data': encode_file(path)} for path in additional_headers]
    for header in encoded_extra_headers:
        add_if_unique(encoded_files, header)
    return json.loads(
        requests.post(
            SERVER_URL,
            json={
                'options': flags,
                'files': encoded_files
            }
        ).json()
    )


if __name__ == "__main__":
    flags = [arg for arg in sys.argv[1:] if arg[0] == '-']
    input_paths = [arg for arg in sys.argv[1:] if arg[0] != '-']

    output_path = get_output_path(sys.argv[1:])
    try_to_remove_output_options(flags, input_paths)

    encoded_files = [ {'path': path, 'data': encode_file(path)} for path in input_paths ]
    response = requests.post(
        SERVER_URL,
        json={
            'options': flags,
            'files': encoded_files
        }
    ).json()

    response_json = json.loads(response)
    while 'requiredHeaders' in response_json.keys():
        try:
            response_json = send_headers_from_response(encoded_files, response_json)
        except:
            print('Cannot find one of included headers')
            sys.exit(1)

    if 'outputFile' in response_json.keys():
        with open(output_path, 'wb+') as f:
            f.write(decode_bytes(response_json['outputFile']))

        for message in response_json['compilationMessages']:
            print(message)
    else:
        print(response_json['errorMessage'])