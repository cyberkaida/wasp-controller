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
