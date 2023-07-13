#!/usr/bin/env python3
import logging
from logging import Logger
from pathlib import Path
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("wasp")

WASP_HOME = Path.home() / ".wasp"
WASP_HOME.mkdir(parents=False, exist_ok=True)

WASPS_PATH = WASP_HOME / "wasps"

WASP_BUILDS_PATH = WASP_HOME / "builds"

WASP_BASE_BUILD = WASP_HOME / "base_build" / "wasp_base"
