from __future__ import annotations

import json
import re
import threading
import time
from typing import TYPE_CHECKING

from snaffpy.types.Rule import Triage

if TYPE_CHECKING:
    from typing import Optional

    from snaffpy.types.Config import Config


COLORS = {
    Triage.BLACK: "\x1b[1;37;41m",
    Triage.RED: "\x1b[1;31m",
    Triage.YELLOW: "\x1b[1;33m",
    Triage.GREEN: "\x1b[1;32m",
}
RESET = "\x1b[0m"


class Logger(object):
    """Thread-safe console logger with triage colors and optional JSONL findings file."""

    config: Config
    outfile: Optional[str]

    def __init__(self, config: Config):
        super(Logger, self).__init__()
        self.config = config
        self.outfile = config.outfile
        self.__lock = threading.Lock()
        self.__fh = open(self.outfile, "a") if self.outfile else None

    def print(self, message: str = "", end: str = "\n"):
        clean = re.sub(r"\x1b\[[0-9;]+m", "", message)
        with self.__lock:
            print(clean if self.config.no_colors else message, end=end)

    def info(self, message: str):
        self.print("[\x1b[1;94minfo\x1b[0m] %s" % message)

    def warn(self, message: str):
        self.print("[\x1b[1;93mwarning\x1b[0m] %s" % message)

    def error(self, message: str):
        self.print("[\x1b[1;91merror\x1b[0m] %s" % message)

    def critical(self, message: str):
        self.print("[\x1b[1;97;41mcritical\x1b[0m] %s" % message)

    def debug(self, message: str):
        if self.config.debug:
            self.print("[\x1b[90mdebug\x1b[0m] %s" % message)

    def verbose(self, message: str):
        if self.config.verbose or self.config.debug:
            self.print("[\x1b[90mdebug\x1b[0m] %s" % message)

    def exception(self, message: str, err: Exception):
        self.error("%s: %s" % (message, err))
        if self.config.debug:
            import traceback
            self.print("\x1b[90m%s\x1b[0m" % traceback.format_exc().rstrip())

    def finding(self, host: str, share: str, path: str, size: int,
                triage: str, rule: str, snippet: str = ""):
        unc = "\\\\%s\\%s%s" % (host, share, path)
        extra = "  |  %s" % snippet if snippet else ""
        color = COLORS.get(triage, "")
        self.print("%s[%-6s]%s [%s] %s (%db)%s"
                   % (color, triage, RESET, rule, unc, size, extra))
        if self.__fh is not None:
            record = {"ts": time.time(), "host": host, "share": share,
                      "path": path, "size": size, "triage": triage,
                      "rule": rule, "match": snippet}
            with self.__lock:
                self.__fh.write(json.dumps(record) + "\n")
                self.__fh.flush()
