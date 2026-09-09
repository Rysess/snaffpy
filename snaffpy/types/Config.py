from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional


class Config(object):
    """Runtime configuration: scope, OPSEC pacing, and output settings."""

    port: int = 445
    timeout: int = 8
    interest: str = "Green"
    admin_shares: bool = False
    share_allow: list = []
    max_depth: int = 12
    max_file_size: int = 10 * 1024 * 1024
    no_content: bool = False
    acls: bool = False
    threads: int = 10
    delay: float = 0.0
    jitter: float = 0.0
    no_colors: bool = False
    verbose: bool = False
    debug: bool = False
    outfile: Optional[str] = None

    def __init__(self, **kwargs):
        super(Config, self).__init__()
        for key, value in kwargs.items():
            if value is not None and hasattr(self, key):
                setattr(self, key, value)
        if not self.share_allow:
            self.share_allow = []
