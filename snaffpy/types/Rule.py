from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional


class Triage(object):
    """Ordered severity levels, mirroring Snaffler (Black > Red > Yellow > Green)."""

    BLACK = "Black"
    RED = "Red"
    YELLOW = "Yellow"
    GREEN = "Green"

    ORDER = {"Green": 0, "Yellow": 1, "Red": 2, "Black": 3}

    @classmethod
    def rank(cls, level: str) -> int:
        return cls.ORDER.get(level, 0)


class Scope(object):
    SHARE = "share"
    DIRECTORY = "directory"
    FILE = "file"
    CONTENT = "content"


class Rule(object):
    """A single classifier rule applied at one stage of the snaffle pipeline."""

    name: str
    scope: str
    location: str
    match: str
    words: list
    triage: str
    action: str

    def __init__(
        self,
        name: str,
        scope: str,
        location: str,
        match: str,
        words: list,
        triage: str,
        action: str = "snaffle",
    ):
        super(Rule, self).__init__()
        self.name = name
        self.scope = scope
        self.location = location
        self.match = match
        self.words = words
        self.triage = triage
        self.action = action
        self.__compiled = None
        self.compile()

    def compile(self) -> "Rule":
        if self.match == "regex":
            self.__compiled = [re.compile(w, re.I) for w in self.words]
        else:
            self.__compiled = [w.lower() for w in self.words]
        return self

    def test(self, value: str) -> tuple[bool, Optional[str]]:
        """Return (matched, snippet) for value against this rule's patterns."""
        if self.match == "regex":
            for pattern in self.__compiled:
                found = pattern.search(value)
                if found:
                    return True, found.group(0)[:200]
            return False, None

        candidate = value.lower()
        for word in self.__compiled:
            if self.match == "exact" and candidate == word:
                return True, word
            if self.match == "endswith" and candidate.endswith(word):
                return True, word
            if self.match == "startswith" and candidate.startswith(word):
                return True, word
            if self.match == "contains" and word in candidate:
                return True, word
        return False, None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "scope": self.scope,
            "location": self.location,
            "match": self.match,
            "words": self.words,
            "triage": self.triage,
            "action": self.action,
        }
