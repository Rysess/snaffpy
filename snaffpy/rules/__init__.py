from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from snaffpy.rules.DefaultRules import default_rules
from snaffpy.types.Rule import Rule

if TYPE_CHECKING:
    from typing import Optional

    from snaffpy.core.Logger import Logger

PACKAGED_RULES = os.path.join(os.path.dirname(__file__), "default_rules.json")
ENV_RULES = "SNAFFPY_RULES"


def packaged_rules_path() -> str:
    return PACKAGED_RULES


def _rules_from_file(path: str) -> list[Rule]:
    with open(path) as fh:
        return [Rule(**entry) for entry in json.load(fh)]


def load_rules(path: str) -> list[Rule]:
    return _rules_from_file(path)


def load_default_rules(logger: Optional[Logger] = None) -> list[Rule]:
    """Load rules from SNAFFPY_RULES, else the install-dir JSON, else the built-in set."""
    path = os.environ.get(ENV_RULES) or PACKAGED_RULES
    try:
        rules = _rules_from_file(path)
        if logger is not None:
            logger.verbose("loaded %d rule(s) from %s" % (len(rules), path))
        return rules
    except FileNotFoundError:
        if logger is not None:
            logger.verbose("no rules file at %s, using built-in defaults" % path)
        return default_rules()
    except Exception as err:
        if logger is not None:
            logger.exception("failed to parse rules at %s, using built-in defaults" % path, err)
        return default_rules()


def dump_rules(path: str) -> None:
    with open(path, "w") as fh:
        json.dump([r.to_dict() for r in default_rules()], fh, indent=2)


__all__ = [
    "default_rules", "load_rules", "load_default_rules", "dump_rules",
    "packaged_rules_path", "PACKAGED_RULES", "ENV_RULES",
]
