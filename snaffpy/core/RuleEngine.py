from __future__ import annotations

from typing import TYPE_CHECKING

from snaffpy.types.Rule import Scope, Triage

if TYPE_CHECKING:
    from typing import Optional

    from snaffpy.types.Rule import Rule


class RuleEngine(object):
    """Applies rules across the share -> directory -> file -> content pipeline."""

    def __init__(self, rules: list[Rule], interest: str = Triage.GREEN):
        super(RuleEngine, self).__init__()
        self.min_rank = Triage.rank(interest)
        self.share_rules = [r for r in rules if r.scope == Scope.SHARE]
        self.dir_rules = [r for r in rules if r.scope == Scope.DIRECTORY]
        self.file_rules = [r for r in rules if r.scope == Scope.FILE]
        self.grep_selectors = [r for r in rules if r.scope == Scope.CONTENT and r.action == "grep"]
        self.grep_rules = [r for r in rules if r.scope == Scope.CONTENT and r.location == "content"]

    def share_allowed(self, share: str) -> bool:
        for rule in self.share_rules:
            hit, _ = rule.test(share)
            if hit and rule.action == "discard":
                return False
        return True

    def dir_allowed(self, path: str) -> bool:
        for rule in self.dir_rules:
            hit, _ = rule.test(path)
            if hit and rule.action == "discard":
                return False
        return True

    def classify_file(self, name: str, ext: str, path: str) -> Optional[tuple[str, str]]:
        best = None
        values = {"filename": name, "fileext": ext, "filepath": path}
        for rule in self.file_rules:
            hit, _ = rule.test(values[rule.location])
            if hit and (best is None or Triage.rank(rule.triage) > Triage.rank(best[0])):
                best = (rule.triage, rule.name)
        return best

    def wants_content(self, ext: str) -> bool:
        return any(rule.test(ext)[0] for rule in self.grep_selectors)

    def grep_content(self, text: str) -> list[tuple[str, str, str]]:
        results = []
        for rule in self.grep_rules:
            hit, snippet = rule.test(text)
            if hit:
                results.append((rule.triage, rule.name, snippet))
        return results

    def reportable(self, triage: str) -> bool:
        return Triage.rank(triage) >= self.min_rank
