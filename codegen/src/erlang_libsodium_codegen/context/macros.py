"""Evaluate libsodium's constant size macros from its public headers.

Only platform-independent integer constants are resolved: expressions that
mention locals (such as `mlen`), function calls, or platform limits (such as
`SIZE_MAX`) evaluate to None. The generated C asserts every resolved value at
compile time, so a mistake here fails the build instead of producing a wrong
Erlang type.
"""

import re
from functools import cached_property
from pathlib import Path

DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)(\([^)]*\))?[ \t]*(.*)$")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
INTEGER = re.compile(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]*\b")
CAST = re.compile(r"\(\s*(?:unsigned\s+)?(?:long\s+long|long|int|char|size_t|u?int(?:8|16|32|64)_t)\s*\)")
SAFE = re.compile(r"^[0-9xXa-fA-F+\-*/%<>()?:,\s]*$")


class Macros:
    def __init__(self, include_dir: Path | None):
        self.include_dir = include_dir

    @cached_property
    def definitions(self) -> dict[str, str]:
        definitions: dict[str, str] = {}
        if self.include_dir is None:
            return definitions
        if not self.include_dir.is_dir():
            raise ValueError(f"libsodium headers not found at {self.include_dir}")
        for header in sorted(self.include_dir.rglob("*.h")):
            # Join continuation lines before matching definitions.
            text = header.read_text(encoding="utf-8").replace("\\\n", " ")
            for line in text.splitlines():
                match = DEFINE.match(line)
                if match and match.group(2) is None and match.group(3).strip():
                    definitions.setdefault(match.group(1), match.group(3).split("/*")[0].split("//")[0].strip())
        return definitions

    def value(self, expression: str) -> int | None:
        return self._evaluate(expression, ())

    def _evaluate(self, expression: str, seen: tuple[str, ...]) -> int | None:
        expression = expression.replace("SODIUM_MIN", "min")
        expression = CAST.sub("", expression)
        expression = INTEGER.sub(lambda m: str(int(m.group(1), 0)), expression)
        for name in sorted(set(IDENTIFIER.findall(expression)) - {"min"}, key=len, reverse=True):
            if name in seen or name not in self.definitions:
                return None
            value = self._evaluate(self.definitions[name], (*seen, name))
            if value is None:
                return None
            expression = re.sub(rf"\b{name}\b", str(value), expression)
        # Only arithmetic on integers remains; C's conditional operator is not supported.
        if not SAFE.match(expression.replace("min", "")) or "?" in expression:
            return None
        try:
            result = eval(expression.replace("/", "//"), {"__builtins__": {}}, {"min": min})  # noqa: S307
        except Exception:
            return None
        return result if isinstance(result, int) and result >= 0 else None
