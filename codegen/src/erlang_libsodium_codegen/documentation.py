"""Evaluate documentation against the built Erlang library in isolated VMs."""

import json
from pathlib import Path
import re
import subprocess
import tempfile


class ErlangExamples:
    def __init__(self, library_path: Path):
        self.library_path = library_path.resolve()
        self.requests: list[dict[str, str]] = []

    def reset(self) -> None:
        self.requests.clear()

    def expression(self, source: str, format: str = "term") -> str:
        if format not in ("term", "hex"):
            raise ValueError(f"Unsupported Erlang output format: {format}")
        token = f"@@LIBSODIUM_ERLANG_RESULT_{len(self.requests)}@@"
        self.requests.append({"source": source, "format": format})
        return token

    def resolve(self, markdown: str) -> str:
        if not self.requests:
            return markdown
        results = self.run(self.requests)
        for index, result in enumerate(results):
            markdown = markdown.replace(f"@@LIBSODIUM_ERLANG_RESULT_{index}@@", result)
        return markdown

    def verify(self, markdown: str, filename: str) -> None:
        blocks = re.findall(r"^```erlang\s*\n(.*?)^```\s*$", markdown, re.MULTILINE | re.DOTALL)
        if blocks:
            self.run([{"source": block, "format": "check"} for block in blocks])
            print(f"[E] {filename}: {len(blocks)} examples passed")

    def run(self, requests: list[dict[str, str]]) -> list[str]:
        if not (self.library_path / "libsodium.beam").is_file():
            raise ValueError(f"Built libsodium not found at {self.library_path}; run gmake first")
        driver = Path(__file__).with_name("erlang_examples.escript")
        with tempfile.TemporaryDirectory(prefix="libsodium-docs-") as directory:
            root = Path(directory)
            input_path = root / "input.json"
            output_path = root / "output.json"
            input_path.write_text(json.dumps(requests), encoding="utf-8")
            try:
                completed = subprocess.run(
                    ["escript", str(driver), str(self.library_path), str(input_path), str(output_path)],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    timeout=120,
                )
            except subprocess.TimeoutExpired as error:
                raise ValueError("Erlang documentation examples exceeded 120 seconds") from error
            if not output_path.is_file():
                raise ValueError(f"Erlang documentation VM failed:\n{completed.stdout}\n{completed.stderr}")
            result = json.loads(output_path.read_text(encoding="utf-8"))
            if completed.returncode != 0 or "error" in result:
                index = result.get("index", 0)
                source = requests[index]["source"] if index < len(requests) else ""
                raise ValueError(f"Erlang example {index + 1} failed:\n{source}\n{result.get('error', completed.stderr)}")
            if len(result["results"]) != len(requests):
                raise ValueError("Erlang documentation VM returned an incomplete result")
            return result["results"]
