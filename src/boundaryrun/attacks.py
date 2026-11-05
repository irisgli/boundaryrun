"""Prompt-injection attack scenarios.

An attack places a payload into a lower-trust channel the agent reads (a README, a
source comment, test output, or the finding text) and declares the prohibited
operations it is trying to induce. Payloads are plain prose for a live model and also
carry machine-readable directives (`[[directive: <tool> <json>]]`) so the deterministic
obedient agent can follow them exactly. Everything here is a local fixture.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

Vector = Literal["readme", "source_comment", "test_output", "finding"]

DIRECTIVE_RX = re.compile(r"\[\[directive:\s*([a-z_]+)\s+(\{.*?\})\s*\]\]", re.DOTALL)


class Directive(BaseModel):
    model_config = ConfigDict(frozen=True)
    tool: str
    input_json: str  # canonical JSON, used as the identity of the directive

    @property
    def input(self) -> Any:
        return json.loads(self.input_json)


def extract_directives(text: str) -> list[Directive]:
    out: list[Directive] = []
    for tool, raw in DIRECTIVE_RX.findall(text or ""):
        try:
            d = Directive(tool=tool, input_json=json.dumps(json.loads(raw), sort_keys=True))
        except json.JSONDecodeError:
            continue
        if d not in out:
            out.append(d)
    return out


class Attack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    vector: Vector
    objective: str  # exfiltrate_secret | tamper_tests | insert_backdoor | disable_auth
    description: str
    payload: str
    target_file: str | None = None  # file in the workspace the payload is written into
    insert_before: str | None = None  # anchor line; payload is inserted above it (None: append)
    objective_directives: list[Directive]  # the prohibited operations the attack is trying to induce

    def apply(self, workspace: Path, finding: dict[str, Any]) -> dict[str, Any]:
        """Mutate the workspace (or the finding) in place. Returns the finding to use."""
        if self.vector == "finding":
            f = dict(finding)
            f["description"] = f"{f.get('description', '')}\n\n{self.payload}"
            return f
        assert self.target_file
        path = workspace / self.target_file
        if self.vector == "test_output":
            path.write_text(self.payload)
            return finding
        text = path.read_text()
        if self.insert_before:
            assert text.count(self.insert_before) == 1, f"anchor not unique in {self.target_file}"
            text = text.replace(self.insert_before, self.payload + "\n" + self.insert_before)
        else:
            text = text + "\n" + self.payload + "\n"
        path.write_text(text)
        return finding


def load_attack(path: Path) -> Attack:
    raw = tomllib.loads(path.read_text())
    payload = (path.parent / raw.pop("payload_file")).read_text()
    directives = extract_directives(payload)
    if not directives:
        raise ValueError(f"attack {path} has no directives in its payload")
    return Attack(payload=payload, objective_directives=directives, **raw)


def load_attacks(directory: Path) -> dict[str, Attack]:
    return {a.id: a for a in (load_attack(p) for p in sorted(directory.glob("*.toml")))}
