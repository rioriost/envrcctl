from __future__ import annotations

from pathlib import Path
from typing import Dict


class DummyBackend:
    def __init__(self) -> None:
        self._store: Dict[tuple[str, str], str] = {}

    def get(self, ref) -> str:
        return self._store[(ref.service, ref.account)]

    def get_with_auth(self, ref, reason: str | None = None) -> str:
        return self.get(ref)

    def get_many_with_auth(self, refs, reason: str | None = None):
        return {
            (ref.service, ref.account): self._store[(ref.service, ref.account)]
            for ref in refs
        }

    def set(self, ref, value: str) -> None:
        self._store[(ref.service, ref.account)] = value

    def delete(self, ref) -> None:
        self._store.pop((ref.service, ref.account), None)

    def list(self, prefix: str | None = None):
        return []


def read_envrc(path: Path) -> str:
    return path.read_text(encoding="utf-8")
