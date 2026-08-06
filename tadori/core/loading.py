"""Shared YAML-pack loading for the rule pack and the fixture set.

Both are the same shape: a list of files or directories, defaulting to a
bundled one, each file holding one or more YAML documents.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml


def yaml_documents(
    paths: list[Path] | None,
    default_dir: Path,
    *,
    kind: str,
    error: type[Exception],
) -> Iterator[tuple[Any, Path]]:
    """Yield ``(document, source path)`` for every non-empty document found.

    ``kind`` and ``error`` only shape the message and type raised when a path
    does not exist, so each caller keeps its own error vocabulary.
    """
    files: list[Path] = []
    for target in paths or [default_dir]:
        target = Path(target)
        if target.is_dir():
            files.extend(sorted(target.rglob("*.yml")) + sorted(target.rglob("*.yaml")))
        elif target.exists():
            files.append(target)
        else:
            raise error(f"{kind} path not found: {target}")

    for path in sorted(set(files)):
        for document in yaml.safe_load_all(path.read_text()):
            if document:
                yield document, path
