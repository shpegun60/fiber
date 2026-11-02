"""Explicit common-source inventory; no Git, compiler, or ABI inference.

get_runtime_source_paths(repo, roles) preserves requested role/source order.
get_runtime_source_inputs(repo, roles) also includes the manifest and both
actual reader files. Callers must additionally capture headers, compiler
dependencies, fixtures, and their own scripts; this is not a full build closure.

Existing Fiber consumers select engine/state/panic/legacy_compat. The additive
Context facade additionally selects facade_bridge. Optional configuration is
never added implicitly. Sources are selected, not discovered by directory glob.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from collections.abc import Iterable, Mapping


_PROVIDERS = ("engine", "state", "panic", "optional_configuration")
_COMPATIBILITY = ("legacy_compat", "facade_bridge")
_ROLES = _PROVIDERS + _COMPATIBILITY
_SOURCE = re.compile(r"(?:context|fiber)/[A-Za-z0-9_-]+\.c", re.ASCII)


class RuntimeSourceError(ValueError):
    """Malformed inventory, unsafe/missing input, or invalid role request."""


def _fail(kind: str, message: str) -> None:
    raise RuntimeSourceError(f"runtime_sources: {kind}: {message}")


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("schema", f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _keys(value: object, expected: tuple[str, ...], label: str) -> dict:
    if type(value) is not dict or set(value) != set(expected):
        _fail("schema", f"{label} requires exactly {', '.join(expected)}")
    return value


def _file(root: Path, relative: str) -> Path:
    current = root
    try:
        for part in relative.split("/"):
            current /= part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                _fail("path", f"reparse/symlink input is unsupported: {relative}")
        if not current.is_file():
            _fail("input", f"not a regular file: {relative}")
        resolved = current.resolve(strict=True)
        if not resolved.is_relative_to(root):
            _fail("path", f"input escapes repository: {relative}")
        return resolved
    except OSError as error:
        _fail("input", f"cannot read {relative}: {error}")


def _load(repository_root: str | os.PathLike) -> tuple[Path, dict[str, tuple[Path, ...]]]:
    try:
        root = Path(repository_root).resolve(strict=True)
        if not root.is_dir():
            _fail("input", "repository root is not a directory")
        manifest = _file(root, "tools/runtime_sources.json")
        data = json.loads(manifest.read_text(encoding="utf-8"), object_pairs_hook=_object,
                          parse_constant=lambda value: _fail("schema", f"invalid JSON number {value}"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        _fail("schema", f"cannot load manifest: {error}")
    data = _keys(data, ("schema_version", "providers", "compatibility"), "root")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _fail("schema", "schema_version must be integer 1")
    providers = _keys(data["providers"], _PROVIDERS, "providers")
    compatibility = _keys(data["compatibility"], _COMPATIBILITY, "compatibility")
    paths = {}
    seen = set()
    for role in _ROLES:
        if role in _PROVIDERS:
            entries = [providers[role]]
        else:
            entries = compatibility[role]
            if type(entries) is not list:
                _fail("provider", f"{role} must be an array")
        resolved = []
        for relative in entries:
            if type(relative) is not str or _SOURCE.fullmatch(relative) is None:
                _fail("path", f"{role} requires a canonical context/*.c or fiber/*.c path")
            key = relative.casefold()
            if key in seen:
                _fail("provider", f"duplicate source provider: {relative}")
            seen.add(key)
            resolved.append(_file(root, relative))
        paths[role] = tuple(resolved)
    return manifest, paths


def _select(paths: dict[str, tuple[Path, ...]], roles: Iterable[str]) -> tuple[Path, ...]:
    if isinstance(roles, str):
        roles = (roles,)
    if isinstance(roles, (bytes, Mapping)):
        _fail("role", "roles must be a role name or an ordered iterable of role names")
    try:
        requested = tuple(roles)
    except TypeError:
        _fail("role", "roles must be an iterable of role names")
    seen = set()
    result = []
    for role in requested:
        if type(role) is not str or role not in _ROLES:
            _fail("role", f"unknown role: {role!r}")
        if role in seen:
            _fail("role", f"duplicate requested role: {role}")
        seen.add(role)
        result.extend(paths[role])
    return tuple(result)


def get_runtime_source_paths(repository_root: str | os.PathLike,
                             roles: Iterable[str]) -> tuple[Path, ...]:
    """Validate the entire inventory and return only explicitly requested roles."""
    _, paths = _load(repository_root)
    return _select(paths, roles)


def get_runtime_source_inputs(repository_root: str | os.PathLike,
                              roles: Iterable[str]) -> tuple[Path, ...]:
    """Return receipt paths, including actual readers; not a dependency closure."""
    manifest, paths = _load(repository_root)
    selected = _select(paths, roles)
    reader = Path(__file__).resolve(strict=True)
    counterpart = _file(reader.parent, "runtime_sources.ps1")
    return (manifest, counterpart, reader, *selected)
