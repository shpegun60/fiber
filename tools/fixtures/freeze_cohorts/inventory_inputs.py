"""Derive declared capture membership; no subprocesses, writes or proof claims."""
from pathlib import Path


CORE_INPUTS = frozenset((
    "tools/freeze_cohorts.py", "tools/freeze_cohorts.json",
    "tools/runtime_sources.py", "tools/runtime_sources.ps1", "tools/runtime_sources.json",
    "tools/fixtures/sensitive_port_closure/run.py",
))
SHARED_DIRECTORIES = ("", "context", "fiber", "fiber/port")


def required_inputs(repo, manifest, groups, reader, inventory):
    """Use current canonical providers and header membership, never receipt lists."""
    repo = Path(repo).resolve(strict=True)
    names = set(CORE_INPUTS)

    def local(path):
        path = Path(path)
        name = inventory.relative(path.absolute().relative_to(repo).as_posix())
        resolved = inventory.regular(path)
        inventory.need(resolved.is_relative_to(repo), "inventory-input-escaped")
        inventory.relative(resolved.relative_to(repo).as_posix())
        inventory.need(resolved == repo / name, "inventory-input-alias")
        names.add(name)

    for path in reader.get_runtime_source_inputs(repo, inventory.RUNTIME_ROLES):
        local(path)

    directories = {repo / name for name in SHARED_DIRECTORIES}
    for group in groups.values():
        for name in group["sources"]:
            inventory.relative(name)
            local(repo / name)
            directories.add((repo / name).parent)
    for directory in sorted(directories):
        resolved = directory.resolve(strict=True)
        inventory.need(resolved.is_relative_to(repo), "inventory-input-escaped")
        relative = resolved.relative_to(repo).as_posix()
        if relative != ".":
            inventory.relative(relative)
        inventory.need(resolved == directory, "inventory-input-alias")
        for path in sorted(directory.glob("*.h")):
            local(path)

    for cohort in manifest["cohorts"]:
        for reference in cohort["claim_refs"]:
            local(repo / inventory.relative(reference["path"]))
        for artifact in cohort["artifacts"]:
            for source in artifact["upstream_sources"]:
                names.add("pinned-reference/" + inventory.relative(source))
    for row in manifest["scope_backlog"]:
        for name in row["refs"]:
            local(repo / inventory.relative(name))
    return names
