"""Pure parser for the captured nine-provider GCC LTO resolution grammar."""

import re


_ROW = re.compile(
    r"(0|[1-9][0-9]*) ([0-9a-f]{8}) "
    r"(PREVAILING_DEF_IRONLY|PREVAILING_DEF|PREEMPTED_IR|RESOLVED_IR|RESOLVED_EXEC) "
    r"([A-Za-z_][A-Za-z0-9_]*)"
)


def _need(condition, message):
    if not condition:
        raise ValueError("REJECT:CM3-LTO-RESOLUTION " + message)


def parse(text, expected_providers):
    """Return every provider/row; caller authenticates the exact ordered paths."""
    _need(type(text) is str and re.fullmatch(r"[\x20-\x7e\r\n]*", text), "text")
    _need(type(expected_providers) in (list, tuple) and len(expected_providers) == 9,
          "nine expected providers")
    _need(all(type(path) is str and path and "\r" not in path and "\n" not in path
              for path in expected_providers), "provider paths")
    _need(len(set(expected_providers)) == 9, "duplicate provider")
    normalized = text.replace("\r\n", "\n")
    _need("\r" not in normalized, "line endings")
    lines = iter(normalized.splitlines())
    _need(next(lines, None) == "9", "provider count")
    result = []
    for provider in expected_providers:
        header = re.fullmatch(re.escape(provider) + r" ([1-9][0-9]*)", next(lines, ""))
        _need(header is not None, "ordered provider header")
        symbols, indices, names = [], set(), set()
        for _ in range(int(header[1])):
            row = _ROW.fullmatch(next(lines, ""))
            _need(row is not None, "symbol row or truncated provider")
            index, unit, resolution, name = row.groups()
            _need(index not in indices and name not in names, "duplicate symbol identity")
            indices.add(index)
            names.add(name)
            symbols.append(dict(Index=int(index), Unit=unit, Resolution=resolution, Name=name))
        result.append(dict(Provider=provider, Symbols=symbols))
    _need(next(lines, None) is None, "trailing rows or providers")
    return result
