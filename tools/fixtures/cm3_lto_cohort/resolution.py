"""Pure fixed eight-provider CM3 cohort resolution grammar, not IR semantics."""

import re


PRIVATE16 = (
    "fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_"
    "f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_u00010000_i0_"
    "o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0")
PRIVATE32 = PRIVATE16.replace("_u00010000_", "_u00100000_")
STORAGE = "fiber_port_storage_cohort_arm_cm3_v1_r0"
_ROW = re.compile(
    r"(0|[1-9][0-9]*) ([0-9a-f]{8}) "
    r"(PREVAILING_DEF_IRONLY|PREVAILING_DEF|PREEMPTED_IR|RESOLVED_IR|RESOLVED_EXEC) "
    r"([A-Za-z_][A-Za-z0-9_]*)")


def _need(condition, message):
    if not condition:
        raise ValueError("REJECT:CM3-LTO-COHORT-RESOLUTION " + message)


def parse(text, expected_providers, *, private, storage):
    """Retain all 106 rows; caller authenticates raw bytes and object identities."""
    _need(type(private) is str and private in (PRIVATE16, PRIVATE32), "fixed private identity")
    _need(type(storage) is str and storage == STORAGE, "fixed storage identity")
    _need(type(expected_providers) in (list, tuple) and len(expected_providers) == 8,
          "eight expected providers")
    _need(all(type(path) is str and re.fullmatch(r"[\x20-\x7e]+", path)
              for path in expected_providers), "literal printable provider paths")
    _need(len(set(expected_providers)) == 8, "duplicate provider")
    _need(type(text) is str and text and re.fullmatch(r"[\x20-\x7e\r\n]*", text), "ASCII resolution text")
    if "\r" in text:
        normalized = text.replace("\r\n", "\n")
        _need("\r" not in normalized and text == normalized.replace("\n", "\r\n"),
              "whole LF or CRLF line endings")
    else:
        normalized = text
    lines = iter(normalized.splitlines())
    _need(next(lines, None) == "8", "provider count")
    result, private_roles, storage_roles, provider_units = [], [], [], set()
    total = 0
    for number, provider in enumerate(expected_providers):
        header = re.fullmatch(re.escape(provider) + r" ([1-9][0-9]*)", next(lines, ""))
        _need(header is not None, "ordered provider header")
        count = int(header[1])
        _need(count <= 106 and total + count <= 106, "bounded symbol row count")
        symbols, indices, names, units = [], set(), set(), set()
        for _ in range(count):
            row = _ROW.fullmatch(next(lines, ""))
            _need(row is not None, "symbol row or truncated provider")
            index, unit, resolution, name = row.groups()
            _need(index not in indices and name not in names, "duplicate symbol index or name")
            indices.add(index)
            names.add(name)
            units.add(unit)
            for prefix, expected in (("fiber_port_context_cohort_", private),
                                     ("fiber_port_storage_cohort_", storage)):
                _need(not name.casefold().startswith(prefix) or name == expected, "foreign cohort identity")
            if name == private:
                private_roles.append((number, resolution))
            if name == storage:
                storage_roles.append((number, resolution))
            symbols.append(dict(Index=int(index), Unit=unit, Resolution=resolution, Name=name))
        _need(len(units) == 1 and not provider_units.intersection(units),
              "one distinct unit per provider")
        provider_units.update(units)
        total += count
        result.append(dict(Provider=provider, Symbols=symbols))
    _need(next(lines, None) is None and total == 106, "complete 106 rows and no trailing records")
    _need(private_roles == [(3, "PREVAILING_DEF_IRONLY"), (4, "RESOLVED_IR"),
                            (5, "RESOLVED_IR"), (6, "RESOLVED_IR")], "exact four private roles")
    _need(storage_roles == [(3, "PREVAILING_DEF_IRONLY"), (7, "RESOLVED_IR")], "exact two storage roles")
    return result
