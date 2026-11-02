"""Exact Secure Handler/basic/MSP UDF origin; no arbitrary fault is success."""


def fault_matches(record, proof, site, origin):
    stack = proof["stack_before"]
    frame = (stack - 32) & ~7
    return (proof["origin_ipsr"] == origin and origin in (11, 14) and proof["control"] == 2 and
            record["pc"] == proof["udf_pc"] == proof["pc"] and
            record["pc"] in site["udf"] and site["start"] <= record["pc"] < site["end"] and
            record["cfsr"] == 0x10000 and record["hfsr"] == 0 and record["ipsr"] == proof["handler_ipsr"] == 6 and
            record["exc_return"] == proof["handler_lr"] == 0xFFFFFFF5 and
            record["frame"] == proof["frame"] == frame and 0x3000F000 <= frame < stack <= 0x30010000 and
            record["xpsr"] == proof["xpsr"] and record["xpsr"] & 0x1000000 != 0 and
            record["xpsr"] & 0x1FF == origin and bool(record["xpsr"] & 0x200) == bool(stack & 4))


def negative_controls(record, proof, site, origin):
    mutations = {
        "zero-return": ("exc_return", 0), "wrong-spsel": ("exc_return", record["exc_return"] ^ 4),
        "thread-return": ("exc_return", record["exc_return"] ^ 8),
        "nonsecure-frame": ("exc_return", record["exc_return"] ^ 0x40),
        "nonsecure-handler": ("exc_return", record["exc_return"] ^ 1),
        "fp-frame": ("exc_return", record["exc_return"] ^ 0x10),
        "wrong-dcrs": ("exc_return", record["exc_return"] ^ 0x20),
        "reserved-bit": ("exc_return", record["exc_return"] ^ 2),
        "wrong-prefix": ("exc_return", record["exc_return"] ^ 0x10000000),
        "wrong-stacked-ipsr": ("xpsr", (record["xpsr"] & ~0x1FF) | (14 if origin == 11 else 11)),
        "missing-thumb": ("xpsr", record["xpsr"] & ~0x1000000),
        "wrong-current-ipsr": ("ipsr", 3), "wrong-frame": ("frame", record["frame"] + 4),
        "zero-frame": ("frame", 0), "wrong-pc": ("pc", site["end"]),
        "missing-undefinstr": ("cfsr", 0), "escalated-fault": ("hfsr", 0x40000000),
    }
    results = {name: not fault_matches(dict(record, **{key: value}), proof, site, origin)
               for name, (key, value) in mutations.items()}
    for name in ("wrong-stacked-ipsr", "missing-thumb"):
        key, value = mutations[name]
        results[name + "-corroborated"] = not fault_matches(
            dict(record, **{key: value}), dict(proof, xpsr=value), site, origin)
    return results
