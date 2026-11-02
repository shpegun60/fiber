"""Fail-closed generated-store decoder and exact gateway UDF oracle."""
import re


class StoreRejected(RuntimeError):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def stores(item, register):
    """Return every written byte range, or reject an unqualified store form."""
    op = item["Opcode"]
    operands = re.split(r"\s*[;@]", item["Operands"], 1)[0].strip()
    if op.startswith("push"):
        match = re.fullmatch(r"\{((?:r\d+|lr)(?:, (?:r\d+|lr))*)\}", operands)
        if op not in ("push", "push.w", "push.n") or not match:
            raise StoreRejected("unrecognized-store", f"Unqualified PUSH: {item}")
        count = len(match[1].split(", "))
        return [(register("sp") - 4 * count, 4 * count, None)]
    if op == "vstr" and operands == "FPCXTNS, [sp, #-4]!":
        return [(register("sp") - 4, 4, None)]
    if op.startswith("str"):
        width = re.fullmatch(r"str([bhd]?)(?:\.[wn])?", op)
        match = re.fullmatch(
            r"(r\d+|ip|lr)(?:, (r\d+|ip|lr))?, \[(r\d+|ip|sp)"
            r"(?:, (#-?(?:0x[0-9a-f]+|\d+)|r\d+|ip)(?:, lsl #(\d+))?)?\]"
            r"(!)?(?:, #-?(?:0x[0-9a-f]+|\d+))?", operands)
        if not width or not match:
            raise StoreRejected("unrecognized-store", f"Unqualified STR: {item}")
        source, second, base, offset, shift, writeback = match.groups()
        size = {"": 4, "b": 1, "h": 2, "d": 8}[width[1]]
        if (size == 8) != (second is not None) or shift and (offset or "").startswith("#"):
            raise StoreRejected("unrecognized-store", f"Invalid STR dataflow: {item}")
        displacement = 0 if offset is None else int(offset[1:], 0) if offset.startswith("#") else \
            register(offset) << int(shift or "0")
        address = (register(base) + displacement) & 0xFFFFFFFF
        return [(address, size, source)]
    if op.startswith(("st", "vst", "vpush")):
        raise StoreRejected("unrecognized-store", f"Unqualified store opcode: {item}")
    return []


def gateway_fault_matches(record, proof, case, site):
    """Only the observed basic Secure SVC/MSP frame is gateway fail-closed.

    Arm DDI0553B.y D1 EXC_RETURN: SPSEL saves transitory CONTROL.SPSEL,
    not the active Handler stack. Thus initial=FFFFFFF1, ready=FFFFFFF5;
    both Mode=Handler, S=Secure, ES=Secure, DCRS=1, FType=basic. The
    before-UDF CONTROL and actual MSP frame independently corroborate this.
    """
    if not proof or case not in ("latch-initial", "latch-ready"):
        return False
    control = 0 if case == "latch-initial" else 2
    expected_return = 0xFFFFFFF1 | ((control & 2) << 1)
    stack = proof["stack_before"]
    frame = (stack - 32) & ~7
    return (proof["control"] == control and proof["origin_ipsr"] == 11 and
            0x3000F000 <= frame < stack <= 0x30010000 and
            proof["msp"] == frame and proof["handler_ipsr"] == 6 and
            proof["handler_lr"] == expected_return and
            record["exc_return"] == expected_return and record["frame"] == frame and
            record["pc"] == proof["udf_pc"] == proof["stacked_pc"] and
            site["start"] <= record["pc"] < site["end"] and record["pc"] in site["udf"] and
            record["cfsr"] == 0x10000 and record["hfsr"] == 0 and record["ipsr"] == 6 and
            record["xpsr"] == proof["stacked_xpsr"] and
            record["xpsr"] & 0x1000000 != 0 and record["xpsr"] & 0x1FF == 11 and
            bool(record["xpsr"] & 0x200) == bool(stack & 4))


def negative_fault_controls(record, proof, case, site):
    """Mutate a genuine QEMU fault report; every invalid origin must fail."""
    changes = {
        "zero-return": ("exc_return", 0),
        "wrong-spsel": ("exc_return", record["exc_return"] ^ 4),
        "thread-return": ("exc_return", record["exc_return"] ^ 8),
        "nonsecure-frame": ("exc_return", record["exc_return"] ^ 0x40),
        "nonsecure-handler": ("exc_return", record["exc_return"] ^ 1),
        "fp-frame": ("exc_return", record["exc_return"] ^ 0x10),
        "wrong-dcrs": ("exc_return", record["exc_return"] ^ 0x20),
        "reserved-bit": ("exc_return", record["exc_return"] ^ 2),
        "wrong-prefix": ("exc_return", record["exc_return"] ^ 0x10000000),
        "wrong-stacked-ipsr": ("xpsr", (record["xpsr"] & ~0x1FF) | 14),
        "missing-thumb": ("xpsr", record["xpsr"] & ~0x1000000),
        "wrong-current-ipsr": ("ipsr", 3),
        "wrong-frame": ("frame", record["frame"] + 4),
        "zero-frame": ("frame", 0),
        "wrong-pc": ("pc", site["end"]),
        "missing-undefinstr": ("cfsr", 0),
        "escalated-fault": ("hfsr", 0x40000000),
    }
    results = {}
    for name, (key, value) in changes.items():
        modified = dict(record, **{key: value})
        results[name] = not gateway_fault_matches(modified, proof, case, site)
    # Corrupt both report and debugger frame evidence to ensure IPSR/T checks
    # are semantic constraints, not merely equality to the observed frame.
    for name in ("wrong-stacked-ipsr", "missing-thumb"):
        key, value = changes[name]
        results[name + "-corroborated"] = not gateway_fault_matches(
            dict(record, **{key: value}), dict(proof, stacked_xpsr=value), case, site)
    return results
