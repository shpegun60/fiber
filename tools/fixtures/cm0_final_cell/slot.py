"""Bounded CM0 direct-slot source/generated-assembly access predicate."""
import hashlib
import re


SLOT = 'fiber_internal_runtime_current_context_slot'
OWNERS = {'SVC_Handler': 'r0', 'PendSV_Handler': 'r1'}


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('cm0-cell-slot: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def check_generated(source, assembly, original_object, replayed_object):
    """Bind two direct load-only accesses to a byte-identical object replay.

    The caller must authenticate the source, original object and compile/dependency
    recipe. This is neither an ELF decoder nor an arbitrary C alias proof.
    """
    need(all(type(value) is bytes for value in (source, assembly, original_object, replayed_object)),
         'literal input buffers')
    need(original_object.startswith(b'\x7fELF\x01\x01\x01') and original_object == replayed_object,
         'whole replayed object must equal the authenticated ELF32 input')
    try:
        c_text, generated = source.decode('ascii'), assembly.decode('ascii')
    except UnicodeError as error:
        raise Rejected('cm0-cell-slot: ASCII source/assembly required') from error
    symbol = re.escape(SLOT)
    mentions = list(re.finditer(r'\b' + symbol + r'\b', generated))
    pair = re.compile(r'(?m)^[ \t]*ldr[ \t]+(?P<register>r(?:1[0-2]|[0-9])),[ \t]*='
        + symbol + r'[ \t]*(?:@[^\r\n]*)?\r?\n'
        r'[ \t]*ldr[ \t]+(?P=register),[ \t]*\[(?P=register)\][ \t]*(?:@[^\r\n]*)?\r?$')
    pairs = list(pair.finditer(generated))
    need(len(mentions) == len(pairs) == 2, 'every generated slot reference is one immediate address/load pair')
    evidence = []
    for owner, register in OWNERS.items():
        start = list(re.finditer(r'(?m)^' + re.escape(owner) + r':[ \t]*(?:@[^\r\n]*)?\r?$', generated))
        end = list(re.finditer(r'(?m)^[ \t]*\.size[ \t]+' + re.escape(owner)
            + r',[ \t]*\.-' + re.escape(owner) + r'[ \t]*\r?$', generated))
        need(len(start) == len(end) == 1 and start[0].end() < end[0].start(), 'one complete generated owner: ' + owner)
        owned = [row for row in pairs if start[0].end() <= row.start() < row.end() <= end[0].start()]
        need(len(owned) == 1 and owned[0].group('register') == register, 'exact owner/register load-only access: ' + owner)
        evidence.append(dict(Owner=owner, Register=register,
                             GeneratedLine=generated.count('\n', 0, owned[0].start()) + 1))
    source_mentions = list(re.finditer(r'\b' + symbol + r'\b', c_text))
    need(len(source_mentions) == 2, 'source has only the two admitted assembly references')
    source_pair = re.compile(r'"ldr[ \t]+(?P<register>r[01]),[ \t]*=' + symbol
        + r'[ \t]*\\n"\s*"ldr[ \t]+(?P=register),[ \t]*\[(?P=register)\][ \t]*\\n"')
    source_pairs = list(source_pair.finditer(c_text))
    need(len(source_pairs) == 2 and {row.group('register') for row in source_pairs} == {'r0', 'r1'},
         'no C declaration, address escape or unclassified direct source access')
    return dict(Status='PASS', Scope='CM0_TWO_DIRECT_SLOT_LOADS_ONLY', SourceSha256=sha(source),
        AssemblySha256=sha(assembly), OriginalObjectSha256=sha(original_object),
        ReplayedObjectSha256=sha(replayed_object), WholeObjectByteIdentical=True,
        DirectSourceReferences=2, GeneratedReferences=2, Owners=evidence,
        ArbitraryPointerAliasProof=False, FullSemanticABIProof=False, CpuExecution=False,
        BoardExecution=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
