"""Os worker provenance over explicit authenticated neutral runner helpers.

No module loading, subprocesses, filesystem normalization or machine semantics
live here. Caller-owned watch/API/reader admission must bind paths and physical
identities, and provide immutable reads during final replay. The frozen helper's
option callback is replaced only on a private view, never in module globals.
"""

import hashlib
from pathlib import Path
from types import SimpleNamespace


HELPER_SHA256 = '9C99D38EACC8F3E3B2B63F343CA79555A66264AC76A3CA11957D2BEB0745987A'
SCOPE = 'NATIVE_CM3_OS_LTO_COMMON_RAW_WORKER_CHAIN_ONLY'
RAW_FLAGS = ('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs',
             '-ftest-coverage', '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
LOWER_FLAGS = ('-flto-partition=one', '-nostdlib', '-r', '-flinker-output=nolto-rel')


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-COMMON-WORKERS:' + message)


def sha(raw):
    need(type(raw) is bytes, 'immutable byte input')
    return hashlib.sha256(raw).hexdigest().upper()


def _helper(helpers):
    need(all(callable(getattr(helpers, name, None)) for name in
         ('worker_chain', 'argument_lines', 'worker_diagnostics')), 'explicit neutral worker helpers')


def _options(args, stage, *, saved):
    need(type(args) is list and args and all(type(arg) is str and arg and '\0' not in arg for arg in args),
         stage + ' literal argv')
    marker = '-fwpa' if stage == 'WPA' else '-fltrans'
    need(args.count(marker) == 1 and ('-fltrans' if stage == 'WPA' else '-fwpa') not in args,
         stage + ' exact worker stage')
    optimizations = [arg for arg in args if arg.startswith('-O')]
    need(optimizations and all(arg == '-Os' for arg in optimizations), stage + ' sole Os optimization')
    need(all(flag in args for flag in ('-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft')),
         stage + ' actual soft CM3 Thumb target')
    need(all(flag in args for flag in RAW_FLAGS), stage + ' all six uncancelled raw flags')
    if saved:
        need(all(flag in args for flag in LOWER_FLAGS), stage + ' fixed real nolto-rel lowering')
    forbidden = ('-fno-instrument-functions', '-finstrument-functions-exclude-', '-fno-stack-protector',
                 '-fno-profile', '-fno-test-coverage', '-fno-sanitize', '-fno-lto', '-ffat-lto-objects',
                 '-mfpu', '-mno-general-regs-only')
    for arg in args:
        need(not arg.startswith(forbidden) and arg not in ('-mgeneral-regs-only', '-marm', '-lgcov'),
             stage + ' forbidden counter/target/runtime option')
        need(not arg.startswith('-mcpu=') or arg == '-mcpu=cortex-m3', stage + ' foreign CPU')
        need(not arg.startswith('-mfloat-abi=') or arg == '-mfloat-abi=soft', stage + ' foreign float ABI')
        if arg.startswith(('-march', '-mlibarch', '--march', '--mlibarch')):
            need(arg in ('-march=armv7-m', '-mlibarch=armv7-m'), stage + ' foreign architecture option')
        need(not arg.startswith('-flto-partition=') or arg == '-flto-partition=one', stage + ' foreign partition')
        need(not arg.startswith('-flinker-output=') or arg == '-flinker-output=nolto-rel', stage + ' foreign lowering kind')
        if arg.startswith(('-finstrument-functions', '-fstack-protector', '-fprofile-arcs', '-ftest-coverage', '-fsanitize')):
            need(arg in RAW_FLAGS, stage + ' contradictory stress option')
    return dict(Stage=stage, Mode='Os-lto', SoleOsOptimization=True, RawFlags=list(RAW_FLAGS),
        ActualStageFlagVerified=marker, UncancelledRawFlagsVerified=True,
        SavedNoltoRelOptionsValidated=saved, AttributeEffectsValidated=False)


def require_hostile_options(wpa, ltrans, helpers):
    """Check actual saved one-argument-per-line bytes using the neutral parser."""
    _helper(helpers)
    evidence = []
    for stage, raw in (('WPA', wpa), ('LTRANS', ltrans)):
        need(type(raw) is bytes, stage + ' raw saved bytes')
        try:
            args = helpers.argument_lines(raw)
        except (ValueError, UnicodeError) as error:
            raise Rejected('REJECT:CM3-OS-LTO-COMMON-WORKERS:saved argument grammar: ' + str(error)) from error
        record = _options(args, stage, saved=True)
        need(not any(arg.startswith('@') for arg in args), stage + ' no unbound saved response indirection')
        record['ArgumentsSha256'] = sha(raw)
        evidence.append(record)
    return dict(Profile='CM3', Mode='Os-lto', ActualHostileOptionsVerified=True, Stages=evidence,
        RuntimeLibraryProvided=False, AttributeEffectsValidated=False, RequiredCellCount=0)


def _path(path, role):
    need(isinstance(path, Path) and path.is_absolute() and '\0' not in str(path)
         and '..' not in path.parts, 'absolute caller-admitted path/' + role)
    return path


def worker_chain(suite_view, lowered, objects, specs, diagnostics, helpers):
    """Return (machine Path, neutral chain proof) with newly checked Os facts.

    helpers is the authenticated cm3_lto_attributes.runner module (or an
    explicit view of its three neutral functions). suite_view supplies watch,
    api, result, transport and admitted; the adapter never mutates those members.
    The caller separately binds this input cohort to one of the six actual
    CommonAttributesDeferredReader.Lowerings and its original command journal.
    """
    _helper(helpers)
    lowered, specs = _path(lowered, 'aggregate'), _path(specs, 'specs')
    need(type(objects) in (tuple, list) and len(objects) in (1, 3), 'fixed stress/three-common IR cohort')
    objects = [_path(path, 'IR object') for path in objects]
    need(len(set(objects)) == len(objects) and lowered not in objects and specs not in objects
         and lowered != specs, 'distinct aggregate/specs/IR roles')
    need(type(diagnostics) is bytes and diagnostics, 'bound raw actual worker diagnostics')
    need(all(hasattr(suite_view, name) for name in ('watch', 'api', 'result', 'transport', 'admitted')),
         'explicit admitted suite view')
    need(type(suite_view.result) is dict and type(suite_view.result.get('ResolvedWorkers')) is dict,
         'admitted actual worker identities')
    callback = lambda wpa, ltrans: require_hostile_options(wpa, ltrans, helpers)
    view = SimpleNamespace(watch=suite_view.watch, api=suite_view.api, result=suite_view.result,
        transport=suite_view.transport, admitted=suite_view.admitted,
        modules={'attributes': SimpleNamespace(HOSTILE_FLAGS=RAW_FLAGS, require_hostile_options=callback)})
    # The frozen routine checks the expected specs count, not foreign extras.
    # Close that list explicitly before it consumes the same immutable buffers.
    for suffix in ('.ltrans_args', '.ltrans0.ltrans_args'):
        raw = view.watch.read(Path(str(lowered) + suffix))
        try:
            args = helpers.argument_lines(raw)
        except (ValueError, UnicodeError) as error:
            raise Rejected('REJECT:CM3-OS-LTO-COMMON-WORKERS:saved argument grammar: ' + str(error)) from error
        need([arg for arg in args if arg.startswith(('-specs', '--specs'))] == ['-specs=' + str(specs)],
             'one exact owned specs adapter, no additional specs')
    try:
        machine, proof = helpers.worker_chain(view, lowered, objects, specs, diagnostics)
    except ValueError as error:
        raise Rejected('REJECT:CM3-OS-LTO-COMMON-WORKERS:neutral chain: ' + str(error)) from error
    execution = proof['Execution']
    need(execution['CompilerReportedWorkerExecutionVerified'] is True
         and execution['OsProcessTraceVerified'] is False and execution['TranscriptSha256'] == sha(diagnostics),
         'actual reported invocation transcript binding')
    invocations = execution['WorkerInvocations']
    need(type(invocations) is list and len(invocations) == 2, 'two actual worker invocation records')
    actual_options = []
    for stage, marker, row in zip(('WPA', 'LTRANS'), ('-fwpa', '-fltrans'), invocations):
        need(type(row) is dict and row.get('Stage') == marker, 'actual invocation stage order')
        actual_options.append(_options(row['Argv'], stage, saved=False))
    proof.update(Scope=SCOPE, Linkage='direct', LTO=True,
        SavedArgumentOsOptionsValidated=True, ActualInvocationOsOptionsValidated=True,
        ActualInvocationOptions=actual_options, HelperAuthenticationCallerOwned=True,
        PhysicalIdentityValidationCallerOwned=True, InputCohortJournalBindingCallerOwned=True,
        Qualification=False, CellContractSatisfied=False, RequiredCellSatisfied=False,
        RequiredCellsSatisfied=0, FullABIProof=False, FullSemanticABIProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
    return machine, proof
