"""One managed capture command, with primary-preserving terminal journals.

The caller authenticates this module's executed buffer. No tool or filesystem
operation occurs on import. api is the unchanged pinned transport utility.
Only failed diagnostic writes may be repeated; the process is never retried.
"""
import math


def command(probe, api, argv, label, *, cwd=None, timeout=120):
    argv = [str(value) for value in argv]
    cwd = api.checked_path(cwd or probe.output)
    api.need(cwd.is_relative_to(probe.output), "command working directory outside output")
    record = dict(Label=label, Argv=argv, Cwd=str(cwd), State="ATTEMPT", Status="ATTEMPT",
                  Exit=None, TimedOut=None, Seconds=None, Error=None, FailurePhase=None,
                  StdoutCaptured=False, StderrCaptured=False, ClosingErrors=[])
    probe.report["Commands"].append(record)
    target = probe.output / ("command-%04d.json" % (len(probe.report["Commands"]) - 1))
    primary, primary_traceback, result = None, None, None

    def failure(error, phase):
        nonlocal primary, primary_traceback
        message = type(error).__name__ + ": " + str(error)
        if primary is None:
            primary, primary_traceback = error, error.__traceback__
            record.update(Error=message, FailurePhase=phase)
            if probe.report.get("PrimaryError") is None:
                probe.report["PrimaryError"] = message
        else:
            closing = label + " / " + phase + ": " + message
            record["ClosingErrors"].append(closing)
            probe.report.setdefault("ClosingErrors", []).append(closing)
        record["Status"] = "FAIL"

    launched = False
    try:
        api.save(target, record)
    except BaseException as error:
        failure(error, "initial journal")
    else:
        try:
            executable = api.regular(argv[0])
            api.need(executable in probe.tool_hashes, "command executable not captured")
            probe.verify_tools()
            launched = True
            result = probe.seed.process.run(argv, cwd=str(cwd), env=probe.environment, timeout=timeout)
            code, timed_out = result.returncode, result.timed_out
            record.update(Exit=code if type(code) is int else None,
                          TimedOut=timed_out if type(timed_out) is bool else None)
            # Preserve command failure before any stream or journal can fail.
            api.need(type(code) is int and code == 0 and timed_out is False,
                     "command failed/timeout: " + label)
        except BaseException as error:
            failure(error, "managed command" if launched else "opening tool checks")

    if result is not None:
        try:
            elapsed = result.elapsed
            api.need(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0,
                     "finite nonnegative command elapsed time required")
            record["Seconds"] = elapsed
        except BaseException as error:
            failure(error, "result elapsed time")

    for name in ("stdout", "stderr"):
        data = b""
        if result is not None:
            try:
                value = getattr(result, name)
                api.need(type(value) is bytes, "managed " + name + " must be bytes")
                data = value
                record[name.capitalize() + "Captured"] = True
            except BaseException as error:
                failure(error, name + " result")
        try:
            target.with_suffix("." + name).write_bytes(data)
        except BaseException as error:
            failure(error, name + " write")

    try:
        probe.verify_tools()
    except BaseException as error:
        failure(error, "closing tool checks")

    record.update(State="TERMINAL", Status="PASS" if primary is None else "FAIL")
    journals = ((target, record, "terminal journal"),
                (probe.output / "commands.json", probe.report["Commands"], "command list"))
    journal_failed = False
    for path, value, phase in journals:
        try:
            api.save(path, value)
        except BaseException as error:
            journal_failed = True
            failure(error, phase)
    if journal_failed:
        # Revoke an earlier terminal PASS if the other journal failed later.
        # This bounded diagnostic repair never repeats a command or stage.
        for path, value, phase in journals:
            try:
                api.save(path, value)
            except BaseException as error:
                failure(error, phase + " recovery")

    if primary is not None:
        raise primary.with_traceback(primary_traceback)
    return result
