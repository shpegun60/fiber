"""No-shell byte-capturing tool runner with bounded process-tree cleanup.

run(argv, *, cwd, env, timeout) returns Result. Launch/setup/capture/cleanup
failures return 125 with a [process-runner] stderr diagnostic; tool failures
retain their return code. A timeout always sets timed_out, even if the root
exited zero in the meantime. The caller must reject timed_out OR nonzero exit.
No jobs/processes are created on import and no receipts/files are written.

Windows uses a non-inheritable kill-on-close job, assignment before resuming
the suspended primary thread, and job accounting to check cleanup. POSIX uses
a new session/process group; tools must not deliberately escape that group.
"""
import ctypes
import math
import os
import signal
import subprocess
import threading
import time
from typing import NamedTuple


class Result(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    elapsed: float


_FAILURE = 125
_CLEANUP_SECONDS = 5.0
_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_DWORD = ctypes.c_uint32
_HANDLE = ctypes.c_void_p


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", _DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", _DWORD), ("Affinity", ctypes.c_size_t),
                ("PriorityClass", _DWORD), ("SchedulingClass", _DWORD)]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", ctypes.c_uint64 * 6),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                ("TotalPageFaultCount", _DWORD), ("TotalProcesses", _DWORD),
                ("ActiveProcesses", _DWORD), ("TotalTerminatedProcesses", _DWORD)]


class _ThreadEntry(ctypes.Structure):
    _fields_ = [("dwSize", _DWORD), ("cntUsage", _DWORD), ("th32ThreadID", _DWORD),
                ("th32OwnerProcessID", _DWORD), ("tpBasePri", ctypes.c_int32),
                ("tpDeltaPri", ctypes.c_int32), ("dwFlags", _DWORD)]


def _platform():
    return os.name


class _WindowsJob:
    def __init__(self):
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        definitions = {
            "CreateJobObjectW": (_HANDLE, [_HANDLE, ctypes.c_wchar_p]),
            "SetInformationJobObject": (ctypes.c_int32, [_HANDLE, ctypes.c_int32, _HANDLE, _DWORD]),
            "QueryInformationJobObject": (ctypes.c_int32, [_HANDLE, ctypes.c_int32, _HANDLE, _DWORD, _HANDLE]),
            "AssignProcessToJobObject": (ctypes.c_int32, [_HANDLE, _HANDLE]),
            "TerminateJobObject": (ctypes.c_int32, [_HANDLE, _DWORD]),
            "OpenProcess": (_HANDLE, [_DWORD, ctypes.c_int32, _DWORD]),
            "CloseHandle": (ctypes.c_int32, [_HANDLE]),
            "CreateToolhelp32Snapshot": (_HANDLE, [_DWORD, _DWORD]),
            "Thread32First": (ctypes.c_int32, [_HANDLE, ctypes.POINTER(_ThreadEntry)]),
            "Thread32Next": (ctypes.c_int32, [_HANDLE, ctypes.POINTER(_ThreadEntry)]),
            "OpenThread": (_HANDLE, [_DWORD, ctypes.c_int32, _DWORD]),
            "GetProcessIdOfThread": (_DWORD, [_HANDLE]),
            "ResumeThread": (_DWORD, [_HANDLE]),
        }
        for name, (result, args) in definitions.items():
            function = getattr(self.api, name)
            function.restype, function.argtypes = result, args
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            limits = _ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE; no breakaway.
            self._check(self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, pid):
        process = self.api.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE.
        self._check(process)
        try:
            self._check(self.api.AssignProcessToJobObject(self.handle, process))
        finally:
            self._check(self.api.CloseHandle(process))

    def resume(self, pid):
        snapshot = self.api.CreateToolhelp32Snapshot(0x00000004, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry, threads = _ThreadEntry(), []
            entry.dwSize = ctypes.sizeof(entry)
            more = self.api.Thread32First(snapshot, ctypes.byref(entry))
            if not more:
                raise ctypes.WinError(ctypes.get_last_error())
            while more:
                if entry.dwSize < 16:
                    raise RuntimeError("short THREADENTRY32")
                if entry.th32OwnerProcessID == pid:
                    threads.append(entry.th32ThreadID)
                entry.dwSize = ctypes.sizeof(entry)
                more = self.api.Thread32Next(snapshot, ctypes.byref(entry))
            if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES.
                raise ctypes.WinError(ctypes.get_last_error())
            if len(threads) != 1:
                raise RuntimeError("suspended process must have exactly one primary thread")
            thread = self.api.OpenThread(0x0802, False, threads[0])  # QUERY_LIMITED_INFORMATION | SUSPEND_RESUME.
            self._check(thread)
            try:
                if self.api.GetProcessIdOfThread(thread) != pid:
                    raise RuntimeError("primary thread owner changed")
                previous = self.api.ResumeThread(thread)
                if previous == 0xFFFFFFFF:
                    raise ctypes.WinError(ctypes.get_last_error())
                if previous != 1:
                    raise RuntimeError("unexpected primary thread suspend count: " + str(previous))
            finally:
                self._check(self.api.CloseHandle(thread))
        finally:
            self._check(self.api.CloseHandle(snapshot))

    def active(self):
        if self.handle is None:
            raise RuntimeError("job already closed")
        info = _Accounting()
        self._check(self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None))
        return info.ActiveProcesses != 0

    def wait_empty(self, deadline):
        while self.active():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def terminate(self):
        if self.handle is None:
            raise RuntimeError("job already closed")
        self._check(self.api.TerminateJobObject(self.handle, 124))

    def close(self):
        if self.handle is not None:
            self._check(self.api.CloseHandle(self.handle))
            self.handle = None


class _PosixGroup:
    def __init__(self, pid):
        self.pid = pid

    def assign(self, pid):
        pass

    def resume(self, pid):
        pass

    def active(self):
        try:
            os.killpg(self.pid, 0)
            return True
        except ProcessLookupError:
            return False

    def wait_empty(self, deadline):
        while self.active():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def terminate(self):
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def close(self):
        pass


class _Capture:
    def __init__(self, stream):
        self.stream, self.chunks, self.error = stream, [], None
        self.thread = threading.Thread(target=self._read, name="managed-tool-pipe", daemon=True)
        self.thread.start()

    def _read(self):
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    break
                self.chunks.append(chunk)
        except Exception as error:
            self.error = "pipe capture: " + str(error)


def _arguments(argv, timeout):
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("argv must be a nonempty command array")
    values = [os.fspath(value) for value in argv]
    if any(not isinstance(value, str) or "\0" in value for value in values) or not values[0]:
        raise ValueError("argv must contain NUL-free strings")
    if values[0].lower().endswith((".bat", ".cmd")):
        raise ValueError("shell scripts are not executable tools")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    return values


def run(argv, *, cwd, env, timeout) -> Result:
    """Capture arbitrary bytes and reap a contained tool, including on timeout.

    Windows job setup must succeed before execution is resumed. A root that
    exits while descendants survive is a runner failure, even with exit zero.
    stdin is DEVNULL. No shell, encoding conversion, receipt I/O or tool lookup
    is performed. Invalid arguments raise before launch; operational failures
    are represented by exit 125 and diagnostic bytes. BaseExceptions propagate
    only after the same cleanup path, for the caller's finally-based receipt.
    """
    argv = _arguments(argv, timeout)
    started = time.monotonic()
    process, tree, captures = None, None, []
    completed, timed_out, errors = False, False, []
    try:
        windows = _platform() == "nt"
        if windows:
            tree = _WindowsJob()
        elif _platform() != "posix":
            raise RuntimeError("unsupported host platform")
        options = dict(cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, shell=False, close_fds=True, bufsize=0)
        if windows:
            options["creationflags"] = _CREATE_SUSPENDED | _CREATE_NO_WINDOW
        else:
            options["start_new_session"] = True
        process = subprocess.Popen(argv, **options)
        if tree is None:
            tree = _PosixGroup(process.pid)
        tree.assign(process.pid)
        captures.append(_Capture(process.stdout))
        captures.append(_Capture(process.stderr))
        tree.resume(process.pid)
        try:
            process.wait(timeout=max(0.0, started + timeout - time.monotonic()))
            completed = True
        except subprocess.TimeoutExpired:
            timed_out = True
        if completed and not tree.wait_empty(time.monotonic() + 0.1):
            errors.append("process tree outlived root (root returncode=%s)" % process.returncode)
    except Exception as error:
        errors.append(type(error).__name__ + ": " + str(error))
    finally:
        deadline = time.monotonic() + _CLEANUP_SECONDS
        if process is not None:
            if not completed or timed_out or errors:
                try:
                    if tree is not None:
                        tree.terminate()
                except Exception as error:
                    errors.append("tree termination: " + str(error))
                    try:
                        tree.close()  # Windows kill-on-close is an independent last resort.
                    except Exception as close_error:
                        errors.append("tree close fallback: " + str(close_error))
                try:
                    if process.poll() is None:
                        process.kill()  # Also covers assignment failure of a still-suspended root.
                except Exception as error:
                    errors.append("root termination: " + str(error))
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except Exception as error:
                errors.append("root reap: " + str(error))
            try:
                if tree is not None and not tree.wait_empty(deadline):
                    errors.append("process tree did not become empty")
            except Exception as error:
                errors.append("tree accounting: " + str(error))
            for capture in captures:
                capture.thread.join(timeout=max(0.0, deadline - time.monotonic()))
                if capture.thread.is_alive():
                    errors.append("pipe reader did not reach EOF after tree cleanup")
                if capture.error is not None:
                    errors.append(capture.error)
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except Exception as error:
                    errors.append("pipe close: " + str(error))
        if tree is not None:
            try:
                tree.close()
            except Exception as error:
                errors.append("tree close: " + str(error))
    stdout = b"".join(captures[0].chunks) if captures else b""
    stderr = b"".join(captures[1].chunks) if len(captures) > 1 else b""
    if errors:
        stderr += ("\n[process-runner] " + "; ".join(errors) + "\n").encode("utf-8", "replace")
    return Result(_FAILURE if errors or process is None else int(process.returncode), stdout, stderr,
                  timed_out, time.monotonic() - started)
