"""Synthetic host-only controls for the Os witness physical identity exception."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import MethodType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
WITNESS = HERE / "witness.py"
EXPECTED_METHODS = 5
subject = None


class SyntheticPath:
    """Path identity and stat results only; never touches the filesystem."""

    def __init__(self, name, *, links=1, device=7, inode=101):
        self.name = name
        self.info = SimpleNamespace(st_dev=device, st_ino=inode, st_nlink=links)
        self.stat = Mock(side_effect=lambda: self.info)

    def __str__(self):
        return self.name

    def __eq__(self, other):
        return isinstance(other, SyntheticPath) and self.name == other.name

    def __hash__(self):
        return hash(self.name)


def context(git=None):
    git = git if git is not None else SyntheticPath("installed/git.exe", links=2)
    regular = Mock(side_effect=lambda path: path)
    seed_close = Mock()
    value = SimpleNamespace(
        api=SimpleNamespace(regular=regular), provenance_git=git,
        identities={}, watch=SimpleNamespace(close=Mock()),
        groups={"Reference": {"Seed": SimpleNamespace(closure=SimpleNamespace(close=seed_close))}})
    value._physical = MethodType(subject.Witness._physical, value)
    return value


class IdentityTests(unittest.TestCase):
    def test_ordinary_single_link_identity_passes(self):
        path = SyntheticPath("capture/source.c")
        value = context()
        self.assertEqual(value._physical(path), (7, 101, 1))
        value.api.regular.assert_called_once_with(path)
        path.stat.assert_called_once_with()

    def test_nongit_multilinks_and_git_name_lookalikes_reject(self):
        for name in ("capture/source.c", "other/git.exe", "installed/not-git.exe"):
            for links in (2, 3):
                with self.subTest(name=name, links=links):
                    value = context()
                    path = SyntheticPath(name, links=links)
                    self.assertIsNot(path, value.provenance_git)
                    with self.assertRaisesRegex(ValueError, "unexpected hard-linked input/output"):
                        value._physical(path)
                    value.api.regular.assert_called_once_with(path)

    def test_exact_git_multilink_identity_is_recorded_and_closes(self):
        for links in (2, 3):
            with self.subTest(links=links):
                git = SyntheticPath("installed/git.exe", links=links, inode=211)
                value = context(git)
                value.identities[git] = value._physical(git)
                self.assertEqual(value.identities, {git: (7, 211, links)})
                subject.Witness.close(value)
                value.watch.close.assert_called_once_with()
                value.groups["Reference"]["Seed"].closure.close.assert_called_once_with()
                self.assertEqual(value.api.regular.call_count, 2)
                self.assertEqual(git.stat.call_count, 2)

    def test_close_rejects_device_inode_and_permitted_git_link_drift(self):
        cases = ((False, "st_dev", 8), (False, "st_ino", 102),
                 (True, "st_dev", 8), (True, "st_ino", 212),
                 (True, "st_nlink", 3), (True, "st_nlink", 1))
        for is_git, field, replacement in cases:
            with self.subTest(git=is_git, field=field, replacement=replacement):
                value = context()
                path = value.provenance_git if is_git else SyntheticPath("capture/source.c")
                value.identities[path] = value._physical(path)
                setattr(path.info, field, replacement)
                with self.assertRaisesRegex(ValueError, "input physical identity drift"):
                    subject.Witness.close(value)
                value.watch.close.assert_called_once_with()

    def test_git_exception_never_waives_zero_links_or_regular_rejection(self):
        for is_git in (False, True):
            for links in (0, -1):
                with self.subTest(git=is_git, links=links):
                    value = context()
                    path = value.provenance_git if is_git else SyntheticPath("capture/source.c")
                    path.info.st_nlink = links
                    with self.assertRaisesRegex(ValueError, "unexpected hard-linked input/output"):
                        value._physical(path)
            for reason in ("reparse point", "not a regular file"):
                with self.subTest(git=is_git, regular_rejection=reason):
                    value = context()
                    path = value.provenance_git if is_git else SyntheticPath("capture/source.c")
                    error = ValueError("synthetic regular rejection: " + reason)
                    value.api.regular.side_effect = error
                    with self.assertRaises(ValueError) as caught:
                        value._physical(path)
                    self.assertIs(caught.exception, error)
                    value.api.regular.assert_called_once_with(path)
                    path.stat.assert_not_called()


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def load_subject(data):
    name = "synthetic_os_join_physical_identity_subject"
    spec = importlib.util.spec_from_file_location(name, WITNESS)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(WITNESS), "exec"), module.__dict__)
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(REPO)
            or REPO.is_relative_to(output) or not output.is_relative_to(temporary)):
        parser.error("fresh external TEMP output directory required")
    report = dict(
        Status="FAIL", Scope="PURE_SYNTHETIC_OS_JOIN_PHYSICAL_IDENTITY_CONTROLS_ONLY",
        Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        SyntheticInputs=True, ActualFilesystemIdentityTested=False, ActualWitnessTested=False,
        WitnessConstructorExecuted=False, GitExecuted=False, ToolInvocations=0,
        NativeCommandsExecuted=0, Qualification=False, FinalElfProof=False,
        FinalReferenceParity=False, FullABIProof=False, CanonicalProtocolValidated=False,
        CompleteObjectProof=False, KernelRuntimeProof=False, CpuExecution=False,
        BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        paths = (Path(__file__).resolve(), WITNESS)
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global subject
        with patch("subprocess.Popen", side_effect=AssertionError("pure identity controls cannot spawn processes")), \
                patch("os.system", side_effect=AssertionError("pure identity controls cannot execute tools")):
            subject = load_subject(buffers[WITNESS])
            with patch.object(subject.Witness, "__init__", side_effect=AssertionError("constructor forbidden")):
                suite = unittest.defaultTestLoader.loadTestsFromTestCase(IdentityTests)
                if suite.countTestCases() != EXPECTED_METHODS:
                    raise ValueError("exact five synthetic identity methods required")
                result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(
            Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[
                dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, expected in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) == expected:
                    report["ClosingFilesVerified"] += 1
                else:
                    report["SourceDrift"].append(path)
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 2 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
