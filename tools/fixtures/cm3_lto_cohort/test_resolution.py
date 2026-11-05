"""Pure synthetic eight-provider grammar controls; no tools or actual ELF proof."""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import traceback
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = HERE / "resolution.py"
EXPECTED_METHODS = 12
PRIVATE16 = ("fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_"
    "f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_u00010000_i0_"
    "o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0")
PRIVATE32 = PRIVATE16.replace("_u00010000_", "_u00100000_")
STORAGE = "fiber_port_storage_cohort_arm_cm3_v1_r0"
PROVIDERS = tuple("C:/synthetic fixture/objects/%02d.o" % i for i in range(8))
subject = None


def fixture(private=PRIVATE16):
    groups = [[dict(Index=j, Unit="%08x" % (i + 1), Resolution="RESOLVED_IR",
                    Name="synthetic_%d_%d" % (i, j)) for j in range(count)]
              for i, count in enumerate((18, 12, 3, 28, 20, 6, 1, 18))]
    for provider, offset, name, resolution in (
            (3, 0, private, "PREVAILING_DEF_IRONLY"), (4, 0, private, "RESOLVED_IR"),
            (5, 0, private, "RESOLVED_IR"), (6, 0, private, "RESOLVED_IR"),
            (3, 1, STORAGE, "PREVAILING_DEF_IRONLY"), (7, 0, STORAGE, "RESOLVED_IR")):
        groups[provider][offset].update(Name=name, Resolution=resolution)
    return groups


def render(groups, providers=PROVIDERS):
    lines = [str(len(groups))]
    for provider, rows in zip(providers, groups):
        lines.append(provider + " " + str(len(rows)))
        lines.extend("{Index} {Unit} {Resolution} {Name}".format(**row) for row in rows)
    return "\n".join(lines) + "\n"


def load_subject(data):
    spec = importlib.util.spec_from_file_location("synthetic_cm3_cohort_resolution", SOURCE)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(SOURCE), "exec"), module.__dict__)
    return module


class ResolutionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global subject
        if subject is None:
            subject = load_subject(SOURCE.read_bytes())

    def reject(self, text, **kwargs):
        options = dict(private=PRIVATE16, storage=STORAGE)
        providers = kwargs.pop("expected_providers", PROVIDERS)
        options.update(kwargs)
        with self.assertRaisesRegex(ValueError, r"^REJECT:CM3-LTO-COHORT-RESOLUTION "):
            subject.parse(text, providers, **options)

    def test_exact_complete_records_for_both_policies(self):
        for private in (PRIVATE16, PRIVATE32):
            with self.subTest(private=private):
                groups = fixture(private)
                original = copy.deepcopy(groups)
                actual = subject.parse(render(groups), PROVIDERS, private=private, storage=STORAGE)
                self.assertEqual(actual, [dict(Provider=path, Symbols=rows)
                                         for path, rows in zip(PROVIDERS, groups)])
                self.assertEqual(sum(len(row["Symbols"]) for row in actual), 106)
                self.assertEqual(groups, original)
                self.assertEqual(set(actual[0]), {"Provider", "Symbols"})
                self.assertEqual(set(actual[0]["Symbols"][0]), {"Index", "Unit", "Resolution", "Name"})

    def test_lf_crlf_and_optional_final_newline(self):
        text = render(fixture())
        expected = subject.parse(text, PROVIDERS, private=PRIVATE16, storage=STORAGE)
        for value in (text.replace("\n", "\r\n"), text.rstrip("\n")):
            self.assertEqual(subject.parse(value, list(PROVIDERS), private=PRIVATE16, storage=STORAGE), expected)

    def test_text_type_ascii_and_newline_rejections(self):
        text = render(fixture())
        for value in (None, b"8\n", 8, "", text + "\n", text + "\0", text + "\u00e9",
                      text.replace("\n", "\r", 1), text.replace("\n", "\r\n", 1),
                      text.replace("\n", "\v", 1), text.replace("\n", "\f", 1)):
            with self.subTest(value=repr(value)[:70]):
                self.reject(value)

    def test_provider_parameter_shapes_uniqueness_and_order(self):
        text = render(fixture())
        for value in (None, "eight", set(PROVIDERS), PROVIDERS[:7], (*PROVIDERS, "extra"),
                      (PROVIDERS[0],) * 8, (False, *PROVIDERS[1:]), ("", *PROVIDERS[1:]),
                      ("bad\npath", *PROVIDERS[1:]), ("nonascii\u00e9", *PROVIDERS[1:]),
                      tuple(reversed(PROVIDERS))):
            with self.subTest(providers=repr(value)[:70]):
                self.reject(text, expected_providers=value)

    def test_fixed_private_and_storage_parameters(self):
        text = render(fixture())
        for private in (None, True, 16, "", PRIVATE32, PRIVATE16 + "x", PRIVATE16.upper()):
            with self.subTest(private=private):
                self.reject(text, private=private)
        for storage in (None, True, 0, "", STORAGE + "x", STORAGE.replace("_v1_", "_v2_")):
            with self.subTest(storage=storage):
                self.reject(text, storage=storage)

    def test_provider_headers_and_complete_membership(self):
        text = render(fixture())
        header = PROVIDERS[0] + " 18"
        for value in (text.replace("8\n", "9\n", 1), text.replace("8\n", "08\n", 1),
                      text.replace(header, PROVIDERS[0] + " 0", 1),
                      text.replace(header, PROVIDERS[0] + " 018", 1),
                      text.replace(header, PROVIDERS[0] + " 107", 1),
                      "\n".join(text.splitlines()[:-1]) + "\n", text + header + "\n"):
            with self.subTest(value=value[:90]):
                self.reject(value)

    def test_symbol_row_grammar(self):
        for key, values in (("Index", ("01", "-1", "+1", "1.0")),
                            ("Unit", ("1", "0000000A", "000000001", "gggggggg")),
                            ("Resolution", ("UNKNOWN", "prevailing_def", "PREVAILING_DEF_EXTRA")),
                            ("Name", ("bad.name", "0bad", "two words"))):
            for value in values:
                with self.subTest(key=key, value=value):
                    groups = fixture()
                    groups[0][0][key] = value
                    self.reject(render(groups))
        self.reject(render(fixture()).replace("0 00000001 ", "0\t00000001 ", 1))

    def test_duplicate_symbol_index_or_name(self):
        for key in ("Index", "Name"):
            groups = fixture()
            groups[0][1][key] = groups[0][0][key]
            with self.subTest(key=key):
                self.reject(render(groups))

    def test_one_unique_unit_per_provider(self):
        groups = fixture()
        groups[0][1]["Unit"] = "abcdef01"
        self.reject(render(groups))
        groups = fixture()
        for row in groups[1]:
            row["Unit"] = groups[0][0]["Unit"]
        self.reject(render(groups))

    def test_each_private_role_and_placement(self):
        for provider in (3, 4, 5, 6):
            for change in (dict(Resolution="PREEMPTED_IR"), dict(Name="removed_private_role"),
                           dict(Name=PRIVATE32)):
                with self.subTest(provider=provider, change=change):
                    groups = fixture()
                    groups[provider][0].update(change)
                    self.reject(render(groups))
        groups = fixture()
        groups[0][0].update(Name=PRIVATE16)
        self.reject(render(groups))
        groups = fixture()
        groups[2][0]["Name"], groups[4][0]["Name"] = groups[4][0]["Name"], groups[2][0]["Name"]
        self.reject(render(groups))

    def test_each_storage_role_and_foreign_identity(self):
        for provider, offset in ((3, 1), (7, 0)):
            for change in (dict(Resolution="PREEMPTED_IR"), dict(Name="removed_storage_role"),
                           dict(Name=STORAGE.replace("_v1_", "_v2_"))):
                with self.subTest(provider=provider, change=change):
                    groups = fixture()
                    groups[provider][offset].update(change)
                    self.reject(render(groups))
        groups = fixture()
        groups[0][0]["Name"] = STORAGE
        self.reject(render(groups))

    def test_foreign_cohort_names_total_rows_and_trailing_records(self):
        for name in (PRIVATE16.replace("_g4_", "_g3_"), PRIVATE16.upper(),
                     "fiber_port_context_cohort_build_expectation", STORAGE.upper(),
                     STORAGE.replace("arm_cm3", "arm_cm4")):
            groups = fixture()
            groups[0][0]["Name"] = name
            with self.subTest(name=name):
                self.reject(render(groups))
        groups = fixture()
        groups[0].pop()
        self.reject(render(groups))
        groups = fixture()
        groups[0].append(dict(Index=99, Unit="00000001", Resolution="RESOLVED_IR", Name="extra_symbol"))
        self.reject(render(groups))
        self.reject(render(fixture()) + "999 00000001 RESOLVED_IR trailing_symbol\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output == temporary or output.is_relative_to(REPO) or REPO.is_relative_to(output)):
        parser.error("fresh external TEMP output directory required")
    for path in (args.output_dir.absolute(), *args.output_dir.absolute().parents):
        if path.exists() or path.is_symlink():
            if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                parser.error("symlink/reparse output ancestor")
    digest = lambda data: hashlib.sha256(data).hexdigest().upper()
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS,
        Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_CM3_LTO_COHORT_RESOLUTION_GRAMMAR_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualCompileTested=False, ActualLinkTested=False,
        Qualification=False, NativeCommandsExecuted=0, ToolInvocations=0, FullABIProof=False,
        SourceIRProof=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        CanonicalProtocolValidated=False, PolicyEquivalence=False, FinalReferenceParity=False,
        CompleteObjectProof=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {path: path.read_bytes() for path in (Path(__file__).resolve(), SOURCE)}
        report["SourceHashes"] = {str(path): digest(data) for path, data in buffers.items()}
        global subject
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            subject = load_subject(buffers[SOURCE])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ResolutionControls)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact twelve pure grammar methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
            for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, expected in report["SourceHashes"].items():
            try:
                if digest(Path(path).read_bytes()) == expected:
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
    print("Receipt:", target, digest(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
