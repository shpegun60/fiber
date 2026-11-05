"""Pure synthetic GCC resolution grammar controls; no linker or ELF execution."""
import argparse
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = HERE / "resolution.py"
EXPECTED_METHODS = 12
PROVIDERS = tuple("C:/synthetic providers/input-%02d.o" % index for index in range(9))
FALLBACK = PROVIDERS[1]
APPLICATION = PROVIDERS[8]
r = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def fixture_rows():
    rows = [["0 00000000 PREVAILING_DEF_IRONLY marker_%d" % index] for index in range(9)]
    rows[0] = ["0 00000000 RESOLVED_IR fiber_panic"]
    rows[1] = ["0 00000000 PREEMPTED_IR fiber_panic", "1 00000000 PREVAILING_DEF_IRONLY fallback_marker"]
    rows[8] = ["0 00000000 PREVAILING_DEF_IRONLY fiber_panic"]
    return rows


def resolution_text(rows=None, providers=PROVIDERS):
    rows = fixture_rows() if rows is None else rows
    lines = [str(len(providers))]
    for provider, symbols in zip(providers, rows):
        lines.append(provider + " " + str(len(symbols)))
        lines.extend(symbols)
    return "\n".join(lines) + "\n"


class ResolutionTests(unittest.TestCase):
    def rejects(self, text, providers=PROVIDERS):
        with self.assertRaisesRegex(ValueError, r"^REJECT:CM3-LTO-RESOLUTION "):
            r.parse(text, providers)

    def test_positive_list_tuple_lf_crlf_and_typed_rows(self):
        for providers in (PROVIDERS, list(PROVIDERS)):
            for text in (resolution_text(), resolution_text().replace("\n", "\r\n")):
                with self.subTest(providers=type(providers).__name__, crlf="\r" in text):
                    parsed = r.parse(text, providers)
                    self.assertEqual([item["Provider"] for item in parsed], list(PROVIDERS))
                    self.assertEqual(len(parsed), 9)
                    self.assertEqual(sum(len(item["Symbols"]) for item in parsed), 10)
                    self.assertEqual(parsed[1]["Symbols"][0], dict(Index=0, Unit="00000000",
                                     Resolution="PREEMPTED_IR", Name="fiber_panic"))
                    self.assertEqual(parsed[8]["Symbols"][0]["Resolution"], "PREVAILING_DEF_IRONLY")
                    for item in parsed:
                        for row in item["Symbols"]:
                            self.assertIs(type(row["Index"]), int)
                            self.assertTrue(all(type(row[key]) is str for key in ("Unit", "Resolution", "Name")))

    def test_all_declared_statuses_and_complete_provider_rows_retained(self):
        rows = fixture_rows()
        statuses = ("PREVAILING_DEF_IRONLY", "PREVAILING_DEF", "PREEMPTED_IR", "RESOLVED_IR", "RESOLVED_EXEC")
        rows[3] = ["%d 12abcdef %s role_%d" % (index, status, index) for index, status in enumerate(statuses)]
        parsed = r.parse(resolution_text(rows), PROVIDERS)
        self.assertEqual([row["Resolution"] for row in parsed[3]["Symbols"]], list(statuses))
        self.assertEqual([row["Index"] for row in parsed[3]["Symbols"]], list(range(5)))
        self.assertEqual([row["Unit"] for row in parsed[3]["Symbols"]], ["12abcdef"] * 5)

    def test_provider_count_order_identity_and_duplicate_headers_reject(self):
        text = resolution_text()
        for count in ("8", "10", "09", "9.0", "True", " 9", "+9"):
            with self.subTest(count=count):
                self.rejects(count + text[1:])
        for providers in (PROVIDERS[:-1], PROVIDERS + ("C:/foreign.o",),
                          (PROVIDERS[1], PROVIDERS[0], *PROVIDERS[2:]),
                          (PROVIDERS[0],) + PROVIDERS[:-1]):
            with self.subTest(providers=providers):
                self.rejects(text, providers)
        self.rejects(text.replace(PROVIDERS[2], "C:/other/input-02.o"))
        self.rejects(text.replace(PROVIDERS[2], PROVIDERS[3]))

    def test_provider_configuration_rejects_bool_float_nonsequence_and_bad_paths(self):
        for providers in (None, True, False, 9, 9.0, "nine", {}, set(PROVIDERS), iter(PROVIDERS)):
            with self.subTest(type=type(providers).__name__):
                self.rejects(resolution_text(), providers)
        for value in (True, False, 1, 1.0, None, b"provider.o", "", "line\npath", "line\rpath"):
            providers = list(PROVIDERS)
            providers[3] = value
            with self.subTest(path=value):
                self.rejects(resolution_text(), providers)

    def test_text_configuration_and_control_characters_reject(self):
        for value in (None, True, False, 9, 9.0, [], {}, resolution_text().encode("ascii")):
            with self.subTest(type=type(value).__name__):
                self.rejects(value)
        for value in ("\0", "\t", "\x1f", "\x7f", "\u00e9", "\r"):
            with self.subTest(character=repr(value)):
                self.rejects(resolution_text().replace("fallback_marker", "fallback" + value + "marker"))

    def test_row_counts_zero_leading_zero_truncation_extra_and_trailing_reject(self):
        text = resolution_text()
        header = PROVIDERS[1] + " 2"
        for count in ("0", "02", "1", "3", "-2", "2.0", "True", " 2", "+2"):
            with self.subTest(count=count):
                self.rejects(text.replace(header, PROVIDERS[1] + " " + count))
        self.rejects("\n".join(text.splitlines()[:-1]) + "\n")
        self.rejects(text + "0 00000000 RESOLVED_IR extra\n")
        self.rejects(text + "\n")
        self.rejects(text + "C:/foreign.o 1\n0 00000000 RESOLVED_EXEC foreign\n")

    def test_row_index_canonical_nonnegative_decimal_only(self):
        rows = fixture_rows()
        for index in ("00", "01", "-1", "+1", "1.0", "True", "0x1", "", " 0"):
            changed = copy.deepcopy(rows)
            changed[4] = [index + " 00000000 PREVAILING_DEF marker_4"]
            with self.subTest(index=index):
                self.rejects(resolution_text(changed))
        rows[4] = ["123 00000000 PREVAILING_DEF marker_4"]
        self.assertEqual(r.parse(resolution_text(rows), PROVIDERS)[4]["Symbols"][0]["Index"], 123)

    def test_unit_ids_exact_eight_lowercase_hex(self):
        for unit in ("0000000", "000000000", "ABCDEF12", "0000000g", "0x000000", "1.0", "True"):
            rows = fixture_rows()
            rows[4] = ["0 " + unit + " PREVAILING_DEF marker_4"]
            with self.subTest(unit=unit):
                self.rejects(resolution_text(rows))

    def test_duplicate_row_index_or_name_reject_but_provider_local_ids_allowed(self):
        for second in ("0 12345678 PREVAILING_DEF second_name", "1 12345678 PREVAILING_DEF marker_4"):
            rows = fixture_rows()
            rows[4].append(second)
            with self.subTest(second=second):
                self.rejects(resolution_text(rows))
        parsed = r.parse(resolution_text(), PROVIDERS)
        self.assertEqual(parsed[0]["Symbols"][0]["Index"], parsed[8]["Symbols"][0]["Index"])
        self.assertEqual(parsed[0]["Symbols"][0]["Name"], parsed[8]["Symbols"][0]["Name"])

    def test_resolution_status_unknown_case_alias_and_spacing_reject(self):
        for status in ("PREEMPTED_REG", "UNDEF", "PREVAILING_DEF_IRONLY_EXP", "preempted_ir", "PREEMPTED_IR ", ""):
            with self.subTest(status=status):
                self.rejects(resolution_text().replace("PREEMPTED_IR", status))

    def test_symbol_names_and_unconsumed_columns_reject(self):
        for name in ("0panic", "fiber.panic", "fiber-panic", "fiber_panic extra", "", "fiber/panic"):
            with self.subTest(name=name):
                self.rejects(resolution_text().replace("fallback_marker", name))
        rows = fixture_rows()
        rows[4] = ["0 00000000 PREVAILING_DEF _marker4"]
        self.assertEqual(r.parse(resolution_text(rows), PROVIDERS)[4]["Symbols"][0]["Name"], "_marker4")

    def test_parser_is_pure_does_not_mutate_config_or_share_results(self):
        providers, text = list(PROVIDERS), resolution_text()
        original = copy.deepcopy(providers)
        with patch("builtins.open", side_effect=AssertionError("pure parser opened file")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure parser read file")), \
                patch.object(Path, "read_text", side_effect=AssertionError("pure parser read text")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure parser spawned process")):
            result = r.parse(text, providers)
        self.assertEqual(providers, original)
        result[0]["Symbols"][0]["Name"] = "mutated-output"
        self.assertEqual(r.parse(text, providers)[0]["Symbols"][0]["Name"], "fiber_panic")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(REPO)
            or REPO.is_relative_to(output) or not output.is_relative_to(temporary)):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_CM3_LTO_RESOLUTION_GRAMMAR_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualResolutionFileTested=False, ActualLinkTested=False,
        Qualification=False, NativeCommandsExecuted=0, ToolInvocations=0, FullABIProof=False,
        SourceIRProof=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        CanonicalProtocolValidated=False, InstructionEquivalence=False, PolicyEquivalence=False,
        FinalReferenceParity=False, CompleteObjectProof=False, KernelRuntimeProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), SOURCE)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {item: item.read_bytes() for item in paths}
        report["SourceHashes"] = {str(item): sha(data) for item, data in buffers.items()}
        global r
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            spec = importlib.util.spec_from_file_location("synthetic_cm3_lto_resolution", SOURCE)
            r = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = r
            exec(compile(buffers[SOURCE], str(SOURCE), "exec"), r.__dict__)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ResolutionTests)
            count = suite.countTestCases()
            if count != EXPECTED_METHODS:
                raise ValueError("exact synthetic resolution control method count required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
            for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == count and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for item, digest in report["SourceHashes"].items():
            try:
                if sha(Path(item).read_bytes()) != digest:
                    report["SourceDrift"].append(item)
                else:
                    report["ClosingFilesVerified"] += 1
            except OSError:
                report["SourceDrift"].append(item)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 2 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
