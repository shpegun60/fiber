"""Bounded two-image Cortex-M55 attachment test; stdlib + explicit QEMU only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    root, seconds, manifest_path, rsp_module = sys.argv[1:]
    manifest_path = Path(manifest_path)
    directory = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    deadline = time.monotonic() + int(seconds)
    receipt = {"result": "FAIL", "hardware": False, "machine": "mps3-an547",
               "case": manifest["case"], "kind": manifest["kind"], "query_trace": []}
    process = None
    connection = None
    try:
        for field in ("secure", "nonsecure"):
            image = Path(manifest[field])
            digest = hashlib.sha256(image.read_bytes()).hexdigest().upper()
            require(digest == manifest[field + "_sha256"], field + " image changed")
            receipt[field + "_sha256"] = digest
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = str(Path(root) / "usr/lib/x86_64-linux-gnu") + (
            ":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
        command = [str(Path(root) / "usr/bin/qemu-system-arm"), "-machine", "mps3-an547",
                   "-accel", "tcg", "-display", "none", "-serial", "none", "-monitor", "none",
                   "-no-reboot", "-semihosting-config", "enable=on,target=native", "-L",
                   str(Path(root) / "usr/share/qemu"), "-kernel", manifest["secure"],
                   "-device", "loader,file=" + manifest["nonsecure"]]
        with tempfile.TemporaryDirectory(prefix="fiber-c55s-attach-") as temporary:
            if manifest["kind"] == "real-SG":
                socket_path = str(Path(temporary) / "gdb.sock")
                command += ["-S", "-chardev", "socket,id=attach,path=" + socket_path + ",server=on,wait=off",
                            "-gdb", "chardev:attach"]
            receipt["qemu_command"] = command
            with (directory / "qemu.log").open("wb") as log:
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                           env=env, start_new_session=True)
                if manifest["kind"] == "real-SG":
                    spec = importlib.util.spec_from_file_location("maintained_rsp", rsp_module)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    connection = socket.socket(socket.AF_UNIX)
                    while True:
                        require(process.poll() is None, "QEMU exited before RSP")
                        try:
                            connection.connect(socket_path)
                            break
                        except (FileNotFoundError, ConnectionRefusedError):
                            require(time.monotonic() < deadline, "RSP startup timeout")
                            time.sleep(0.01)
                    rsp = module.Rsp(connection, deadline)
                    rsp.discover_registers()
                    require(rsp.packet("?").startswith(("S", "T")), "Missing initial stop")
                    queries = manifest["queries"]
                    addresses = {q["address"]: q for q in queries}
                    require(len(addresses) == 8, "Non-exact query entry set")
                    for address in addresses:
                        rsp.breakpoint(address)
                    for index in range(8):
                        stop = rsp.packet("c")
                        require(stop.startswith(("S05", "T05")), "Missing query stop: " + stop)
                        pc = rsp.register("pc") & ~1
                        require(pc == queries[index]["address"], "Wrong query call order/address")
                        lr = rsp.register("lr")
                        xpsr = rsp.register("xpsr")
                        require(lr == queries[index]["ns_return"], "Wrong exact Non-secure call return")
                        require((lr & 1) == 0 and 0x10000 <= lr < 0x20000,
                                "Query did not originate across Non-secure SG")
                        require((xpsr & 511) == 0, "Query did not execute in Thread mode")
                        receipt["query_trace"].append({"name": queries[index]["name"], "pc": pc,
                                                       "lr": lr, "ipsr": xpsr & 511})
                        rsp.breakpoint(pc, False)
                        step = rsp.packet("s")
                        require(step.startswith(("S05", "T05")), "Unexpected query step: " + step)
                        rsp.breakpoint(pc)
                    stop = rsp.packet("c")
                    require(stop == "W00", "Unexpected final RSP exit: " + stop)
                code = process.wait(timeout=max(0.01, deadline-time.monotonic()))
            text = (directory / "qemu.log").read_text(errors="replace")
            require("START:C55S-ATTACH:Secure-M55\n" in text, "Missing Secure execution report")
            require("START:C55S-ATTACH:NS-Thread case=" in text, "Missing NS Thread report")
            if "oracle_failure" in manifest:
                require(code == 90, "Compiled mutant did not reach the exact assertion exit")
                marker = "FAIL:C55S-ATTACH check=" + manifest["oracle_failure"] + "\n"
                require(text.count(marker) == 1 and text.count("FAIL-EXIT\n") == 1,
                        "Compiled mutant did not reach the independent oracle")
                require("FAULT" not in text and "PANIC" not in text and "PASS-EXIT" not in text,
                        "Compiled mutant failed incidentally instead of at the oracle")
                receipt.update(result="PASS", exit_code=code, compiled_mutant_rejected_at=marker.strip())
                return
            require(code == 0, "QEMU exit " + str(code) + ": " + text)
            require("FAIL" not in text and "FAULT" not in text, "Failure/fault report")
            expected = manifest["expected_marker"]
            require(text.count(expected) == 1 and text.count("PASS-EXIT:C55S-ATTACH\n") == 1,
                    "Missing/duplicate exact completion report")
            if manifest["case"] < 1000:
                require(text.count("PASS:C55S-ATTACH:constructor19+pinned19+r9+guards\n") == 1,
                        "Missing constructor/reference proof")
            receipt.update(result="PASS", exit_code=code)
    except Exception as error:
        receipt["error"] = str(error)
        receipt["error_type"] = type(error).__name__
        raise
    finally:
        if connection:
            connection.close()
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS:C55S-ATTACH:case=" + str(manifest["case"]))


if __name__ == "__main__":
    main()
