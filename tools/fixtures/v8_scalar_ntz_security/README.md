# Scalar V8 Security Historical Input

`pre_audit_cm33_handler.c` is the actual historical source consumed by the
`pre-fix-handler` archive negative in `tools/test_v8_scalar_ntz_security.ps1`.
It is not a runtime implementation or a supported old handler.

- Repository commit: `5c34785088e3496540a8dcbec1351fac241e11ca`.
- Original path: `fiber/port/ARM_CM33/non_secure/fiber_port_svc.c`.
- Consumed form: UTF-8 without BOM, LF line endings, no final newline. This is
  exactly the former `Run-Tool git show` result joined with LF.
- Length: 16,959 bytes.
- SHA256: `21F1285D0F39511560BDD4E1F8CB0B961DFF0D0AF4CE644A2405471B045FB212`.

The source was copied byte-for-byte from the retained pre-audit-handler proof
input and independently compared with that commit's Git blob using the former
join semantics. It was not reconstructed from current production. The local
`.gitattributes` keeps LF bytes stable under `core.autocrlf=true`.

The runner validates length and SHA before compilation and tests exact missing
and corrupt-file diagnostics. It never falls back to Git, current source, or an
optional/absent negative. Both normal and LTO cases compile this same source
with fresh current common/runtime/boot/attachment objects. Matching archives
must link with strong SVC/PendSV vectors; the old handler must fail specifically
on the missing current handler-component anchor. The other stale BASEPRI and
reverse-ABI archive controls remain independent.

Historical handler execution is not qualified. This fixture proves archive
extraction and identity rejection, not its obsolete runtime semantics.
