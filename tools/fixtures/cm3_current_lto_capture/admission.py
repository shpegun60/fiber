"""Caller-bound ordinary CM3 reference seed admission, without tool execution.

seed_type(legacy_module) returns Seed(api, args). The frontend must execute
both modules from authenticated, watched source buffers before this factory.
Args use reference_build, reference_receipt_sha256,
reference_artifacts_sha256 and output_dir, as in the legacy reference API.

Only __init__ is duplicated: the legacy constructor hardcodes three seed
identity guards with no overridable admission hook. Every validator, helper
and its defining globals remain inherited from the hash-bound legacy module.
The caller separately binds its current inventory; this adapter grants no
current-inventory, LTO, final-image, ABI, runtime or qualification claim.
"""
from pathlib import Path


LEGACY_SHA256 = "27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC"


def seed_type(legacy_module):
    """Derive only the constructor; helper execution authority is caller-owned."""
    legacy = legacy_module

    class Seed(legacy.Seed):
        def __init__(self, api, args):
            self.api, self.args = api, args
            self.closure = api.Closure()
            self.root = api.checked_path(args.reference_build)
            receipt_sha = api.digest_text(args.reference_receipt_sha256)
            artifacts_sha = api.digest_text(args.reference_artifacts_sha256)
            source_path, legacy_path = api.regular(__file__), api.regular(legacy.__file__)
            source_bytes = self.closure.read(source_path)
            legacy_bytes = self.closure.read(legacy_path, LEGACY_SHA256)
            self.result = self.closure.structured(self.root / "results.json", receipt_sha)
            manifest = self.closure.structured(self.root / "artifacts.json", artifacts_sha)
            self.artifacts = manifest["Artifacts"]
            api.need(type(self.artifacts) is dict and self.artifacts, "nonempty reference seed artifacts required")
            for name, value in self.artifacts.items():
                api.portable_name(name)
                api.digest_text(value)
            api.same(self.artifacts.get("results.json"), receipt_sha, "reference receipt/manifest binding")
            self.closure.tree(self.root, dict(self.artifacts, **{"artifacts.json": artifacts_sha}))
            self.inputs = self.closure.structured(self.root / "inputs.json", self.artifacts["inputs.json"])
            self.originals, self.captures = {}, {}
            rows, self.generated = self.inputs["Files"], self.inputs["Generated"]
            api.need(type(rows) is list and rows and type(self.generated) is dict and self.generated,
                     "complete reference input and generated-file records required")
            for row in rows:
                original, captured = api.regular(row["Original"]), api.regular(row["Captured"])
                api.need(original not in self.originals and captured.is_relative_to(self.root), "unique reference input identity")
                value = api.digest_text(row["Sha256"])
                self.member(captured, value)
                self.closure.read(original, value)
                self.originals[original] = row
                if captured in self.captures:
                    api.same(self.captures[captured]["Sha256"], value, "shared reference capture bytes")
                self.captures[captured] = row
            for path, value in self.generated.items():
                self.member(path, api.digest_text(value))
            self.inventory = api.checked_path(self.result["SourceInventoryReceipt"])
            inventory_manifest = self.inventory / "artifacts.json"
            api.need(inventory_manifest in self.originals, "captured complete source inventory required")
            inventory_hash = self.originals[inventory_manifest]["Sha256"]
            inventory_files = self.closure.structured(inventory_manifest, inventory_hash)["Artifacts"]
            api.need(type(inventory_files) is dict and inventory_files, "nonempty source inventory closure")
            for name, value in inventory_files.items():
                path = api.regular(self.inventory / api.portable_name(name))
                api.need(path.is_relative_to(self.inventory) and path in self.originals, "omitted reference inventory input")
                api.same(self.originals[path]["Sha256"], api.digest_text(value), "reference inventory member hash")
            self.closure.tree(self.inventory, dict(inventory_files, **{"artifacts.json": inventory_hash}))
            self.output = api.checked_path(args.output_dir, must_exist=False)
            self.deny_output({api.REPO, self.root, self.inventory,
                              *(path.parent for path in self.originals), *(path.parent for path in self.captures),
                              *(api.regular(path).parent for path in self.generated)})
            self.validate_scope()
            self.buffers = {path: self.closure.read(path, row["Sha256"]) for path, row in self.captures.items()
                            if path.suffix == ".py"}
            loader_path = api.regular(api.REPO / legacy.LOADER)
            loader_data = self.closure.read(loader_path, legacy.LOADER_SHA256)
            self.buffers[loader_path] = loader_data
            loader = api.load_buffer("cm3_reference_lto_immutable_loader", loader_path, loader_data)
            self.frozen = loader.FrozenSources(self.buffers)
            self.loader_evidence = dict(Path=str(loader_path), Sha256=api.sha(loader_data))
            self.native = self.module(legacy.CLASSIC + "run.py")
            self.recipe, self.model = self.module(legacy.RECIPE), self.module(legacy.MODEL)
            self.process, self.reference_recipe = self.module(legacy.PROCESS), self.module(legacy.REFERENCE)
            self.validate_inventory()
            self.validate_commands()
            self.validate_reference()
            self.validate_recipe()
            self.validate_sources()
            self.validate_links()
            self.validate_prelink()
            api.need(self.closure.read(source_path, api.sha(source_bytes)) == source_bytes,
                     "executed adapter source closing binding")
            api.need(self.closure.read(legacy_path, LEGACY_SHA256) == legacy_bytes,
                     "executed legacy admission source closing binding")
            self.closure.read(api.__file__)
            self.interpreter = api.regular(self.native.interpreter_path())
            self.closure.read(self.interpreter)
            self.deny_output({self.tool_root, self.interpreter.parent, self.reference_root, loader_path.parent,
                              api.regular(api.__file__).parent, source_path.parent, legacy_path.parent})
            self.closure.close()

    return Seed
