# package/hatch_build.py
from hatchling.builders.hooks.plugin.interface import BuildHookInterface
import shutil
from pathlib import Path

class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        """Runs before building the package."""
        root = Path(__file__).resolve().parent.parent
        core_dir = root / "core"
        dest_dir = Path(__file__).resolve().parent / "src" / "s2n_py" / "core"

        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        shutil.copytree(core_dir, dest_dir)

        print(f"[SUCCESS✅] Copied from /core → {dest_dir}")