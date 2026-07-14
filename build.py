"""Hatchling build hook for the cffi extension."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Build the cffi extension before wheel creation."""

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        root = Path(self.root)
        interface_path = root / "src" / "py_fn_dsa" / "interface.py"

        spec = importlib.util.spec_from_file_location(
            "py_fn_dsa_build_interface",
            interface_path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load build interface from {interface_path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        built_path = Path(module.build_extension(root))
        build_data["infer_tag"] = True
        build_data["pure_python"] = False
        build_data.setdefault("artifacts", [])
        build_data["artifacts"].append(str(built_path.relative_to(root)).replace("\\", "/"))
