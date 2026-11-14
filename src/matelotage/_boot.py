"""Runs at every Python startup via matelotage.pth: cheap, silent, never raises.
Patches pirateface.client.api lazily, when something imports it."""
import contextlib
import os
import sys

TARGET = "pirateface.client.api"


class _PatchOnImport:
    def find_spec(self, fullname, path=None, target=None):
        if fullname != TARGET:
            return None
        sys.meta_path.remove(self)
        try:
            import importlib.util
            spec = importlib.util.find_spec(fullname)
        finally:
            sys.meta_path.insert(0, self)
        if spec is None or spec.loader is None:
            return None
        exec_module = spec.loader.exec_module

        def exec_and_patch(module):
            exec_module(module)
            _patch(module)

        spec.loader.exec_module = exec_and_patch
        return spec


def _patch(module):
    with contextlib.suppress(Exception):
        from matelotage import patch
        patch.install(module)


_finder = _PatchOnImport()
if (os.environ.get("MATELOTAGE_DISABLE") or "").strip() in ("", "0"):
    sys.meta_path.insert(0, _finder)
    if TARGET in sys.modules:
        _patch(sys.modules[TARGET])
