"""Environment variables that make the system's loader load code into a program.

The dynamic loader reads these before any program's own code runs, so a
library they name runs inside npm, node, pip, uv, Python and every program
those start. The check takes them out of every program it runs before the
user approves the command, and the hooks ask when the command line sets
one. Only the standard library is used, so pip, uv and npm code can all
import this module.
"""

from __future__ import annotations

from collections.abc import Mapping

# glibc and musl (Linux) and macOS's dyld. ``LD_LIBRARY_PATH`` and the
# ``DYLD_*_PATH`` settings make the loader pick a library from another folder
# in place of the one a program links. Names are compared in upper case.
LOADER_PRELOAD = frozenset(
    {
        "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_VERSION_LIBRARY_PATH", "DYLD_VERSION_FRAMEWORK_PATH", "DYLD_IMAGE_SUFFIX",
        "DYLD_ROOT_PATH",
    }
)  # fmt: skip
# Every other DYLD_ setting, and the 32- and 64-bit spellings other systems'
# loaders read (Solaris LD_PRELOAD_64, FreeBSD LD_32_PRELOAD), count too.
LOADER_PRELOAD_PREFIXES = ("DYLD_", "LD_PRELOAD_", "LD_AUDIT_", "LD_LIBRARY_PATH_", "LD_32_")


def is_loader_preload(name: str) -> bool:
    """True when ``name`` is one of the loader's code-loading settings (any case)."""
    upper = name.upper()
    return upper in LOADER_PRELOAD or upper.startswith(LOADER_PRELOAD_PREFIXES)


def without_loader_preloads(env: Mapping[str, str]) -> dict[str, str]:
    """``env`` with every loader preload setting taken out."""
    return {k: v for k, v in env.items() if not is_loader_preload(k)}


def set_by_command(command_env: Mapping[str, str], outer: Mapping[str, str]) -> list[str]:
    """The loader preload settings a command line sets or changes: those in
    ``command_env`` (the outer environment plus the line's assignments and
    exports) whose value differs from ``outer``'s. Sorted."""
    return sorted(k for k, v in command_env.items() if is_loader_preload(k) and outer.get(k) != v)
