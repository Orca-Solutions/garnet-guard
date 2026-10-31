"""The install wrapper (SPEC §10.3).

``garnet pip install`` and ``garnet uv add|remove|lock|sync`` resolve the
change with builds off, check it, and hand off an install of exactly what
was checked.

Nothing here imports, builds or runs a package Garnet inspects. The only
programs started are the user's own package manager (with builds off for
the resolve step) and ``git show`` for a base lockfile.
"""
