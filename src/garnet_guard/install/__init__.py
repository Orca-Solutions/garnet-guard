"""The install wrapper and the agent hooks (SPEC §10.3 and §10.4).

``garnet pip install`` and ``garnet uv add|remove|lock|sync`` resolve the
change with builds off, check it, and hand off an install of exactly what
was checked. ``garnet hook claude-code|codex run`` reads the shell command
an agent is about to run and checks the pip and uv commands in it the same
way, without installing anything.

Nothing here imports, builds or runs a package Garnet inspects. The only
programs started are the user's own package manager (with builds off for
the resolve step) and ``git``: ``git show`` for a base lockfile, and
``git ls-files`` to see whether a package manager is committed to the
repository.
"""
