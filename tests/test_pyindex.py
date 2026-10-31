from garnet_guard.facts.pyindex import index_module


def names(src: str) -> set[str]:
    calls, _ = index_module(src.encode())
    return {c.name for c in calls}


def test_top_level_call_resolves_alias() -> None:
    assert names("import subprocess as sp\nsp.run(['x'])\n") == {"subprocess.run"}
    assert names("from os import system\nsystem('x')\n") == {"os.system"}


def test_function_body_not_import_time() -> None:
    assert names("import subprocess\ndef f():\n    subprocess.run(['x'])\n") == set()


def test_function_reached_through_thread_target() -> None:
    src = (
        "import subprocess, threading\n"
        "def _run():\n    subprocess.Popen(['x'])\n"
        "threading.Thread(target=_run, daemon=True).start()\n"
    )
    calls, _ = index_module(src.encode())
    assert [(c.name, c.via) for c in calls] == [("subprocess.Popen", "_run")]


def test_main_guard_skipped() -> None:
    assert names("import os\nif __name__ == '__main__':\n    os.system('x')\n") == set()


def test_exec_and_literal_import_module() -> None:
    assert names("exec('1')\n") == {"exec"}
    assert names("import importlib\nimportlib.import_module('json')\n") == set()
    assert names("import importlib\nm='x'\nimportlib.import_module(m)\n") == {
        "importlib.import_module"
    }


def test_class_body_and_decorators_run_at_import() -> None:
    assert names("import os\nclass A:\n    x = os.popen('id')\n") == {"os.popen"}


def test_own_package_calls_not_sensitive() -> None:
    src = b"from requests.adapters import HTTPAdapter\nHTTPAdapter()\n"
    calls, _ = index_module(src, own=frozenset({"requests"}), project="requests")
    assert calls == ()
    # The same call from a release that only ships a top-level requests module.
    calls, _ = index_module(src, own=frozenset({"demo", "requests"}), project="demo")
    assert [c.name for c in calls] == ["requests.adapters.HTTPAdapter"]


def test_returned_function_is_not_reached() -> None:
    # pip 26.2's vendored platformdirs: picks a function at import, never calls it.
    src = (
        b"import ctypes\n"
        b"def via_ctypes():\n    return ctypes.windll.LoadLibrary('shell32')\n"
        b"def _pick():\n    return via_ctypes\n"
        b"get_folder = _pick()\n"
        b"TABLE = {'a': via_ctypes}\n"
    )
    calls, _ = index_module(src)
    assert calls == ()


def test_function_passed_to_a_call_or_decorator_is_reached() -> None:
    src = (
        b"import atexit, os, subprocess, threading\n"
        b"def a():\n    os.system('a')\n"
        b"def b():\n    subprocess.run(['b'])\n"
        b"def deco(f):\n    os.system('deco')\n    return f\n"
        b"threading.Thread(target=a).start()\n"
        b"atexit.register(b)\n"
        b"@deco\ndef c():\n    pass\n"
    )
    calls, _ = index_module(src)
    assert {(c.name, c.via) for c in calls} == {
        ("os.system", "a"),
        ("subprocess.run", "b"),
        ("os.system", "deco"),
    }


def test_lambda_called_or_passed_at_import_is_reached() -> None:
    assert names("import os\n(lambda: os.system('id'))()\n") == {"os.system"}
    assert names("import atexit, subprocess\natexit.register(lambda: subprocess.run(['x']))\n") == {
        "subprocess.run"
    }
    assert names("import os\nf = lambda: os.system('id')\nf()\n") == {"os.system"}
    # Stored and never called: not reached, like a function.
    assert names("import os\nf = lambda: os.system('id')\n") == set()


def test_class_instantiated_at_import_runs_its_init() -> None:
    cls = "import os\nclass Boot:\n    def __init__(self):\n        os.system('id')\n"
    calls, _ = index_module((cls + "Boot()\n").encode())
    assert [(c.name, c.via) for c in calls] == [("os.system", "Boot")]
    assert names(cls) == set()  # defined, never instantiated
    assert names(cls + "class Sub(Boot):\n    pass\nSub()\n") == {"os.system"}
    static = "import os\nclass K:\n    @staticmethod\n    def boot():\n        os.system('id')\n"
    assert names(static + "K.boot()\n") == {"os.system"}
    assert names(static) == set()


def test_star_import_of_a_sensitive_module() -> None:
    assert names("from subprocess import *\nrun(['x'])\n") == {"subprocess.run"}
    assert names("from os import *\nsystem('x')\n") == {"os.system"}
    # Builtins, the module's own definitions and harmless names stay quiet.
    assert names("from subprocess import *\nprint('x')\nlist()\n") == set()
    assert names("from subprocess import *\ndef run():\n    pass\nrun()\n") == set()
    assert names("from os import *\ngetcwd()\n") == set()


def test_getattr_and_import_with_literal_names_resolve() -> None:
    assert names("import os\ngetattr(os, 'system')('id')\n") == {"os.system"}
    assert names("import os\ngetattr(os, 'sys' + 'tem')('id')\n") == {"os.system"}
    assert names("import importlib\nimportlib.import_module('os').system('id')\n") == {"os.system"}
    assert names("__import__('os').system('id')\n") == {"__import__", "os.system"}
    # A name built at runtime can't be followed without running code.
    assert names("import os\nn = 'system'\ngetattr(os, n)('id')\n") == set()


def test_base64_decode_feeding_a_sensitive_call_is_its_own_entry() -> None:
    assert names("import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n") == {
        "exec",
        "base64.b64decode → exec",
    }
    assert names("import base64, zlib\nexec(zlib.decompress(base64.b85decode('x')))\n") == {
        "exec",
        "base64.b85decode → exec",
    }
    assert names("import base64\nblob = base64.b64decode('x')\nexec(blob)\n") == {
        "exec",
        "base64.b64decode → exec",
    }
    assert names("from base64 import b64decode as d\nexec(d('x'))\n") == {
        "exec",
        "base64.b64decode → exec",
    }
    # Decoding on its own is not sensitive.
    assert names("import base64\nprint(base64.b64decode('x'))\n") == set()


def test_assignment_aliases_and_getattr_on_a_module_object() -> None:
    from garnet_guard.facts.pyindex import scan_module

    assert names("import subprocess\nsp = subprocess\nsp.run(['x'])\n") == {"subprocess.run"}
    assert names("import os\nrun = os.system\nrun('x')\n") == {"os.system"}
    # num2words 0.5.15: the module reached through sys.modules, then CDLL through getattr.
    src = (
        "import os, sys, ctypes\n"
        "try:\n"
        "    ct = getattr(sys.modules[__name__], 'ctypes')\n"
        "    lib = getattr(ct, 'CDLL')(os.path.join('here', '_build.py'))\n"
        "    getattr(lib, 'main')()\n"
        "except Exception:\n"
        "    pass\n"
    )
    assert names(src) == {"ctypes.CDLL"}
    # Only a module the file imported is read that way.
    assert names("import sys\nx = getattr(sys.modules[__name__], 'ctypes')\nx.CDLL('a')\n") == set()
    assert scan_module(b"import os\nclass K:\n    pass\n", entry="missing").calls == ()


def test_calls_into_own_package_are_reported_not_flagged() -> None:
    from garnet_guard.facts.pyindex import scan_module

    src = b"from memos.log import get_logger\nfrom . import util\nlogger = get_logger(__name__)\nutil.setup()\n"
    scan = scan_module(
        src, own=frozenset({"memos"}), module="memos.api.client", path="memos/api/client.py"
    )
    assert scan.calls == ()
    assert scan.calls_out == ("memos.api.util.setup", "memos.log.get_logger")


def test_scan_from_an_entry_follows_the_chain_inside_the_module() -> None:
    from garnet_guard.facts.pyindex import scan_module

    src = (
        b"import subprocess\n"
        b"def configure():\n"
        b"    from memos._stage0 import trigger\n"
        b"    trigger()\n"
        b"def get_logger(name):\n"
        b"    configure()\n"
        b"    return name\n"
        b"def unused():\n"
        b"    subprocess.run(['x'])\n"
    )
    scan = scan_module(src, own=frozenset({"memos"}), module="memos.log", entry="get_logger")
    assert scan.calls == () and scan.calls_out == ("memos._stage0.trigger",)
    assert scan_module(src, own=frozenset({"memos"}), module="memos.log").calls_out == ()


def test_nested_function_handed_to_a_call_is_followed() -> None:
    # The mrmustard 0.7.4 shape: a module-level call runs a function that
    # defines _run inside itself and starts it on a thread.
    src = (
        "import threading\n\n"
        "def _check():\n"
        "    def _run():\n"
        "        import subprocess, urllib.request\n"
        "        subprocess.check_output(['uname', '-a'])\n"
        "        urllib.request.urlopen('https://example.invalid/x')\n"
        "    threading.Thread(target=_run, daemon=True).start()\n\n"
        "_check()\n"
    )
    assert names(src) == {"subprocess.check_output", "urllib.request.urlopen"}
    # Two functions nesting the same name are followed separately.
    twice = (
        "import os, socket\n\n"
        "def a():\n    def _go():\n        os.system('x')\n    _go()\n\n"
        "def b():\n    def _go():\n        socket.socket()\n    _go()\n\n"
        "a()\nb()\n"
    )
    assert names(twice) == {"os.system", "socket.socket"}
    # A nested function that is only returned does not run.
    stored = (
        "import os\n\n"
        "def make():\n    def _go():\n        os.system('x')\n    return _go\n\n"
        "handler = make()\n"
    )
    assert names(stored) == set()


def test_a_dotted_name_needs_an_imported_head() -> None:
    # curl-cffi 0.15.0: a local list called requests; oscrypto 0.17.3: a local
    # socket beside ``import socket as socket_``.
    assert names("def run():\n    requests = []\n    requests.append(1)\nrun()\n") == set()
    assert (
        names(
            "import socket as socket_\ndef f(s):\n    socket = s\n    socket.settimeout(5)\nf(1)\n"
        )
        == set()
    )
    assert names("import os.path\nos.system('x')\n") == {"os.system"}
    assert names("import socket as socket_\nsocket_.socket()\n") == {"socket.socket"}


def test_a_module_level_definition_shadows_a_builtin() -> None:
    # nltk 3.10.4 redos.py defines its own compile().
    assert names("def compile(src, flags):\n    return src\n\ncompile('a', 0)\n") == set()
    assert names("import re\ncompile = re.compile\ncompile('a')\n") == set()
    assert names("class exec:\n    pass\n\nexec('a')\n") == set()
    assert names("compile('a', 'b', 'exec')\n") == {"compile"}


def test_a_handed_function_carries_the_call_it_went_to() -> None:
    from garnet_guard.facts.pyindex import scan_module

    def handed(src: str) -> set[str | None]:
        return {c.handed_to for c in scan_module(src.encode()).calls}

    body = "import subprocess\nfrom functools import partial\n\ndef _run():\n    subprocess.run(['x'])\n\n"
    # partd 1.3.0 built partial(Encode, ...) at import; nothing ran Encode.
    assert handed(body + "runner = partial(_run)\n") == {"functools.partial"}
    # The same partial called at once runs _run.
    assert handed(body + "partial(_run)()\n") == {None}
    # A function both handed and called counts as called.
    assert handed(body + "runner = partial(_run)\n_run()\n") == {None}
    assert handed(body + "import threading\nthreading.Thread(target=_run).start()\n") == {
        "threading.Thread"
    }
    assert handed("import atexit, os\natexit.register(lambda: os.system('x'))\n") == {
        "atexit.register"
    }
    # A factory the module defines itself is named as written.
    src = body + "def wrap(f):\n    return f\n\nrun = wrap(_run)\n"
    assert handed(src) == {"wrap"}
    # Handing one of the package's own callables is recorded with the call.
    scan = scan_module(
        b"from functools import partial\nfrom memos import work\njob = partial(work.go)\n",
        own=frozenset({"memos"}),
        module="memos.api",
        path="memos/api.py",
    )
    assert scan.calls_out == () and scan.handed_out == (("memos.work.go", "functools.partial"),)


def test_sensitive_calls_anywhere_names_the_enclosing_function() -> None:
    from garnet_guard.facts.pyindex import sensitive_calls

    src = (
        "import subprocess as sp\n"
        "import demo.helpers\n"
        "class Model:\n"
        "    def __init__(self):\n"
        "        sp.Popen(['x'])\n"
        "def dl():\n"
        "    demo.helpers.run()\n"
        "    return sp.run(['y'])\n"
        "sp.call(['z'])\n"
    )
    calls = sensitive_calls(src.encode(), own=frozenset({"demo"}))
    assert [(c.name, c.line, c.via) for c in calls] == [
        ("subprocess.Popen", 5, "Model.__init__"),
        ("subprocess.run", 8, "dl"),
        ("subprocess.call", 9, None),
    ]


# Set 2026-10-c: one line per name added, written the way code imports it.
WIDENED = [
    ("import os\nos.fork()\n", "os.fork"),
    ("import os\nos.forkpty()\n", "os.forkpty"),
    ("import os\nos.startfile('x')\n", "os.startfile"),
    ("import pty\npty.fork()\n", "pty.fork"),
    ("import asyncio\nasyncio.create_subprocess_exec('x')\n", "asyncio.create_subprocess_exec"),
    ("import asyncio\nasyncio.create_subprocess_shell('x')\n", "asyncio.create_subprocess_shell"),
    ("from multiprocessing import Process\nProcess(target=print)\n", "multiprocessing.Process"),
    (
        "from multiprocessing.context import SpawnProcess\nSpawnProcess()\n",
        "multiprocessing.context.SpawnProcess",
    ),
    (
        "import multiprocessing.context as c\nc.ForkProcess()\n",
        "multiprocessing.context.ForkProcess",
    ),
    (
        "import multiprocessing.context as c\nc.ForkServerProcess()\n",
        "multiprocessing.context.ForkServerProcess",
    ),
    ("import _winapi\n_winapi.CreateProcess(None, 'x')\n", "_winapi.CreateProcess"),
    ("from distutils.spawn import spawn\nspawn(['x'])\n", "distutils.spawn.spawn"),
    ("from distutils.util import spawn\nspawn(['x'])\n", "distutils.util.spawn"),
    ("from distutils.ccompiler import spawn\nspawn(['x'])\n", "distutils.ccompiler.spawn"),
    (
        "import distutils.archive_util as a\na.spawn(['x'])\n",
        "distutils.archive_util.spawn",
    ),
    ("import pydoc\npydoc.pipepager('t', 'x')\n", "pydoc.pipepager"),
    ("import pydoc\npydoc.tempfilepager('t', 'x')\n", "pydoc.tempfilepager"),
    ("import _posixsubprocess\n_posixsubprocess.fork_exec()\n", "_posixsubprocess.fork_exec"),
    ("import importlib\nimportlib.__import__('json')\n", "importlib.__import__"),
    ("import runpy\nrunpy.run_path('x.py')\n", "runpy.run_path"),
    ("import zipimport\nzipimport.zipimporter('x.zip')\n", "zipimport.zipimporter"),
    (
        "import importlib.util as u\nu.spec_from_file_location('m', 'x.py')\n",
        "importlib.util.spec_from_file_location",
    ),
    (
        "from importlib.util import spec_from_loader\nspec_from_loader('m', None)\n",
        "importlib.util.spec_from_loader",
    ),
    (
        "from importlib.machinery import SourceFileLoader\nSourceFileLoader('m', 'x.py')\n",
        "importlib.machinery.SourceFileLoader",
    ),
    (
        "import importlib.machinery\nimportlib.machinery.SourcelessFileLoader('m', 'x.pyc')\n",
        "importlib.machinery.SourcelessFileLoader",
    ),
    (
        "from importlib.machinery import ExtensionFileLoader\nExtensionFileLoader('m', 'x.so')\n",
        "importlib.machinery.ExtensionFileLoader",
    ),
    ("import imp\nimp.load_source('m', 'x.py')\n", "imp.load_source"),
    ("import imp\nimp.load_compiled('m', 'x.pyc')\n", "imp.load_compiled"),
    ("from imp import load_dynamic\nload_dynamic('m', 'x.so')\n", "imp.load_dynamic"),
    ("import imp\nimp.load_module('m', None, 'x.py', ('.py', 'r', 1))\n", "imp.load_module"),
    ("import imp\nimp.load_package('m', 'x')\n", "imp.load_package"),
    ("import types\ntypes.FunctionType(None, {})\n", "types.FunctionType"),
    ("import types\ntypes.LambdaType(None, {})\n", "types.LambdaType"),
    ("from types import CodeType\nCodeType()\n", "types.CodeType"),
    ("import asyncio\nasyncio.open_connection('h', 1)\n", "asyncio.open_connection"),
    ("import asyncio\nasyncio.open_unix_connection('p')\n", "asyncio.open_unix_connection"),
    ("import asyncio\nasyncio.start_server(None, 'h', 1)\n", "asyncio.start_server"),
    ("import asyncio\nasyncio.start_unix_server(None, 'p')\n", "asyncio.start_unix_server"),
    ("import ssl\nssl.create_connection(('h', 443))\n", "ssl.create_connection"),
    ("from ssl import socket\nsocket()\n", "ssl.socket"),
    ("import urllib3\nurllib3.PoolManager()\n", "urllib3.PoolManager"),
    ("import urllib3\nurllib3.ProxyManager('u')\n", "urllib3.ProxyManager"),
    ("import urllib3\nurllib3.HTTPConnectionPool('h')\n", "urllib3.HTTPConnectionPool"),
    (
        "from urllib3 import HTTPSConnectionPool\nHTTPSConnectionPool('h')\n",
        "urllib3.HTTPSConnectionPool",
    ),
    ("import urllib3\nurllib3.connection_from_url('u')\n", "urllib3.connection_from_url"),
    ("import urllib3\nurllib3.proxy_from_url('u')\n", "urllib3.proxy_from_url"),
    ("import urllib3\nurllib3.request('GET', 'u')\n", "urllib3.request"),
    (
        "import urllib3.connection\nurllib3.connection.HTTPConnection('h')\n",
        "urllib3.connection.HTTPConnection",
    ),
    (
        "from urllib3.connection import HTTPSConnection\nHTTPSConnection('h')\n",
        "urllib3.connection.HTTPSConnection",
    ),
    (
        "from urllib3.connection import VerifiedHTTPSConnection\nVerifiedHTTPSConnection('h')\n",
        "urllib3.connection.VerifiedHTTPSConnection",
    ),
    (
        "from urllib3.contrib.socks import SOCKSProxyManager\nSOCKSProxyManager('u')\n",
        "urllib3.contrib.socks.SOCKSProxyManager",
    ),
    ("import ftplib\nftplib.FTP('h')\n", "ftplib.FTP"),
    ("import smtplib\nsmtplib.SMTP('h')\n", "smtplib.SMTP"),
    ("import poplib\npoplib.POP3('h')\n", "poplib.POP3"),
    ("import imaplib\nimaplib.IMAP4_SSL('h')\n", "imaplib.IMAP4_SSL"),
    ("import telnetlib\ntelnetlib.Telnet('h')\n", "telnetlib.Telnet"),
    ("import xmlrpc.client\nxmlrpc.client.ServerProxy('u')\n", "xmlrpc.client.ServerProxy"),
    ("import webbrowser\nwebbrowser.open('u')\n", "webbrowser.open"),
]


def test_widened_set_names_each_call() -> None:
    for src, name in WIDENED:
        assert names(src) == {name}, src


def test_widened_set_leaves_common_calls_alone() -> None:
    # Calls packages make at import every day, which stay out of the set.
    for src in (
        "import importlib.util\nimportlib.util.find_spec('numpy')\n",
        "import importlib.util\nimportlib.util.module_from_spec(None)\n",
        "import urllib3\nurllib3.disable_warnings()\n",
        "import multiprocessing\nmultiprocessing.cpu_count()\n",
        "import types\ntypes.SimpleNamespace()\n",
        "import os\nos.getpid()\n",
        "from distutils.spawn import find_executable\nfind_executable('git')\n",
        "import pydoc\npydoc.render_doc(len)\n",
        "import ssl\nssl.create_default_context()\n",
        "from distutils.util import strtobool\nstrtobool('yes')\n",
    ):
        assert names(src) == set(), src


def test_subprocess_values_that_start_nothing_are_not_in_the_set() -> None:
    # Building subprocess's exceptions and results, or quoting a command line,
    # runs nothing; the calls that start a process still count.
    for src in (
        "import subprocess\nraise subprocess.CalledProcessError(1, 'x')\n",
        "from subprocess import TimeoutExpired\nraise TimeoutExpired('x', 1)\n",
        "import subprocess as sp\nsp.SubprocessError()\n",
        "import subprocess\nsubprocess.CompletedProcess(['x'], 0)\n",
        "import subprocess\nsubprocess.list2cmdline(['a', 'b c'])\n",
    ):
        assert names(src) == set(), src
    assert names("import subprocess\nsubprocess.run(['x'])\n") == {"subprocess.run"}
    assert names("from subprocess import Popen as P\nP(['x'])\n") == {"subprocess.Popen"}
    assert names("import subprocess\nsubprocess.check_output(['x'])\n") == {
        "subprocess.check_output"
    }


def test_explain_names_the_subprocess_values_left_out() -> None:
    from garnet_guard.facts.pyindex import sensitive_set

    assert (
        "subprocess.* except CalledProcessError, CompletedProcess, SubprocessError, "
        "TimeoutExpired and list2cmdline, which start nothing"
    ) in sensitive_set()


def test_every_line_of_the_explained_set_starts_with_a_name_in_it() -> None:
    # GRN-C012 never counts the first name of a line as the release's own.
    import builtins
    import sys

    from garnet_guard.facts.pyindex import _THIRD_PARTY, sensitive_set

    removed = {"imp", "telnetlib", "distutils"}
    names = set(sys.stdlib_module_names) | set(dir(builtins)) | removed | _THIRD_PARTY
    for line in sensitive_set():
        head = line.split(".")[0].split(" ")[0]
        assert head in names, line


# The same objects under the module that defines them: one line per module.
SAME_AS = [
    ("import builtins\nbuiltins.exec('1')\n", "builtins.exec"),
    ("import builtins as b\nb.eval('1')\n", "builtins.eval"),
    ("from builtins import exec as run\nrun('1')\n", "builtins.exec"),
    ("import builtins\ngetattr(builtins, 'compile')('1', 'f', 'exec')\n", "builtins.compile"),
    ("import builtins\nbuiltins.__import__('json')\n", "builtins.__import__"),
    ("__builtins__.exec('1')\n", "builtins.exec"),  # the module itself in a script
    ("import posix\nposix.system('x')\n", "posix.system"),
    ("from nt import startfile\nstartfile('x')\n", "nt.startfile"),
    ("import _socket\n_socket.socket()\n", "_socket.socket"),
    ("import _ctypes\n_ctypes.dlopen('x')\n", "_ctypes.dlopen"),
    ("import _pickle\n_pickle.loads(b'')\n", "_pickle.loads"),
    (
        "import asyncio\nasyncio.subprocess.create_subprocess_shell('x')\n",
        "asyncio.subprocess.create_subprocess_shell",
    ),
    (
        "from asyncio import subprocess as asp\nasp.create_subprocess_exec('x')\n",
        "asyncio.subprocess.create_subprocess_exec",
    ),
    (
        "from asyncio.streams import open_connection\nopen_connection('h', 1)\n",
        "asyncio.streams.open_connection",
    ),
    (
        "from multiprocessing.context import Process\nProcess()\n",
        "multiprocessing.context.Process",
    ),
    (
        "import importlib._bootstrap as b\nb.spec_from_loader('m', None)\n",
        "importlib._bootstrap.spec_from_loader",
    ),
    (
        "import _frozen_importlib\n_frozen_importlib.spec_from_loader('m', None)\n",
        "_frozen_importlib.spec_from_loader",
    ),
    (
        "from importlib._bootstrap import __import__ as imp\nimp('json')\n",
        "importlib._bootstrap.__import__",
    ),
    ("import _frozen_importlib as f\nf.__import__('json')\n", "_frozen_importlib.__import__"),
    (
        "from importlib._bootstrap_external import SourceFileLoader\nSourceFileLoader('m', 'x.py')\n",
        "importlib._bootstrap_external.SourceFileLoader",
    ),
    (
        "import _frozen_importlib_external as e\ne.spec_from_file_location('m', 'x.py')\n",
        "_frozen_importlib_external.spec_from_file_location",
    ),
    (
        "from setuptools._distutils.spawn import spawn\nspawn(['x'])\n",
        "setuptools._distutils.spawn.spawn",
    ),
    (
        "from setuptools._distutils.ccompiler import spawn\nspawn(['x'])\n",
        "setuptools._distutils.ccompiler.spawn",
    ),
    (
        "from urllib3.poolmanager import PoolManager\nPoolManager()\n",
        "urllib3.poolmanager.PoolManager",
    ),
    (
        "from urllib3.connectionpool import HTTPSConnectionPool\nHTTPSConnectionPool('h')\n",
        "urllib3.connectionpool.HTTPSConnectionPool",
    ),
    (
        "import urllib3.connectionpool as p\np.HTTPSConnection('h')\n",
        "urllib3.connectionpool.HTTPSConnection",
    ),
]


def test_a_name_under_the_module_that_defines_it_counts() -> None:
    from garnet_guard.facts.pyindex import sensitive_calls

    for src, name in SAME_AS:
        assert names(src) == {name}, src
        assert {c.name for c in sensitive_calls(src.encode())} == {name}, src
    # Only the listed names count: the rest of those modules stays out.
    for src in (
        "import posix\nposix.getcwd()\n",
        "import nt\nnt._getfullpathname('x')\n",
        "import _pickle\n_pickle.load(None)\n",
        "from asyncio.subprocess import Process\nProcess(None, None, None)\n",
        "import importlib._bootstrap_external as e\ne.cache_from_source('x.py')\n",
        "from urllib3.poolmanager import PoolKey\nPoolKey()\n",
        "from setuptools._distutils.spawn import find_executable\nfind_executable('git')\n",
        "import builtins\nbuiltins.print('x')\nbuiltins.open('x')\n",
        "import importlib._bootstrap as b\nb._find_spec('x', None)\n",
        "from urllib3.connectionpool import DummyConnection\nDummyConnection()\n",
    ):
        assert names(src) == set(), src


def test_a_top_level_module_named_like_the_standard_library_is_not_the_package() -> None:
    from garnet_guard.facts.pyindex import scan_module, sensitive_calls

    # A wheel that ships an empty os.py or webbrowser.py beside its package:
    # Python still imports the standard library's, so the calls stay sensitive.
    own = frozenset({"demo", "os", "webbrowser", "exec"})
    src = b"import os, webbrowser\nos.system('x')\nwebbrowser.open('u')\nexec('1')\n"
    want = {"os.system", "webbrowser.open", "exec"}
    assert {c.name for c in scan_module(src, own=own, project="demo").calls} == want
    assert {c.name for c in sensitive_calls(src, own=own, project="demo")} == want


# A call to each PyPI library in the set, and to the builtins module.
LIBRARY_CALLS = {
    "requests": "import requests\nrequests.post('u', data='')\n",
    "httpx": "import httpx\nhttpx.get('u')\n",
    "urllib3": "import urllib3\nurllib3.PoolManager()\n",
    "aiohttp": "import aiohttp\naiohttp.ClientSession()\n",
    "setuptools": "from setuptools._distutils.spawn import spawn\nspawn(['x'])\n",
    "builtins": "import builtins\nbuiltins.exec('1')\n",
}


def test_a_top_level_module_named_like_a_library_in_the_set_hides_no_call() -> None:
    from garnet_guard.facts.pyindex import _THIRD_PARTY, scan_module, sensitive_calls

    assert set(LIBRARY_CALLS) == _THIRD_PARTY | {"builtins"}
    for head, src in LIBRARY_CALLS.items():
        # demo ships an empty requests.py (or httpx.py, builtins.py) beside its
        # package. Python imports the installed library, so the call counts. It
        # is followed into the stub as well, in case the stub is what Python imports.
        own = frozenset({"demo", head})
        scan = scan_module(src.encode(), own=own, project="demo")
        [call] = scan.calls
        assert scan.calls_out == (call.name,), head
        assert len(sensitive_calls(src.encode(), own=own, project="demo")) == 1, head


def test_a_library_in_the_set_calls_its_own_modules() -> None:
    from garnet_guard.facts.pyindex import scan_module, sensitive_calls

    # The requests project calling requests.get: its own code, followed there.
    for head, src in LIBRARY_CALLS.items():
        own = frozenset({head})
        scan = scan_module(src.encode(), own=own, project=head)
        if head == "builtins":  # no project's own code: builtins is built in
            assert [c.name for c in scan.calls] == list(scan.calls_out) == ["builtins.exec"]
        else:
            assert scan.calls == () and len(scan.calls_out) == 1, head
            assert sensitive_calls(src.encode(), own=own, project=head) == (), head
    # A call to the standard library stays sensitive in a project named like it.
    scan = scan_module(b"exec('1')\n", own=frozenset({"exec"}), project="exec")
    assert [c.name for c in scan.calls] == ["exec"]


def test_project_name_from_wheel_and_sdist_filenames() -> None:
    from garnet_guard.facts.inventory import project_name

    assert project_name("requests-2.32.3-py3-none-any.whl") == "requests"
    assert project_name("urllib3-2.2.3.tar.gz") == "urllib3"
    assert project_name("Typing_Extensions-4.12.0.zip") == "typing-extensions"
    assert project_name("aiohttp-3.9.5-cp312-cp312-manylinux_2_17_x86_64.whl") == "aiohttp"


def test_explain_lists_builtins_as_the_bare_names() -> None:
    from garnet_guard.facts.pyindex import sensitive_set

    assert "builtins.<name>, counted as <name>" in sensitive_set()
    assert "importlib._bootstrap.<name>, counted as importlib.<name> or importlib.util.<name>" in (
        sensitive_set()
    )


def test_every_top_level_name_in_the_set_is_standard_library_unless_listed() -> None:
    import builtins
    import sys

    from garnet_guard.facts import pyindex

    removed = {"imp", "telnetlib", "distutils"}  # standard library up to Python 3.11 or 3.12
    stdlib = set(sys.stdlib_module_names) | set(dir(builtins)) | removed
    heads = {n.split(".")[0] for n in (*pyindex._EXACT, *pyindex._PREFIXES, *pyindex._SAME_AS)}
    assert heads - stdlib == pyindex._THIRD_PARTY


def sites(src: str) -> list[tuple[int, str, str | None]]:
    calls, _ = index_module(src.encode())
    return [(c.line, c.name, c.via) for c in calls]


# The shape of six as mpmath 0.18 vendors it (mpmath/libmp/six.py:305-335):
# exec_ is the builtin in the Python 3 branch and a function in the Python 2
# branch, which calls it at once.
SIX = """\
import sys
PY3 = sys.version_info[0] == 3
if PY3:
    import builtins
    exec_ = getattr(builtins, "exec")
    print_ = getattr(builtins, "print")
else:
    def exec_(code, globs=None, locs=None):
        exec(\"\"\"exec code in globs, locs\"\"\")
    exec_(\"\"\"def reraise(tp, value, tb=None):
    raise tp, value, tb
\"\"\")
"""


def test_a_def_rebinds_its_name_for_the_rest_of_its_block() -> None:
    # Line 10 calls the exec_ defined at line 8, which calls exec at line 9.
    # It used to be listed as calling builtins.exec, the value exec_ gets in
    # the other branch, at line 5.
    assert sites(SIX) == [(9, "exec", "exec_")]
    # The same in straight-line code, and for a builtin's name.
    alias = "import builtins\nexec_ = builtins.exec\ndef exec_(c):\n    return c\nexec_('x')\n"
    assert sites(alias) == []
    assert (
        sites("import sys\nif sys.platform:\n    def exec(c):\n        return c\n    exec('x')\n")
        == []
    )


def test_an_alias_a_def_unbinds_still_counts_where_the_def_may_not_have_run() -> None:
    # After the if/else, exec_ may be the builtin: six 1.16 runs it there
    # (awscli's copy, raise_from).
    assert sites(SIX + "exec_('def raise_from(value, from_value): raise value')\n") == [
        (9, "exec", "exec_"),
        (13, "builtins.exec", None),
    ]
    # The def's branch may not run, so the other branch and the code after
    # it still see the alias.
    branch = (
        "import subprocess, sys\nrun = subprocess.run\n"
        "if sys.platform == 'x':\n    def run(c):\n        return c\nelse:\n    run(['id'])\n"
        "run(['id'])\n"
    )
    assert sites(branch) == [(7, "subprocess.run", None), (8, "subprocess.run", None)]
    # A function called later may run when the alias still held, so it sees it.
    later = (
        "import subprocess\nrun = subprocess.run\ndef g():\n    run(['id'])\ng()\n"
        "def run(c):\n    return c\n"
    )
    assert sites(later) == [(4, "subprocess.run", "g")]


def test_a_def_that_may_bind_something_else_keeps_the_alias() -> None:
    head = "import subprocess\nrun = subprocess.run\n"
    # A decorator decides what the name holds, and default arguments run
    # before the def binds it.
    decorated = head + "@staticmethod\ndef run(c):\n    return c\nrun(['id'])\n"
    assert sites(decorated) == [(6, "subprocess.run", None)]
    default = head + "def run(c=run(['id'])):\n    return c\n"
    assert sites(default) == [(3, "subprocess.run", None)]
    # An import after the def binds the name again.
    imported = "def run(c):\n    return c\nfrom subprocess import run\nrun(['id'])\n"
    assert sites(imported) == [(4, "subprocess.run", None)]
    # An assignment after the def, and a loop or a try whose def may not
    # have run.
    again = head + "def run(c):\n    return c\nrun = subprocess.run\nrun(['id'])\n"
    assert sites(again) == [(6, "subprocess.run", None)]
    loop = head + "for i in range(0):\n    def run(c):\n        return c\nrun(['id'])\n"
    assert sites(loop) == [(6, "subprocess.run", None)]
    tried = (
        head + "try:\n    def run(c):\n        return c\nexcept Exception:\n    pass\nrun(['id'])\n"
    )
    assert sites(tried) == [(8, "subprocess.run", None)]
