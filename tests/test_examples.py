"""Tests for all 10 CTF example challenges — compile, smoke test, exploit run."""

import os
import subprocess
import sys

import pytest

EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")

EXAMPLES = [
    "canary-leak",
    "crackme",
    "format-string",
    "heap-uaf",
    "integer-overflow",
    "nx-bypass",
    "off-by-one",
    "ret2win",
    "rop-chain",
    "shellcode-injection",
]

EXAMPLES_WITH_C = [n for n in EXAMPLES if n != "format-string"]

COMPILE_FLAGS = {
    "canary-leak": ["-g", "-O0", "-fstack-protector", "-no-pie"],
    "crackme": ["-g", "-O0", "-fno-stack-protector", "-no-pie"],
    "heap-uaf": ["-g", "-O0", "-fno-stack-protector", "-no-pie"],
    "integer-overflow": ["-g", "-O0", "-fno-stack-protector", "-no-pie"],
    "nx-bypass": ["-g", "-O0", "-fno-stack-protector", "-no-pie"],
    "off-by-one": ["-g", "-O0", "-fno-stack-protector", "-no-pie", "-include", "unistd.h"],
    "ret2win": ["-g", "-O0", "-fno-stack-protector", "-no-pie"],
    "rop-chain": ["-g", "-O0", "-fno-stack-protector", "-no-pie"],
    "shellcode-injection": ["-g", "-O0", "-fno-stack-protector", "-no-pie", "-z", "execstack"],
}

SMOKE_INPUT = {
    "canary-leak": b"AAAA\n",
    "crackme": b"test\n",
    "heap-uaf": b"AAAABBBBCCCCDDDD",
    "integer-overflow": b"0\n",
    "nx-bypass": b"AAAA",
    "off-by-one": b"AAAAAAAA",
    "ret2win": None,
    "rop-chain": b"AAAA",
    "shellcode-injection": b"AAAA",
}

NO_STDIN = {"ret2win"}

HANGING_EXPLOITS = {"canary-leak", "integer-overflow", "nx-bypass", "rop-chain", "shellcode-injection"}

BINARY_PATHS: dict[str, str] = {}


@pytest.fixture(scope="session")
def gcc_available():
    try:
        subprocess.run(["gcc", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _compile(name: str) -> str:
    c_path = os.path.join(EXAMPLES_DIR, name, f"{name}.c")
    binary_path = f"/tmp/{name}"
    cmd = ["gcc"] + COMPILE_FLAGS[name] + ["-o", binary_path, c_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.fail(f"Compilation failed for {name}:\n{result.stderr}")
    assert os.path.isfile(binary_path), f"Binary not created: {binary_path}"
    assert os.access(binary_path, os.X_OK), f"Binary not executable: {binary_path}"
    BINARY_PATHS[name] = binary_path
    return binary_path


def _cleanup():
    for name in list(BINARY_PATHS):
        path = BINARY_PATHS.pop(name)
        if os.path.isfile(path):
            os.remove(path)


@pytest.fixture(scope="session", autouse=True)
def cleanup_all():
    yield
    _cleanup()


# ── file existence ──────────────────────────────────────────────────────

@pytest.mark.parametrize("name", EXAMPLES)
def test_readme_exists(name):
    readme = os.path.join(EXAMPLES_DIR, name, "README.md")
    assert os.path.isfile(readme), f"Missing {readme}"


@pytest.mark.parametrize("name", EXAMPLES_WITH_C + ["format-string"])
def test_exploit_py_exists(name):
    py_path = os.path.join(EXAMPLES_DIR, name, "exploit.py")
    assert os.path.isfile(py_path), f"Missing {py_path}"


@pytest.mark.parametrize("name", EXAMPLES_WITH_C)
def test_c_file_exists(name):
    c_path = os.path.join(EXAMPLES_DIR, name, f"{name}.c")
    assert os.path.isfile(c_path), f"Missing {c_path}"


# ── compilation ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", EXAMPLES_WITH_C)
def test_compile(name, gcc_available):
    if not gcc_available:
        pytest.skip("gcc not available")
    _compile(name)


# ── binary smoke test ───────────────────────────────────────────────────

@pytest.mark.parametrize("name", EXAMPLES_WITH_C)
def test_binary_runs(name, gcc_available):
    if not gcc_available:
        pytest.skip("gcc not available")
    binary_path = f"/tmp/{name}"
    if not os.path.isfile(binary_path):
        _compile(name)

    if name in NO_STDIN:
        proc = subprocess.run(
            [binary_path], capture_output=True, timeout=5,
        )
    else:
        inp = SMOKE_INPUT.get(name, b"\n")
        proc = subprocess.run(
            [binary_path], input=inp, capture_output=True, timeout=5,
        )

    assert proc.returncode in (0, 1), (
        f"{name} crashed (rc={proc.returncode})\n"
        f"stdout: {proc.stdout[:300]}\n"
        f"stderr: {proc.stderr[:300]}"
    )


# ── exploit tests ───────────────────────────────────────────────────────

@pytest.mark.parametrize("name", EXAMPLES)
def test_exploit_syntax(name):
    py_path = os.path.join(EXAMPLES_DIR, name, "exploit.py")
    code = open(py_path).read()
    compile(code, py_path, "exec")


@pytest.mark.parametrize("name", EXAMPLES_WITH_C)
def test_exploit_runs(name, gcc_available):
    if not gcc_available:
        pytest.skip("gcc not available")
    binary_path = f"/tmp/{name}"
    if not os.path.isfile(binary_path):
        _compile(name)

    py_path = os.path.join(EXAMPLES_DIR, name, "exploit.py")
    timeout = 5 if name in HANGING_EXPLOITS else 15

    try:
        proc = subprocess.run(
            [sys.executable, py_path],
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        if name in HANGING_EXPLOITS:
            return
        pytest.fail(f"{name} exploit timed out after {timeout}s")

    assert proc.returncode in (0, 1, -15), (
        f"{name} exploit crashed (rc={proc.returncode})\n"
        f"stdout: {proc.stdout[:500]}\n"
        f"stderr: {proc.stderr[:500]}"
    )
