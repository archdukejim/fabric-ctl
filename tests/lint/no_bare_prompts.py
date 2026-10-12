"""Every question fabric asks goes through fabriclib/common/ask.py with a stable ID (manual 1.1.5.6): refuse input()
and getpass() anywhere else in the product, and an ask()/ask_secret() whose ID does not start with a literal
"<area>." (the entry-point inventory reads it, 3.1.2.5). Read from the syntax tree, so comments, docstrings and
strings that mention input() never count.
    python3 tests/lint/no_bare_prompts.py <dir> ...
"""
import ast
import pathlib
import re
import sys

ALLOWED = pathlib.PurePosixPath("fabriclib/common/ask.py")
AREA_RE = re.compile(r"^[a-z][a-z0-9_]*\.")


def _python_files(root):
    """Purpose: the product's Python files under one folder: *.py, and extension-less files with a python shebang.
    Inputs:  root — a folder path (str).
    Returns: sorted list of pathlib.Path.
    Fails:   never (an unreadable file is skipped).
    Feeds:   main."""
    out = []
    for path in pathlib.Path(root).rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".py":
            out.append(path)
        elif not path.suffix:
            try:
                with open(path, "rb") as f:
                    first = f.readline(80)
            except OSError:
                continue
            if first.startswith(b"#!") and b"python" in first:
                out.append(path)
    return sorted(out)


def _id_is_literal(node):
    """Purpose: whether an ask()/ask_secret() ID starts with a literal "<area>." (a str, or an f-string whose first
             part is one: f"menu.vars.{key}").
    Inputs:  node — the call's first argument (ast node), or None when there is none.
    Returns: bool.
    Fails:   never.
    Feeds:   findings."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(AREA_RE.match(node.value))
    if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
        return bool(AREA_RE.match(str(node.values[0].value)))
    return False


def findings(path, text):
    """Purpose: the bare prompts and unnamed questions in one file.
    Inputs:  path — shown in each finding; text — the file's source.
    Returns: list of str, "<path>:<line>: <what>".
    Fails:   never (a file that does not parse is a finding).
    Feeds:   main; tests (the check's own cases)."""
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError as e:
        return [f"{path}:{e.lineno}: does not parse: {e.msg}"]
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "getpass" and any(
                a.name == "getpass" for a in node.names):
            out.append(f"{path}:{node.lineno}: imports getpass.getpass: use fabriclib.common.ask.ask_secret")
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
        if name == "input" and (isinstance(f, ast.Name) or (isinstance(f.value, ast.Name)
                                                             and f.value.id == "builtins")):
            out.append(f"{path}:{node.lineno}: input(): use fabriclib.common.ask.ask with a stable ID")
        elif name == "getpass":
            out.append(f"{path}:{node.lineno}: getpass(): use fabriclib.common.ask.ask_secret with a stable ID")
        elif name in ("ask", "ask_secret") and isinstance(f, ast.Name) and not _id_is_literal(
                node.args[0] if node.args else None):
            out.append(f"{path}:{node.lineno}: {name}() needs a literal \"<area>.<name>\" ID as its first argument")
    return out


def main(roots):
    """Purpose: check every Python file under the given folders; ask.py itself is the one place allowed to prompt.
    Inputs:  roots — folder paths (str).
    Returns: exit status: 0 when nothing is found, 1 otherwise (each finding printed).
    Fails:   never.
    Feeds:   tests/lint/run.sh."""
    bad, files = [], 0
    for root in roots:
        for path in _python_files(root):
            if pathlib.PurePosixPath(path.as_posix()).match(f"*/{ALLOWED}"):
                continue
            files += 1
            bad += findings(path, path.read_text(encoding="utf-8"))
    for line in bad:
        print(line)
    print(f"{files} file(s): {len(bad)} bare prompt(s) or unnamed question(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
