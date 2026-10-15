# tests/lint

| File | What |
|---|---|
| `run.sh` | ruff on `src/`, `scripts/` and `tests/` (rules in the root `pyproject.toml`), shellcheck on every shell script (the tests' eval-only findings excepted), and `parse_py.py` and `no_bare_prompts.py` under Python 3.10; all from images pinned by digest (decision 2.1.1.15, manual 3.1.2) |
| `no_bare_prompts.py` | Refuses `input()` and `getpass()` anywhere in `src/` outside `fabriclib/common/ask.py`, and an `ask()`/`ask_secret()` without a literal `<area>.<name>` ID (manual 1.1.5.6); read from the syntax tree, so comments and docstrings never count |
| `parse_py.py` | Parses every Python file under the given folders with the Python it runs on: the oldest supported, 3.10 (Ubuntu 22.04, 2.1.1.43), so syntax only newer Pythons accept cannot ship |
