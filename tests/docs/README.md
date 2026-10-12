# tests/docs

The `docs` suite: the documentation says what the code does. No Docker, no
root: `python3 tests/docs/run.py`. The tools it shares with the generator (`product_code.py`, `call_graph.py`)
are in `scripts/docs/`.

| File | What |
|---|---|
| `run.py` | The suite: runs the checks below, the function reference's `--check` and the review ledger (both in `scripts/docs/`) |
| `check_docstrings.py` | Every product function has a structured docstring (Purpose, Inputs, Returns, Fails, Feeds) |
| `check_consistency.py` | Docs and code agree: READMEs, settings, commands, agent routes, permissions, suites, setup steps, links |
| `check_entrypoints.py` | Every entry point has a positive and a negative test, or is a listed gap that only shrinks (decisions 2.1.1.38, 2.1.1.46; manual 3.1.2.5) |
| `docstring_only_diff.py` | Prove a documentation pass changed no code (syntax trees without docstrings compared) |

The structured docstring (shell functions: the same labels in the comment
block above the function):

```
Purpose: what it is for
Inputs:  each argument: type, constraints ("none" if it takes none)
Returns: the result on success
Fails:   each way it fails and what the caller sees ("never" + why)
Feeds:   which functions use the result ("—" if none)
```
