# scripts/docs

| File | What |
|---|---|
| `gen_lib_doc.py` | Generate the function reference (manual 1.17) from the code's docstrings, with the Volume 1 index (`--check`: is it current?) |
| `lib_doc_registry.py` | The reference's numbers: given once, never reused (manual 1.17.1.2) |
| `lib_doc_numbers.tsv` | Every number the reference has ever given (written by `gen_lib_doc.py`) |
| `review_ledger.py` | The review ledger: every file reviewed, and which changed since (`--mark` after reviewing) |
| `product_code.py` | The product's code and every function's structured docstring (shared with the checks in `tests/docs/`) |
| `call_graph.py` | Static callers of every Python function ("Called by" in the reference) |
| `entrypoints.py` | The entry-point inventory (manual 3.1.2.5): writes `tests/entrypoints.yaml` (`--check`: is it current? `--gaps`: every missing case) |
