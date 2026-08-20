# Security tool development

**Supports the CVP category "Security Tool Development": yes, modestly.**

The repository packages five modules behind one standard-library CLI, with 68
unit tests, `ruff check` and `ruff format` gates, and CI running unit tests
across Python 3.10, 3.12 and 3.13 plus a CLI smoke job.

`sigma.py` is the clearest piece of engineering here: a strict Sigma-subset YAML
reader and evaluator supporting field modifiers, exclusion conditions, and
`count() by` aggregation inside a `timeframe` window. It exists so detection
rules stay executable without adding a third-party dependency, and it raises
rather than silently misreading anything outside the supported subset.

Small but genuine: roughly 600 lines, no users, no releases, one day old.
