# Release / Post-Change Verification Routine (HARD GATE #10)

Run this full ordered battery after ANY canonical skill edit (SKILL.md, scripts/, references/,
gate.conf, fixtures) before bumping a version or declaring GREEN. Do not skip a step;
each closes a distinct integrity gap.

## 0. Working paths
- Canonical skill dir: `$HERMES_SKILL` (= this skill dir).
- Project root: `$ROOT` (= the catalog repo).
- 4 replika: canonical, `$ROOT/ben-mode`, `~/.dsh/skills/ben-mode`,
  `~/Tools/dsh-skill-wrappers/ben-mode`.
- Interpreter: one venv python (`$PY`); bash always via Git-Bash absolute path
  `C:/Program Files/Git/bin/bash.exe` (never bare `bash`).

## 1. Sync replicas
```bash
bash "$HERMES_SKILL/scripts/sync-all-roots.sh"   # expect quorum 4/4
```

## 2. Full verification (deep)
```bash
HARD_GATE_DEEP_TEST=1 HARD_GATE_FRESH=1 bash "$HERMES_SKILL/scripts/benctl.sh" --redgreen
```
Expect: gate PASS + OPA Rego PASS, fresh-machine PASS, BMC Z3 UNSAT (K=10),
WASI wasmtime PASS, manifest Ed25519 PASS, VSA + P_transparency PASS, Merkle
append+verify PASS, quorum 4/4, matrix + self-BOM OK.

## 3. Negative + unit suites
```bash
bash "$HERMES_SKILL/scripts/test-hard-gate-negative.sh"   # all N/N
"$PY" -m unittest "$HERMES_SKILL/scripts/tests/test_toolchain.py"  # OK
```

## 4. Routing + traceability
```bash
"$PY" "$HERMES_SKILL/scripts/routing-health.py"    # 171/171
"$PY" "$HERMES_SKILL/scripts/traceability.py"       # all anchors resolve
```

## 5. Oracle & matrix
```bash
# On version bump (first run): accept the new baseline
"$PY" "$HERMES_SKILL/scripts/regression-oracle.py" --root "$ROOT" --accept
# Then verify no drift on a re-run
"$PY" "$HERMES_SKILL/scripts/regression-oracle.py" --root "$ROOT"
"$PY" "$HERMES_SKILL/scripts/status-matrix.py" "$ROOT"
```
Check: `version_consistent=true`, `negative_test_count == negative_declared`,
`negative_pass_consistent=true`, sbom/opa listed present.

## 6. Dashboard regenerate + publish
```bash
# generate-dashboard.py takes POSITIONAL args: <target_dir> <out_file>.
# It has no --meta-dir flag — passing one lands in the out-file slot and the
# file open fails (or the arg is treated as the output path), so never invoke it
# with a flag-style call.
"$PY" "$HERMES_SKILL/scripts/generate-dashboard.py" "$ROOT/.hard-gate-meta" "$ROOT/.hard-gate-meta/dashboard.html"
cp "$ROOT/.hard-gate-meta/dashboard.html" "$ROOT/docs/dashboard.html"
# The dashboard display is driven by the oracle snapshot. On a version bump the
# snapshot drifts (old version shown); accept it, then regenerate the dashboard
# again so the card reflects the new version before commit.
"$PY" "$HERMES_SKILL/scripts/regression-oracle.py" --accept --root "$ROOT"
"$PY" "$HERMES_SKILL/scripts/generate-dashboard.py" "$ROOT/.hard-gate-meta" "$ROOT/.hard-gate-meta/dashboard.html"
cp "$ROOT/.hard-gate-meta/dashboard.html" "$ROOT/docs/dashboard.html"
```

## 7. Version bump (only after GREEN)
Touch in one atomic pass so reports stay consistent, then re-run step 2 quick mode:
1. `SKILL.md` frontmatter `version:` + suite-count mentions.
2. `CHANGELOG.md`: insert new `## vX.Y.Z` block ABOVE the first existing `## v`
   heading (anchoring on the first heading, not the first newline).
3. `.hard-gate-meta/adr.md`: new ADR entry.
4. `TOTAL_TESTS` in the negative suite if the test count changed.
Then `benctl.sh --quick` to confirm quick-PASS still holds post-bump.

## Pitfalls specific to this routine
- **Order matters**: sync → refresh baseline → verify in ONE landasan. Baseline
  recorded before further edits goes stale; a clean tree then fails verify.
- **Deep is opt-in**: default `benctl.sh` is quick (incremental tree-sig). For a
  release you must explicitly set `HARD_GATE_DEEP_TEST=1 HARD_GATE_FRESH=1`.
- **Oracle `--accept` only after final edits**: accepting before the last edit ships
  the pre-edit baseline and the verify step flags drift.
- **Model predicate self-reference**: if `model-hashes.json` points at a generated
  artifact (e.g. `docs/dashboard.html`), regenerate its hash whenever the artifact
  is rewritten, or `P_model_signed` fails with no change to the manifest.
- **Copy dashboard to docs last**: `generate-dashboard.py` writes only meta;
  `docs/dashboard.html` is the published copy — copy it after the final regen.
