# Regenerating PDF-Based Citation Indexes & Corpus-Grounded Synthesis

Use when a spec/reference document contains a table of cited PDFs (e.g. arXiv IDs) whose titles/checksums are truncated or unverified, and the real files are available locally.

## Citation index (titles + hashes)
1. Confirm the source folder covers all row tokens (map filename tokens in the table to files on disk; report missing ones, never fabricate).
2. Install `pypdf` in the execute_code kernel (`sys.executable -m pip install pypdf`); a terminal venv is often pip-less. Kernel state resets between calls, so install inside the same call that uses it.
3. For each row: compute `hashlib.sha256(open(path,'rb').read()).hexdigest()` (64 lowercase hex).
4. Title: prefer `PdfReader(path).metadata.title` — reject `'untitled'` and titles shorter than 4 chars. Fallback: `pages[0].extract_text()` collapsed to single spaces, capped ~240 chars.
5. Sanitize each title: replace `|`, backtick, backslash; collapse whitespace; cap 240.
6. Rewrite the table block (header + rows) preserving every other column (authors/year/sections) — replace only title and checksum cells.

## Pitfalls
- If sources are absent: do NOT invent titles/hashes — rename the column to what the data actually is (e.g. `Checksum (64-bit ref)`) and mark the gap for later regeneration. Fabricated bibliographic data is worse than a labeled gap.
- Spaced-letter extraction: some PDFs extract text as single-character tokens (`H o w ...`). Joining all tokens over-merges (title+author run together). Prefer a known-good title, or join only the leading consecutive single-char tokens that form the title.
- Verify after writing: row pipe counts (7 columns = 8 pipes incl. leading/trailing), every checksum exactly 64 hex, no duplicate headings, and year-in-row matches the arXiv ID year.

## Grounding synthesis from a corpus record file
- A structured corpus (e.g. `merged_records.json`) already holds the reading: per-record fields like `core_thesis`, `concrete_evidence`, `hardgate_applicability`, `verification_status`.
- Build section/mechanism content from those fields — quote only VERIFIED records as support; list UNVERIFIED separately and never cite them as settled. Never claim a mechanism is implemented at runtime when only the spec/policy text changed: mark `Status` honestly (e.g. "Specified — runtime pending").
- Group records into thematic slots by keyword overlap with the slot's intent and cite representative arXiv IDs + a thesis snippet per slot.
