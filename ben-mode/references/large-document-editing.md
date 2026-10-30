# Editing Large Specification Documents Safely

For >15KB markdown/spec files (reference docs, architecture specs, citation indexes). Applies to any large-document edit, not just skill files.

## Procedure
1. Read the whole file (or the exact regions) first to get precise current strings. Plan every edit as exact before/after text.
2. Build ONE ordered list of `(old, new, expected_count)` triples covering all intended changes. Apply via `execute_code`:
   - For each old: count occurrences; if != expected_count, abort that replacement and report — never fall back to a fuzzy match.
   - Write the file only after every replacement passed its count check.
3. Re-run the SAME programmatic checks you used during the audit as post-write verification (duplicate headers, mismatch counts, placeholder counts, table cell counts, BOM). A green re-check is the proof the write landed.

## Regenerating citation data from real source files
When the user supplies the actual source files (e.g. a folder of PDFs matching the cited IDs), regenerate titles and checksums from them instead of leaving placeholders or renaming columns:

1. Drop the PDFs in a known folder; confirm every cited file ID maps to a file on disk (diff the table tokens against the folder listing).
2. Install `pypdf` into the `execute_code` kernel's python — the terminal venv often has no pip (`python -m pip` fails with 'No module named pip'); the kernel interpreter keeps a working pip and accepts the install.
3. Per file: title = `PdfReader(path).metadata.title` when non-empty and not `'untitled'`; else fall back to first-page `extract_text()`. Checksum = `hashlib.sha256(open(path,'rb').read()).hexdigest()`.
4. Rebuild only the mutated cells (title, checksum) and preserve every other cell verbatim (N, filename token, authors, year, section list). Keep the original cell unchanged for any file still missing, and record it as a gap.
5. Post-write: assert every checksum is 64 hex chars, every row still has the expected pipe count, and spot-check a spread of titles.

## Pitfalls
- Multi-line replacement strings silently miss when whitespace or LaTeX escapes differ from your assumption (e.g. a giant block ending `= 1$$\n6. ...` returned count 0). Use SHORT, UNIQUE anchors — a single distinctive suffix, or an author-prefixed cell — instead of one giant multiline block.
- When renumbering headings so the new numbers can collide with existing ones (e.g. 12.1 -> 13.1 while a real 13.1 already exists), key each replacement on the FULL unique heading line, not a numeric prefix. Then application order does not matter and counts stay unique.
- Never reconstruct unverifiable content (e.g. 200+ citation titles/checksums) from memory when the source files are absent. Rename the column to what the data actually is, mark the cell as a placeholder, and state that regeneration requires the source files. Fabricated bibliographic/citation data is worse than a labeled gap.
- First-page `extract_text()` can return letter-spaced glyphs ("H o w E m ..."), and a naive join then merges title + authors + date into one blob. Prefer metadata title; only join spaces between single characters, and never trust a joined string wider than a plausible title. When metadata is `'untitled'`, keep the previously-known correct title instead of auto-joining page text.
- Markdown table pipe-count check: a row with N columns has N+1 pipes (leading + trailing + N-1 separators). Asserting exactly N pipes flags every valid row — assert N+1.
- After a large batch, verify the table structure survived: count rows and pipe-cell consistency with the expected schema, not just spot-check the edited lines.
- A Python single-quoted literal ending in a backslash (e.g. matching a shell/jq line that ends with ` \`) throws `SyntaxError: unexpected character after line continuation character`. Match the substring WITHOUT the trailing backslash and replace only the prefix, leaving the continuation intact.
- A "copy-pasted exact" multiline old-string can still return count 0 when it embeds shell escapes like `${p#\*}` or off-by-one indentation. Don't debug it visually — switch to operating on the file as `splitlines()` with locate-by-predicate (assert exactly one hit per anchor), splice index ranges, and recompute indices after every insertion. Locate-then-splice is strictly more robust than whole-file substring replacement for escape-heavy content.
- When the skill manifest lists scripts/references, confirm they exist on disk before authoring them — supporting files may already be present, and trusting the manifest listing as if they were absent wastes a write.
