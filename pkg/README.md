# Outis 0.1.0 (pii_package) -- a procedural personal-data filter for private corpus instances

A deterministic, fail-closed filter for a corpus that is converted, summarised,
embedded and served to a retrieval layer. Python 3 standard library only; no
network; no model. The procedure it implements is in `PROCEDURE.md`; the
changes from the instance it was extracted from are in `CHANGELOG.md`.

Contents: `pii_scan.py` (ingress scanner and the single definition of what
counts), `pii_gate.py` (egress sieve over embedded nodes), `pii_scrub.py`
(source scrubber), `scrub_envelopes.py` (envelope scrubber that nulls
vectors), `text_decode.py` and `ledger.py` (their imports), `RULINGS.template`,
`examples/make_example.py`, `tests/` (suite, runner, mutation check).

License: see LICENSE: private to the collaboration and to any other non-commercial entity that supplies its own PII-gate database.

## The eight steps

All commands run from the package root. The block below is executed verbatim
by `tests/test_package.py`, each line checked against the exit status in its
comment, so it cannot drift from the tools. `W` is a scratch directory.

<!-- example-commands:begin -->
```sh
W=$(mktemp -d)
python3 tests/run_tests.py                                              # exit 0
python3 examples/make_example.py "$W"                                   # exit 0
python3 pii_scan.py "$W/markdown" --gate                                # exit 1
python3 pii_scan.py "$W/markdown" --gate --rulings "$W/RULINGS"         # exit 1
python3 pii_scrub.py "$W/markdown" --quarantine "$W/quarantine" --label example --rulings "$W/RULINGS"          # exit 0
python3 pii_scrub.py "$W/markdown" --quarantine "$W/quarantine" --label example --rulings "$W/RULINGS" --apply  # exit 0
python3 pii_scan.py "$W/markdown" --gate --rulings "$W/RULINGS"         # exit 0
python3 pii_gate.py --egress --gate --registry "$W/corpora.registry" --inventory-root "$W/structure" --rulings "$W/RULINGS" --status "$W/gate_status"  # exit 1
python3 scrub_envelopes.py --structure "$W/structure/*.json" --quarantine "$W/quarantine" --label example --keep-orcid --rulings "$W/RULINGS" --apply  # exit 0
python3 pii_gate.py --egress --gate --registry "$W/corpora.registry" --inventory-root "$W/structure" --rulings "$W/RULINGS" --status "$W/gate_status"  # exit 0
grep -qx 'status=GREEN' "$W/gate_status"                                # exit 0
```
<!-- example-commands:end -->

1. **Install.** Unpack the archive; nothing else. `pdftotext` (poppler) is
   used only for PDFs; without it a PDF is reported `unscannable`, never passed.
2. **Prove.** `python3 tests/run_tests.py` runs the suite (also
   `python3 -m unittest discover -s tests`, or `python3 -m pytest tests -q`
   where pytest is installed). `python3 tests/mutation_check.py` reintroduces
   recorded defects and confirms the suite kills each one. Check both before the
   first real scan: a suite that only ever passes has not been tested.
3. **Run the ingress scan FIRST.** `pii_scan.py <path> --gate` over every new
   tree, before conversion or inspection. Exit 1 means stop. Converter output
   (OCR, PDF rendering) is new material and is scanned again.
4. **Rule.** A human sorts findings into SCRUB, EXEMPT or HOLD. An exemption is
   one line in the instance's own RULINGS file (below); `--rulings FILE` or the
   `PII_RULINGS` environment variable makes every tool read it. The shipped
   scanner exempts only the RFC 2142 role mailboxes and the never-personal
   reserved forms (RFC 2606/6761 names, its own placeholders, SSH URL hosts).
5. **Scrub.** `pii_scrub.py <root> --quarantine <dir>` is a dry run;
   `--apply` writes, copying each original to the quarantine with a
   `.removed.json` record (kinds and lengths, never values) and one ledger row
   per file.
6. **Re-embed.** `scrub_envelopes.py --apply` nulls `embedding` and
   `sparse_embedding` on every node whose text changed and writes
   `<quarantine>/<label>_reembed.txt`. Those nodes are unretrievable until the
   instance's own embedder re-embeds the listed files. Re-embedding is
   mandatory, not scheduled.
7. **Gate the egress.** `pii_gate.py --egress --gate` scans the `summary` and
   `title` of every node that carries a vector. The INGRESS/EGRESS
   DISAGREEMENT line counts findings whose markdown source is already clean --
   a broken propagation path; it must stay at zero. Reachable blocking
   findings may only fall between releases.
8. **Record.** Every real finding becomes a test case with a synthetic value
   and a ledger line (kind, file, line, ruling, date). Reports never carry the
   value; `--report` writes kind, file and line only.

**Never read a gate's status through a pipe.** `pii_gate.py --gate | tail;
echo $?` prints the failure and reports 0, because `$?` is the last command's.
Use `if python3 pii_scan.py X --gate; then ...`, or `--status FILE` and
`grep -qx 'status=GREEN' FILE`.

Exit statuses: 0 success; 1 findings (with `--gate`) or ran with degradation;
2 could not run (bad arguments, missing target, malformed RULINGS or registry).

## The RULINGS file

One ruling per line, five `|`-separated fields (`RULINGS.template`):

    <class>:<value> | EXEMPT or BLOCK | <reason> | <ruler role> | <YYYY-MM-DD>

- `address:office@site.example` -- that exact address, case-insensitively;
  never its domain, never a longer local part, never a spoofed tail.
- `domain:agency.example` -- every address whose domain is, or ends in
  `.agency.example`. The tail is anchored: `x@agency.example.attacker.test`
  is not covered.
- `literal:<text of 8 or more characters>` -- a finding whose start lies inside
  an occurrence of exactly this text.

A malformed row refuses (exit 2) and names its line. `BLOCK` rows exempt
nothing; they record a decision. The file is never required: absent means no
local exemptions. A path given but missing refuses. The RULINGS file is
instance data: it is never committed with the package.

## The node schema (the egress interface)

`pii_gate.py` and `scrub_envelopes.py` read envelopes, one JSON file per
document, and nothing else of the instance:

    {"nodes": {"<node id>": {"title": "...", "summary": "...",
                             "embedding": [..] or null,
                             "sparse_embedding": {..} or null, ...}, ...}, ...}

- `summary` and `title` are the reader-visible text the gate scans.
- A node is **reachable** when `embedding` or `sparse_embedding` is non-empty;
  an unreachable node is not in the index and is not scanned.
- An envelope that does not parse is a blocking finding.
- Files whose basename contains `ledger` are bookkeeping, not envelopes.
- For the disagreement count, the source of `<name>.json` is
  `<markdown_root>/<name>/paper.md`.
- Corpora are registered with `--corpus label:glob[:markdown_root]` or a
  registry file (`label | glob | markdown_root or -`, paths relative to the
  file). `--inventory-root DIR` makes every `*.json` under DIR that no glob
  covers a blocking `unregistered_envelope`.
- `scrub_envelopes.py` sets `pii_scrubbed: true` on each node it changes.
