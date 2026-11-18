# Changelog -- Outis (pii_package)

## 0.1.1 -- 2026-11-17

Reason: two rules of the reference instance's ingestion-to-embed pipeline were
present in 0.1.0 only as PROCEDURE.md text, not as shipped code. Both now ship.

- `builder_guard.py` (new): the builder-side refusal. Converter output is new
  material; a builder makes one call, `guard_markdown(path_or_text, ledger,
  rulings=None)`, before building from a markdown file. Any blocking kind
  (the egress gate's partition: ORCID is recorded, everything else blocks)
  refuses the file and appends a `pii_blocked: <kinds>` row -- kinds, never
  values -- in ledger.for_each's row form; a passed file gets an `ok` row, so
  files in = passed + refused. CLI `builder_guard.py FILE... --ledger L`
  exits 1 on any refusal. An unreadable file is refused, not passed.
- `ledger.py`: the row form is factored into `row_record` and a new
  `append_row` writes one row for callers that meet records one at a time;
  `for_each` writes the identical form.
- `tests/test_ratchet_template.py` (new): the egress ratchet as an adoptable
  test. It reads the JSON report of `pii_gate.py --egress --report` and a
  committed baseline file (`reachable_blocking=<count>`), fails on a rise or a
  non-zero disagreement, passes on a fall or standstill, and SKIPS -- never
  passes -- when no report exists. README.md, "The egress ratchet", says how
  an instance adopts it. In this package it is the suite's one skip.
- README: step 3 gains the builder hook; the executed command block gains
  the guard before (exit 1) and after (exit 0) the scrub.
- Tests: 110 methods (95 in 0.1.0; +7 builder guard, +7 ratchet logic, +1
  ratchet template). Census: 12 external, 26 human, 50 spec, 20 metamorphic,
  2 structural, 0 implementation. 109 run, 1 skipped (the template, by
  design).
- Mutation check: 30 of 30 mutants killed over 109 tests (1 skipped in the
  scratch tree); the six new mutants let a refused file through, exit 0 on
  refusal, key a refused text by its content, invert the ratchet's
  direction, ignore the disagreement, and pass with no report.
- Tool versions read 0.1.1.

## 0.1.0 -- 2026-11-17

First packaged release, extracted from the PII tooling of one private corpus
instance (the "reference instance"). The reference instance keeps its own
copies unchanged; this package is a separate, self-contained copy.

license: LICENSE: private to the collaboration and to any other non-commercial entity that supplies its own PII-gate database; the author's terms of 2026-11-17, confirmed with the two clarifications (the member institutes; within-entity redistribution) the same day.

### Contents

- `pii_scan.py`, `pii_gate.py`, `pii_scrub.py`, `scrub_envelopes.py` -- the four
  tools; `text_decode.py`, `ledger.py` -- their whole import closure, determined
  by importing each tool from an empty directory (no other module is needed).
- `PROCEDURE.md` -- the collaboration procedure document, copied verbatim
  (v0 DRAFT of 2026-11-17).
- `README.md` (the eight steps, the RULINGS form, the node schema),
  `RULINGS.template`, `examples/make_example.py`.
- `tests/` -- suite, `run_tests.py` runner, `mutation_check.py`, `_support.py`.

### Changed from the reference instance

Exemptions (X2, X3):

- `pii_scan.BENIGN` now holds ONLY the RFC 2142 role mailboxes and POSIX
  system accounts. Removed from the shipped code: the reference's exact
  personal-address rulings and its government top-level-domain class ruling;
  also its organisation-office mailbox convention, its call-valued-assignment
  dictionary (including instance-specific API names), its wiki form-token
  attribute, its documentation-placeholder logins and home directories, and the
  `None`/`null` contact-field values. `FLAT_HOMEDIR_BENIGN` ships empty; one
  instance-specific generic local part was dropped from `SHELL_PROMPT_GENERIC`.
- The never-personal forms the package's own output depends on moved into a
  separate pattern, `NON_REFERRING`: the RFC 2606 / RFC 6761 reserved
  namespaces, the scrubber's placeholders (`REDACTED@example.invalid`,
  `/home/REDACTED`, `0000-0000-0000-0000`, a contact field reading
  `[address removed]`), and the SSH URL host form `git@<host>:`. These are
  not rulings: without them a scrubbed corpus can never pass its own gate.
- New: the local RULINGS file (`--rulings FILE` or `PII_RULINGS`), read by all
  four tools through one definition (`pii_scan.configure_rulings`). Classes
  `address:` (exact, never a domain), `domain:` (tail anchored by the
  reference's two lookaheads), `literal:` (exact text, 8+ characters). A
  malformed row refuses with exit 2 and names its line; absent means none; a
  configured path that does not exist refuses.

Instance state removed (X7):

- `pii_gate.CORPORA` (the instance's corpus list) and the default sentinel
  path are gone. Corpora are registered with `--corpus` or `--registry`; the
  register-or-fail inventory runs under `--inventory-root`; the sentinel is
  written only to `--status`. A gate given no corpus refuses (2).
- Every comment and docstring that named the instance, a person, a facility,
  a host, a corpus, an internal document, an audit identifier or a path was
  rewritten to describe the incident generically ("on the reference
  instance"). Incident figures are kept; their attributions are not.

Fixes judged necessary while extracting (each pinned by a test):

- `pii_scan.py` and `pii_scrub.py` refuse (2) a target that does not exist;
  the reference scanned nothing and its gate exited 0.
- `scrub_envelopes.py` filtered ledger files by WHOLE-PATH substring, the
  defect `pii_gate.is_ledger_artifact` had already fixed; it now imports that
  one definition. It also exits 1 when an envelope is unreadable (the
  reference exited 0).
- `pii_gate.py` treats an envelope whose `nodes` is not a mapping of objects
  as unreadable (a finding) instead of raising.
- The `SECRET` constant's own assignment line was itself a call-valued
  secret assignment once the dictionary exemption was removed; it is written
  `SECRET = (re.compile)(...)` so the package passes its own gate.

### Tests (X4)

The three reference suites carried (scanner, gate, scrubber) held 64 test
functions, 94 cases counting parametrisations.

- Carried: 58 functions (88 cases). 45 keep their assertion direction with
  every value re-fixtured synthetically. 13 are adapted: 4 gate tests whose
  subject was the built-in corpus list or default sentinel now drive the
  explicit flags; 9 scanner tests whose subject was an instance ruling are
  INVERTED (the shipped scanner blocks the class) and paired with a RULINGS
  test restoring it, the reference's 12 over-reach refutations included.
- Dropped: 6 functions (6 cases), all instance-only behaviour: 4 tests of the
  reference's code-chunking module and 2 tests of its boilerplate classifier,
  neither of which is part of this package.
- Package suite: 95 test methods (cases within a method run as subTests); 35
  of them are package-added (RULINGS contract, X2 removal, detectors the
  carried files did not reach, the envelope scrubber, hygiene, the README run).
- Fixtures: values that must PASS use RFC 2606 names; values that must BLOCK
  are assembled at run time from fragments under the never-delegated `zz`
  label, so no literal in the package is personal-data shaped.
- Oracle provenance is carried: `@oracle(cls, authority)` from
  `tests/_support.py`, enforced by a census test that fails on an untagged
  method. Census: 12 external, 23 human, 40 spec, 18 metamorphic,
  2 structural, 0 implementation (36.8% verification-capable). `human` marks
  a requirement ruled on the reference instance; its authority string says
  which.
- Runner: `python3 tests/run_tests.py` or `python3 -m unittest discover -s
  tests`; `python3 -m pytest tests -q` also runs it where pytest is
  installed (95 passed, measured on the build host).

### Mutation check (X5)

`tests/mutation_check.py`: 24 of 24 mutants killed over 95 tests (0 skipped
in the scratch tree), each by its named target test. The harness reports a
no-op mutant as SURVIVED, a stale pattern as NOT_APPLIED and a syntax error as
BROKEN_MUTANT (verified before the score was taken).

### Release hygiene (X6)

`python3 pkg/pii_scan.py pkg --gate` and the reference scanner over `pkg`
both exit 0. A bare-token scan for the generic home-path form plus the
reference-instance tokens met while reading its files found 0. Classes of
token scrubbed from the carried text: personal names, personal and
institutional email addresses, user handles, home and project paths, host
and domain names, IP addresses, a credential value, facility and computing-
centre names, experiment and corpus labels, internal document identifiers,
and audit and ruling identifiers.
