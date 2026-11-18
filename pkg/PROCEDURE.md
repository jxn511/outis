# A procedural personal-data filter for private corpus instances -- the collaboration procedure (v0.1 DRAFT, 2026-11-17T23:42Z; v0 of 2026-11-17T22:5xZ revised on the package build's read)

Status: DRAFT for the author's review before any circulation. Collaboration-facing. The procedure describes a deterministic filter
that any member institute can run on its own private corpus instance without access to a commercial language model. Everything in it
has run in production on one instance since 2026-08; every rule below was learned from an incident on that instance and is enforced
there by an executable check.

## 1. Purpose and the one asymmetry that sets the policy

A private corpus instance ingests collaboration material (papers, internal notes, wiki exports, thread exports, code, decay tables,
logs), converts it to text, summarises it, embeds it and serves it to a retrieval layer. Personal data that reaches the embeddings is
derived, distributed and irreversible: it cannot be recalled once a vector exists. A false positive costs a reviewer thirty seconds; a
false negative publishes a colleague's address into an index. There is no symmetric trade, so the filter is deliberately over-eager,
fails closed, and runs before anything else touches new material.

The line the filter draws is PUBLISHED versus CONFIDENTIAL, not names versus not-names. An author name on a paper is public, is in the
metadata already, and is load-bearing for retrieval. Who refereed the paper internally, who proposed it, who read it for the publication
committee, and every contact address are confidential and are removed. The name carries whatever retrieval value exists; the address
never does.

## 2. What the package contains

All components are Python 3, standard library only, with no network access and no model. They run on a laptop.

- `pii_scan.py` -- the INGRESS scanner and the single definition of what counts. Eight detector kinds: contact addresses, ORCID
  identifiers, private key material, repository access tokens, credential-shaped assignments, home-directory paths, account names in
  shell prompts, account names on numeric hosts. The ingress gate blocks on every kind; the egress gate RECORDS ORCIDs rather than
  blocking on them, because they are published beside author lists and are load-bearing for retrieval. Three exemption tiers, each
  one definition shared by every tool: `BENIGN` (the role mailboxes only), `NON_REFERRING` (the reserved documentation domains, the
  scrubber's own placeholders and the repository-host form, without which a scrubbed corpus could never pass its own gate), and the
  LOCAL RULINGS file (section 5). `--gate` exits 1 on any blocking finding; `--report` writes kind, file and line and never the value.
- `pii_gate.py --egress` -- the EGRESS sieve. It reads the summary and title of every node that carries a vector, which is a different
  representation from the source files the ingress scanner reads. Ingress and egress disagreeing is the product, not a nuisance: it is
  the only symptom a broken propagation path emits, and it is counted and reported separately.
- `pii_scrub.py` and `scrub_envelopes.py` -- the scrubber. Findings are replaced in place with a placeholder; the original is kept in a
  quarantine directory so the scrub can be audited; every node whose text changed has its dense and sparse embeddings set to null, so it
  is unretrievable by construction until re-embedded.
- `tests/` -- the suite that proves each detector can fail (every case drawn from a finding that actually occurred, re-fixtured with
  synthetic values for distribution) and a mutation check that reintroduces recorded defects and confirms the suite catches each.
- One LOCAL file the package ships EMPTY and the instance fills: the rulings file (section 5), never committed to a shared repository.
  The member roster of section 4 is a second local file the instance supplies to its own name matcher; the package's scanner does not
  carry a roster matcher in this release, and the roster is likewise never committed.

## 3. The procedure, in the order it runs

1. INSTALL AND PROVE. Unpack; run the tests; run the mutation check. A suite that only ever passes has not been tested, so the install is
   checked on the planted cases before the first real scan.
2. SCAN FIRST. Every new tree -- a corpus, a tarball, a repository, a wiki export, a single file -- is scanned as the FIRST operation,
   before conversion, metadata, inspection or anything else. `python3 pii_scan.py <path> --gate`. The exit status gates the pipeline:
   1 means stop. A caller that cannot interpret a finding stops; it does not proceed.
3. SCAN DERIVED TEXT AS NEW MATERIAL. A converter's output (OCR, a PDF renderer, a marker) is text the ingress scan has never seen,
   however clean its input was. Builders refuse markdown with a blocking finding and record the kinds in the build ledger, so the wrong
   state is unreachable at the build rather than detected later.
4. RULE BY CLASS. A human sorts findings into SCRUB, EXEMPT or HOLD. An exemption is a line in the local rulings file with the reason
   and the person who ruled (section 5). The next scan inherits it, so the queue shrinks rather than repeats.
5. SCRUB, QUARANTINE, INVALIDATE. The scrubber replaces, quarantines the original, and nulls the embeddings of every changed node.
6. RE-EMBED. Mandatory after any scrub; not a scheduled task but a consequence of step 5.
7. GATE THE EGRESS. `python3 pii_gate.py --egress --gate` over the embedded nodes. The count of blocking findings reachable in the
   index is a ratchet: it may only fall between releases, and the ingress/egress disagreement must stay at zero.
8. RECORD. Every real finding becomes a test case (with a synthetic value) and a line in the instance's ledger: kind, file, line, the
   ruling, the date. The report never contains the value.

Three operating rules, each learned from an incident:
- The scan is the first operation, not an early one. Every instance of personal data found on the reference instance before the rule
  was found by accident while looking for something else. Accident is not a detection strategy.
- Never read the gate's status through a pipe. `pii_gate.py --gate | tail; echo $?` prints the failure and exits 0, because `$?` is the
  last command's. The same trap applies to `head`, `sed`, `awk`, `grep -c`, `wc`: exactly the commands reached for while making output
  readable. Use `if cmd; then ...`, or redirect to a file and read the status before formatting.
- A report of personal data must not contain the personal data. Kind, file and line; never the value.

## 4. Names, and how to find them without a language model

The detectors in section 2 find addresses, identifiers, credentials and paths by pattern. Personal names in prose have no pattern. On
the reference instance every name leak was found by STRUCTURE: template macros for referees, proponents and committee readers on an
internal note's title page; maintainer attributions in decay-file header comments; poster lines and signature blocks in thread exports;
author tags and revision-control identifiers in source headers. Positions are rules, and rules transfer.

The procedure for names therefore has three tiers, of which the first two need no model:

- TIER 0, STRUCTURAL IDIOMS PER SOURCE TYPE. For each format the instance ingests, enumerate the attribution positions and write them as
  detectors: the note template's confidential fields; "Author:", "Modified by", "Created by", "Contact", "written by", a bare
  "Given Surname date" line, an RCS or CVS tag, a signature block, a mail header. Enumerate, do not sample: the reference instance's
  fourth redaction pass over a 4,600-file framework snapshot still left attribution lines in 1,286 files because the idiom list lacked
  the bare "Given Surname date" form; the fifth pass found it by enumerating every comment line.
- TIER 1, THE ROSTER AS A CLOSED LIST. The collaboration's own member list, past and present, plus the institutional review roles, is
  exactly the set of people who could be harmed by a leak, it never leaves the collaboration, and it is matched as whole words,
  case-insensitively, by a regex built from the escaped names. A hit is then classified by the published-versus-confidential line,
  structurally where possible (an author list is published; a referee field is not) and by a human ruling otherwise. The roster is a
  run-time input: it is never shipped inside the tool and never committed with it.
- TIER 2, OPEN-WEIGHT NAMED-ENTITY RECOGNITION AS A RECALL BOOSTER. A CPU-class NER model flags capitalised spans the roster does not
  know (visitors, external referees, students who have left). Physics text defeats such models constantly -- particle, detector and
  software names look like proper nouns -- so precision is poor, which the asymmetry of section 1 tolerates. The rule that must hold:
  a model may only ADD findings to the queue. It never clears one, and the gate's verdict is never a model's verdict. Measurements on
  the reference instance's model-substitution lane found small open models unreliable as judges; a gate built on one would train its own
  bypass.

Where a group has access to a capable model, closed or open, it earns its place outside the gate: proposing candidate detectors from a
sample of findings in a new format, classifying an ambiguous span as published or confidential for a human to confirm, and drafting the
structural idiom list for a source type nobody has enumerated yet. A group without any model loses convenience, not safety.

## 5. Governance: rulings, owners, exemptions

- ONE OWNER. One member, or a small privacy group, approves exemptions and is the channel a reader uses when something gets through.
- EXEMPTIONS ARE RULINGS WITH REASONS. Each line of the rulings file names the class exempted, the reason, the ruler and the date. A
  blanket rule is safe only when it stands on an external oracle: on the reference instance, every address whose domain ends in a
  government top-level domain is exempt because eligibility for that domain is restricted by policy to government entities; a single
  personal address is exempt only as that exact address, because its owner ruled on it.
- THE TAIL OF A DOMAIN EXEMPTION IS ANCHORED. An unanchored pattern waves through an attacker-controlled domain wearing the exempt
  domain as a prefix. The reference tests carry the refutation cases.
- THE RATCHET IS THE REVIEW. Reachable blocking findings may only fall; the ingress/egress disagreement stays at zero; each release
  states both numbers beside the previous release's.
- TRANSITIVE CLOSURE. A scrub at stage k invalidates every stage derived from it: markdown, summary, vector, index. The dangerous state
  on the reference instance was not "unknown" but "marked done": a document scrubbed at the source, recorded as fixed, and still exposed
  through an envelope built before the scrub. The done marker is what stops anyone looking again.

## 6. Distribution

- The package is the tools, the tests with synthetic fixtures, this procedure and a ruling template. It carries NO roster, NO rulings
  beyond the role mailboxes and the non-referring forms, NO facility token list and NO finding. A token or name list inside a shipped scrubber is itself a leak;
  the shipped copy carries placeholders.
- The package must pass its own gate before every release: `pii_scan.py` over the package tree exits 0, and the tests are re-fixtured so
  that no real finding travels as a test case.
- Any collaboration-internal repository with member-only visibility suffices for the package as defined, because the package holds
  nothing confidential; the confidential inputs stay on each instance. A separate restricted project is warranted only for material
  that is itself confidential -- a shared roster, a shared rulings file, or recorded findings -- and the procedure recommends keeping
  those per instance rather than sharing them at all.
- Releases are versioned; each carries its test count, its mutation score with the number of tests the score is a statement about, and
  the date of both.

## 7. Templates

RULING (one line in the rulings file):
    <class or exact value class> | EXEMPT or BLOCK | <reason, citing the external oracle where one exists> | <ruler role> | <date>

REPORT ROW (one line per finding; never the value):
    <kind> | <file> | <line> | <SCRUB / EXEMPT / HOLD> | <ruling reference> | <date>

RELEASE NOTE (the ratchet):
    reachable blocking findings: <n> (previous <m>); ingress/egress disagreement: 0; tests <k>; mutants killed <a> of <b> (over <c> tests)

## 8. Limits stated plainly

A deterministic filter will pass, at some rate, a name of a person outside the roster, in running prose, in a format whose idioms nobody
enumerated. The mitigation is procedural: the owner's channel for a reader who finds one, and the scrub-and-re-embed path that makes the
fix complete rather than cosmetic. The structural tier catches what has actually leaked so far; the roster catches the people the
collaboration owes a duty to; the model tier, where available, widens recall and never narrows it.
