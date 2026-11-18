#!/usr/bin/env python3
"""mutation_check.py -- prove the suite can fail.

A test that has only ever passed has not been tested. So: copy the package to a
scratch tree, reintroduce one defect at a time -- each a defect that actually
occurred on the reference instance, or the exact inverse of a property the
procedure requires -- run the suite, and check that it FAILS. A mutation that
survives means the tests it was aimed at are decorative.

Run:   python3 tests/mutation_check.py          (from anywhere)
Exit:  0 every mutant killed; 1 any survived, was not applied, or broke the
       harness; 2 the harness could not run.

HOW A MUTANT IS JUDGED. The mutated file must still compile (a syntax error
makes every test "fail" and would flatter the suite: BROKEN_MUTANT). The
pattern must match exactly once (a stale pattern is NOT_APPLIED, never a
pass). The FULL suite then runs in the scratch tree; the mutant is KILLED when
it exits non-zero AND the named target test is among the failures. A suite
that fails only elsewhere is reported as KILLED_ELSEWHERE -- still a kill,
but evidence that the named test is not the one guarding the defect.

THE SCORE IS ONLY A STATEMENT ABOUT THE TESTS THAT RAN. The scratch tree holds
the package and nothing else, so a test that skips there (the PDF test without
pdftotext/pdflatex) cannot kill anything. The summary prints the score as
"k of n over t tests" with t the number that RAN, and the skip count beside
it. Read the score with the run state, never alone: a tree that cannot even
import scores every mutant as surviving.
"""

import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable

# (name, file, pattern, replacement, target test, defect it recreates)
MUTANTS = [
    ("drop-email-detector", "pii_scan.py",
     r'    \("email", EMAIL, "contact address"\),\n', '',
     "test_email_addresses_are_found_anywhere",
     "a dropped detector: contact addresses pass the gate"),

    ("drop-host-account-detector", "pii_scan.py",
     r'    \("host_account", HOST_ACCOUNT, "account name on a numeric host"\),\n', '',
     "test_an_account_on_a_numeric_host_is_found_and_versions_are_not",
     "a dropped detector: accounts on numeric hosts reachable in the index"),

    ("widened-role-exemption", "pii_scan.py",
     r'\|mailer-daemon\|noreply\|no-reply\|donotreply\|usenet\|news\|uucp\|ftp\)@"\)',
     '|mailer-daemon|noreply|no-reply|donotreply|usenet|news|uucp|ftp|[A-Za-z0-9._%+-]+)@")',
     "test_the_shipped_exemption_list_is_role_mailboxes_only",
     "a widened exemption: every local part excused as a role mailbox"),

    ("reinstated-government-class", "pii_scan.py",
     r'    r"\|\(\?i:contact\|email\|e-mail\)\\s\*\[:=\]\?\\s\*\\\[address removed\\\]"\)',
     r'    r"|(?i:contact|email|e-mail)\s*[:=]?\s*\[address removed\]"'
     r'    r"|(?i:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*\.gov)(?![A-Za-z0-9-])(?!\.[A-Za-z])")',
     "test_a_government_shaped_address_blocks_in_the_shipped_scanner",
     "an instance ruling shipped in the code: the government-TLD class"),

    ("unanchored-domain-tail", "pii_scan.py",
     r'\+ re\.escape\(r\.value\) \+ r"\)" \+ _TAIL\)\n        elif r\.cls == "literal"',
     '+ re.escape(r.value) + r")")\n        elif r.cls == "literal"',
     "test_a_domain_ruling_is_anchored_at_the_tail",
     "domain exemption unanchored: an address under a spoofed .gov.<attacker> tail waved through"),

    ("exact-address-as-domain", "pii_scan.py",
     r'alts\.append\(r"\(\?<!\[A-Za-z0-9\._%\+-\]\)\(\?i:" \+ re\.escape\(r\.value\) \+ r"\)" \+ _TAIL\)',
     r'alts.append(r"(?i:[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*" + re.escape(r.value.split("@")[1]) + r")" + _TAIL)',
     "test_an_exact_address_ruling_does_not_over_reach",
     "an exact-address ruling matched as its domain: every sibling mailbox excused"),

    ("malformed-ruling-skipped", "pii_scan.py",
     r'        if len\(fields\) != 5:\n            raise RulingsError\(n, "expected 5',
     '        if len(fields) != 5:\n            continue\n            raise RulingsError(n, "expected 5',
     "test_every_malformed_row_refuses_with_its_line_number",
     "a malformed RULINGS row silently skipped: a half-loaded exemption list"),

    ("scan-gate-exits-zero", "pii_scan.py",
     r'% \(total, len\(found\)\)\)\n        return 1',
     '% (total, len(found)))\n        return 0',
     "test_gate_exits_nonzero_on_any_finding",
     "the ingress gate exits 0 on a finding"),

    ("egress-gate-exits-zero", "pii_gate.py",
     r'% ", "\.join\(sorted\(RECORDED\)\), file=sys\.stderr\)\n        return 1',
     '% ", ".join(sorted(RECORDED)), file=sys.stderr)\n        return 0',
     "test_gate_fails_red_on_an_unregistered_tree",
     "the egress gate exits 0 on a blocking finding"),

    ("report-carries-the-value", "pii_scan.py",
     r'json\.dump\(\{rel: \[\{"kind": k, "line": l, "why": w\} for k, l, _s, w in v\]',
     'json.dump({rel: [{"kind": k, "line": l, "why": w, "value": _s} for k, l, _s, w in v]',
     "test_the_report_does_not_reproduce_the_values",
     "the report reproduces the personal data it reports"),

    ("scrub-record-carries-the-path", "pii_scrub.py",
     r'removed\.append\(\("home_path", "<%d chars>" % len\(val\)\)\)',
     'removed.append(("home_path", val))',
     "test_pii_scrub_home_path_detail_never_carries_the_username",
     "the scrub's own removal record stores the username it removed"),

    ("scrubber-keeps-the-embedding", "scrub_envelopes.py",
     r'            node\["embedding"\] = None\n', '',
     "test_a_scrubbed_node_loses_both_vectors_and_others_keep_theirs",
     "a scrubbed node keeps its dense vector: the address stays retrievable"),

    ("scrubber-keeps-the-sparse-embedding", "scrub_envelopes.py",
     r'            node\["sparse_embedding"\] = None\n', '',
     "test_a_scrubbed_node_loses_both_vectors_and_others_keep_theirs",
     "half-fix: the sparse index still matches on the removed token"),

    ("egress-reads-the-source-not-the-summary", "pii_gate.py",
     r'parts = \[node\.get\(f\) for f in TEXT_FIELDS\]',
     'parts = [node.get(f) for f in ("source", "text")]',
     "test_source_clean_but_index_dirty_is_counted_as_disagreement",
     "the egress sieve reads a source field instead of the summary"),

    ("egress-scans-unembedded-nodes", "pii_gate.py",
     r'            if not any\(node\.get\(v\) for v in VECTOR_FIELDS\):\n                continue\n',
     '',
     "test_only_nodes_with_a_vector_are_scanned",
     "unreachable nodes reported as exposure, diluting the real findings"),

    ("ledger-filter-reads-whole-path", "pii_gate.py",
     r'return "ledger" in os\.path\.basename\(path\)',
     'return "ledger" in path',
     "test_a_parked_corpus_directory_does_not_hide_a_strand",
     "a corpus parked under a 'ledgers' directory leaves the sieve, gate GREEN"),

    ("no-error-stamp-before-scan", "pii_gate.py",
     r'        # run\'s GREEN claiming a verdict this run never reached\. Fail closed\.\n'
     r'        write_status\(status_path, "ERROR", None\)\n',
     "        # run's GREEN claiming a verdict this run never reached. Fail closed.\n"
     "        pass\n",
     "test_a_crash_mid_scan_leaves_error_never_a_stale_green",
     "a crash mid-scan leaves the previous GREEN on disk"),

    ("inventory-ignored", "pii_gate.py",
     r'            r\["blocking"\] \+= len\(un\)\n', '',
     "test_gate_fails_red_on_an_unregistered_tree",
     "an unregistered tree rides a GREEN verdict"),

    ("role-field-excused-by-proximity", "pii_scan.py",
     r'        if benign_covers\(text, m\.start\("value"\), m\.end\(\), window=m\.span\(\)\):',
     '        if NON_REFERRING.search(text, max(0, m.start() - 24), m.end() + 8):',
     "test_role_field_benign_requires_coverage_not_proximity",
     "an SSH URL on the previous line excuses a Referees: line"),

    ("gpfs-homedir-drops-residual-recovery", "pii_scan.py",
     r'GPFS_HOMEDIR = r"\(\?<=/gpfs\)/home/\(\?:REDACTED\|\(\?!REDACTED\)'
     r'\[A-Za-z0-9\._-\]\+\)/\(\?!REDACTED\)\[A-Za-z0-9\._-\]\+"',
     r'GPFS_HOMEDIR = r"(?<=/gpfs)/home/(?!REDACTED)[A-Za-z0-9._-]+/(?!REDACTED)[A-Za-z0-9._-]+"',
     "test_gpfs_home_directory_catches_a_half_scrubbed_residue",
     "a home path half-scrubbed by a prior pass goes invisible again"),

    ("shell-prompt-escape-absorbed", "pii_scan.py",
     r'r"\|\(\?<!\[\\w@\.\]\)" \+ _SP_NOT_GENERIC \+ r"\(\?<!\\\\\)',
     r'r"|(?<![\w@.])" + _SP_NOT_GENERIC + r"',
     "test_an_escape_letter_is_not_glued_onto_a_generic_local_part",
     "a JSON escape letter glued onto 'user': the gate never clears"),

    ("json-escape-neutralisation-length-breaking", "pii_scan.py",
     r'text = re\.sub\(r"\\\\\[nrt\]", "  ", text\)',
     r'text = re.sub(r"\\[nrt]", "", text)',
     "test_a_reported_snippet_occurs_verbatim_in_the_file",
     "escape neutralisation shortened the text: reported snippets drift"),

    ("scrub-dry-run-writes", "pii_scrub.py",
     r'        if not args\.apply:\n            return ledger\.ok\("dry run',
     '        if False:\n            return ledger.ok("dry run',
     "test_a_dry_run_writes_nothing_and_apply_does",
     "a dry run that rewrites the corpus"),

    ("builder-lets-the-refused-file-through", "builder_guard.py",
     r'    refused = bool\(blocking\)\n', '    refused = False\n',
     "test_markdown_with_an_address_is_refused_by_kind_never_value",
     "the builder builds markdown with a blocking finding (the 488-document class)"),

    ("builder-cli-exits-zero-on-refusal", "builder_guard.py",
     r'    return 1 if refused else 0', '    return 0',
     "test_the_ledger_conserves_records_and_the_cli_exits_1",
     "a batch build reports success over refused files"),

    ("builder-row-key-carries-the-text", "builder_guard.py",
     r'k = key or "text:" \+ hashlib\.sha256\(text\.encode\("utf-8", "surrogateescape"\)\)\.hexdigest\(\)\[:16\]',
     'k = key or "text:" + text',
     "test_text_input_is_keyed_by_digest",
     "the ledger row's key reproduces the markdown it refused, value included"),

    ("ratchet-direction-inverted", "tests/test_ratchet_template.py",
     r'    if blocking > baseline:\n', '    if blocking < baseline:\n',
     "test_a_rise_fails",
     "the baseline read as a bound in the wrong direction: a rise passes, a fall fails"),

    ("ratchet-ignores-disagreement", "tests/test_ratchet_template.py",
     r'    if disagreement != 0:\n', '    if False:\n',
     "test_a_disagreement_fails",
     "a broken propagation path rides a passing ratchet"),

    ("ratchet-no-report-passes", "tests/test_ratchet_template.py",
     r'            self\.skipTest\(', '            return (',
     "test_no_report_skips",
     "'not checked' reported as a pass"),

    ("outis-output-gate-skipped", "outis.py",
     r'        bad = gate_output\(stage, inv_before\)\n', '        bad = []\n',
     "test_an_output_finding_fails_the_gate_and_is_named",
     "the clean delivers a tree its own scanner would fail"),

    ("outis-input-written", "outis.py",
     r'    with open\(dst, "wb"\) as fh:\n        fh\.write\(data\)',
     '    with open(src, "wb") as fh:\n        fh.write(data)',
     "test_the_input_is_byte_identical_after_the_run",
     "the quarantine (IN_DIR) is overwritten by the scrub"),

    ("outis-must-survive-eaten", "redact_names.py",
     r'            if len\(tok\) <= 3 or k in NAME_PARTICLES or k in words:\n',
     '            if False:\n',
     "test_every_must_survive_item_is_intact",
     "ambiguous tokens treated as names: a rule name and a compound eaten"),

    ("outis-binary-altered", "outis.py",
     r'        with open\(dst, "wb"\) as fh:\n            fh\.write\(raw\)',
     '        with open(dst, "wb") as fh:\n            fh.write(raw.replace(b"\\x00", b" "))',
     "test_binaries_are_byte_identical_and_listed",
     "a binary rewritten on the way through"),

    ("pem-body-left-behind", "pii_scrub.py",
     r'    out = PEM_BLOCK\.sub\(pem, out\)\n', '',
     "test_key_material_and_tokens_are_removed",
     "a private key's armour removed and its body left in the output"),

    ("missing-target-passes", "pii_scan.py",
     r'    if not os\.path\.exists\(args\.target\):\n',
     '    if False:\n',
     "test_a_missing_target_refuses_rather_than_passing",
     "a mistyped target scans nothing and the gate reports 0"),
]

SKIP = {"__pycache__", ".git"}


def _scratch():
    tmp = tempfile.mkdtemp(prefix="pii-mutant-")
    dst = os.path.join(tmp, "pkg")
    shutil.copytree(PKG, dst, symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
    return tmp, dst


def _run_suite(dst, timeout=600):
    env = dict(os.environ)
    env.pop("PII_RULINGS", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([PY, "tests/run_tests.py"], cwd=dst, env=env,
                          capture_output=True, text=True, timeout=timeout)


def _failed_tests(output):
    return set(re.findall(r"^(?:FAIL|ERROR): (\w+) \(", output, re.M))


def run(name, path, pat, rep, target):
    tmp, dst = _scratch()
    try:
        f = os.path.join(dst, path)
        with open(f, encoding="ascii") as fh:
            src = fh.read()
        # lambda, not a plain string: replacements contain \d and \b, which re
        # would otherwise parse as template escapes rather than literal text.
        new, n = re.subn(pat, lambda m: rep, src, count=0)
        if n != 1:
            return "NOT_APPLIED", "pattern matched %d times in %s" % (n, path)
        with open(f, "w", encoding="ascii") as fh:
            fh.write(new)
        try:
            py_compile.compile(f, doraise=True, cfile=os.path.join(tmp, "x.pyc"))
        except py_compile.PyCompileError as e:
            return "BROKEN_MUTANT", str(e).splitlines()[-1]
        p = _run_suite(dst)
        out = p.stdout + p.stderr
        if p.returncode == 0:
            return "SURVIVED", "the suite passed"
        failed = _failed_tests(out)
        if not failed:
            return "BROKEN_MUTANT", "suite exited %d with no test failure" % p.returncode
        if target in failed:
            return "KILLED", "%d test(s) failed, target among them" % len(failed)
        return "KILLED_ELSEWHERE", "target passed; failed: %s" % ", ".join(sorted(failed))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def baseline():
    """(ran, skipped, ok) for the unmutated scratch tree."""
    tmp, dst = _scratch()
    try:
        p = _run_suite(dst)
        out = p.stdout + p.stderr
        m = re.search(r"^Ran (\d+) tests? ", out, re.M)
        s = re.search(r"skipped=(\d+)", out)
        return (int(m.group(1)) if m else 0, int(s.group(1)) if s else 0,
                p.returncode == 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("mutation check -- reintroducing defects into a scratch copy\n")
    ran, skipped, ok = baseline()
    if not ok or ran == 0:
        print("  BASELINE FAILED: the unmutated scratch tree does not pass "
              "(%d run). Nothing can be scored." % ran)
        return 2
    results = []
    for name, path, pat, rep, target, defect in MUTANTS:
        try:
            status, detail = run(name, path, pat, rep, target)
        except subprocess.TimeoutExpired:
            status, detail = "TIMEOUT", target
        results.append((name, status))
        mark = {"KILLED": "  ok  ", "KILLED_ELSEWHERE": "  ok* "}.get(status, " FAIL ")
        print("[%s] %-42s %-16s %s" % (mark, name, status, defect))
        if status not in ("KILLED",):
            print("         -> %s" % detail)
    killed = sum(1 for _n, s in results if s in ("KILLED", "KILLED_ELSEWHERE"))
    bad = [n for n, s in results if s not in ("KILLED", "KILLED_ELSEWHERE")]
    print("\n  %d of %d mutants killed over %d tests (%d skipped in the scratch tree)"
          % (killed, len(results), ran - skipped, skipped))
    if skipped:
        print("  A mutant only a skipped test would catch scores as SURVIVED.")
    if bad:
        print("  NOT KILLED: %s" % ", ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
