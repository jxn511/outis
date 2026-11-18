"""Tests for redact_names.py (carried from the loop's redact_pass5.py) over an INVENTED fixture tree and an INVENTED
names file. Each test names the contract item (P1-P11) it scores."""

import csv
import json
import os
import re
import unittest

import names_support as S


class Base(unittest.TestCase):
    def setUp(self):
        self.base = S.mkdtemp()
        self.root, self.agents = S.build(self.base)
        self.out = os.path.join(self.base, "out")
        os.makedirs(self.out)
        self.ledger = os.path.join(self.out, "ledger.jsonl")
        self.manifest = os.path.join(self.out, "SNAPSHOT_MANIFEST_pass5.csv")
        self.readme = os.path.join(self.out, "README_pass5.txt")
        self.before_root = S.snapshot(self.root)
        self.before_agents = S.snapshot(self.agents)

    def tearDown(self):
        S.rmtree(self.base)

    def apply(self, *extra, agents=True):
        args = ["--names", S.NAMES] + S.MEMBERSHIP + [
                "--root", self.root, "--ledger", self.ledger,
                "--manifest-out", self.manifest, "--readme-out", self.readme, "--apply"]
        if agents:
            args += ["--agents", self.agents]
        return S.run_cli(*(args + list(extra)))

    def dry(self):
        return S.run_cli(*(["--names", S.NAMES] + S.MEMBERSHIP + [
                         "--root", self.root, "--agents", self.agents, "--ledger", self.ledger]))

    def ledger_rows(self):
        with open(self.ledger) as f:
            return [json.loads(x) for x in f]

    def totals(self):
        return [r for r in self.ledger_rows() if r["kind"] == "totals"][0]

    def read(self, rel, top=None):
        with open(os.path.join(top or self.root, rel), newline="") as f:
            return f.read().split("\n")


class P1Inputs(Base):
    def test_missing_names_file_refuses_before_any_tree_read(self):
        # the root does not even exist: a refusal ABOUT THE NAMES proves the
        # names were checked first
        rc, out, err = S.run_cli("--names", os.path.join(self.base, "absent.txt"),
                                 "--root", os.path.join(self.base, "no_such_tree"),
                                 "--ledger", self.ledger)
        self.assertEqual(rc, 2)
        self.assertIn("names file missing", err)
        self.assertFalse(os.path.exists(self.ledger))

    def test_empty_names_file_refuses(self):
        empty = os.path.join(self.out, "empty_names.txt")
        with open(empty, "w") as f:
            f.write("# only a comment\n\n   # and another\n")
        rc, out, err = S.run_cli("--names", empty, "--root",
                                 os.path.join(self.base, "no_such_tree"),
                                 "--ledger", self.ledger)
        self.assertEqual(rc, 2)
        self.assertIn("no usable token", err)
        self.assertEqual(S.snapshot(self.root), self.before_root)

    def test_names_are_run_time_input_not_in_the_tool(self):
        with open(S.MODULE) as f:
            src = f.read()
        for tok in S.TOKENS:
            self.assertFalse(tok.lower() in src.lower(), tok)

    def test_short_token_dropped_and_counted(self):
        rc, _o, _e = self.dry()
        self.assertEqual(rc, 0)
        t = self.totals()
        self.assertEqual(t["tokens_listed"], 14)
        self.assertEqual(t["tokens_dropped_short"], 1)

    def test_output_inside_tree_refused(self):
        rc, _o, err = S.run_cli("--names", S.NAMES, "--root", self.root,
                                "--ledger", os.path.join(self.root, "ledger.jsonl"))
        self.assertEqual(rc, 2)
        self.assertIn("inside a scanned tree", err)


class Prefilter(unittest.TestCase):
    def test_prefilter_never_rejects_a_regex_match_bmp(self):
        """Enumerated, not sampled: every BMP code point the case-insensitive
        regex accepts in place of any one letter of a token is also passed by
        the word-set pre-filter (the dotted/dotless i pair is the known trap)."""
        mod = S.load_module()
        toks = ("Iyer", "Kas", "Sas")
        nl = mod.NameList([(i + 1, t) for i, t in enumerate(toks)], {})
        misses = []
        accepted = 0
        for cp in range(0x10000):
            c = chr(cp)
            for tok in toks:
                for i in range(len(tok)):
                    t = tok[:i] + c + tok[i + 1:]
                    if nl.rx.fullmatch(t):
                        accepted += 1
                        if not nl.find(" " + t + " "):
                            misses.append((hex(cp), tok, i))
        self.assertEqual(misses, [])
        self.assertGreater(accepted, 10 * 2)      # positive control: variants exist


class P2Context(Base):
    def setUp(self):
        Base.setUp(self)
        self.rc, self.stdout, self.stderr = self.apply()

    def test_apply_exit_zero(self):
        self.assertEqual(self.rc, 0, self.stdout + self.stderr)

    def test_dec_comments_replaced_code_left(self):
        dec = self.read("dec/B0_fixture.dec")
        self.assertEqual(dec[1], "# Author: <name> <name> 2004-05-12")
        self.assertEqual(dec[2], "# <name> <name> 2004-05-12")
        self.assertEqual(dec[3], "#   modified by C. <name>")
        self.assertEqual(dec[4], "# uses the Mikelson model; see <name>'s note")
        self.assertEqual(dec[5], "Alias Indiason K+")
        self.assertEqual(dec[7], "1.0   Indiason pi-   PHSP; # tuned by <name> <name>")

    def test_cc_comment_replaced_code_identifier_left(self):
        cc = self.read("src/EvtGen/testEvtGen.cc")
        self.assertEqual(cc[1], "// Author: <name> <name>")
        # P29: an identifier opening a comment as its subject is replaced
        self.assertEqual(cc[2], "/* <name> wrote the first")
        self.assertEqual(cc[3], "   version; <name> <name> 1998-03-02 */")
        self.assertEqual(cc[5], "int Golfwick = 0;             // <name> counter, by <name>")
        # a '//' inside a string literal is code
        self.assertEqual(cc[6], S.TEST_EVTGEN_HEADER[6])
        # whole word: Bravoson_count and Mikelson untouched; the comment replaced
        self.assertEqual(cc[7], "int Bravoson_count = 0; /* <name> */ int Mikelson = 1;")
        # a char literal holding a double quote does not open a string
        self.assertEqual(cc[8], "char c = '\"'; // quote char by <name>")
        self.assertEqual(cc[9], "/* block start <name>")
        self.assertEqual(cc[10], "   <name> continues */ int Indiason = 2; // <name>")

    def test_tcl_shell_txt_rules(self):
        tcl = self.read("tcl/run.tcl")
        # P29: an identifier opening a comment as its subject is a person
        self.assertEqual(tcl, ["# set up by <name>", "set Golfwick 3 ;# <name> knob",
                               "puts \"# Golfwick\"", ""])
        sh = self.read("scripts/run.sh")
        self.assertEqual(sh[2], "label=\"Golfwick\"   # <name>")
        txt = self.read("txt/notes.txt")   # P13 prose; P24: identifiers by the attribution rule
        self.assertEqual(txt[1], "<name> <name> 2004-05-12")
        self.assertEqual(txt[2], "The Golfwick method is used here.  # Golfwick")
        self.assertEqual(txt[3], "quote: \"# not a comment Golfwick\"")
        extra = self.read("README_EXTRA")
        self.assertEqual(extra[0], "Contact for this tree, <name> <name>")
        self.assertEqual(extra[1], "$Id: EvtFoo.cc,v 1.2 2004/05/12 <name> Exp $")
        self.assertEqual(extra[2], "The Indiason resonance is described below.")

    def test_p13_history_and_extensionless_prose_every_occurrence(self):
        # unambiguous tokens: every occurrence; identifiers: attribution lines only (P24)
        self.assertEqual(self.read("logs/run.history"),
                         ["cd work; ran fit with Golfwick tuning", "<name> 2004-05-12",
                          "plain Indiason line", ""])
        # P31(d): an identifier opening a prose line's text as its subject is replaced
        self.assertEqual(self.read("NOTES"),
                         ["notes kept by the shift", "<name> resonance seen, <name>'s check", ""])
        # a shebang file is a script: comment replaced, code left
        self.assertEqual(self.read("configure"), ["#!/bin/sh", "# by <name>", "Golfwick=1", ""])

    def test_p13_ledger_names_the_file_class(self):
        rows = [r for r in self.ledger_rows() if r["kind"] == "changed_line"]
        cls = {(r["file"], r["line"]): r["fclass"] for r in rows}
        self.assertEqual(cls[("root:./logs/run.history", 2)], "prose")
        self.assertEqual(cls[("root:./NOTES", 2)], "prose")
        # an unambiguous token in prose is replaced under the prose rule (context p)
        ctx = {(r["file"], r["line"]): r["context"] for r in rows}
        self.assertIn("p", ctx[("root:./NOTES", 2)])
        self.assertEqual(cls[("root:./configure", 2)], "shellish")
        self.assertEqual(cls[("root:./dec/B0_fixture.dec", 2)], "hash")
        self.assertEqual(cls[("root:./src/EvtGen/testEvtGen.cc", 2)], "c")
        left = [r for r in self.ledger_rows() if r["kind"] == "code_left"]
        self.assertFalse([r for r in left if r["fclass"] == "prose"
                          and r["membership"] == "unambiguous"])

    def test_code_occurrences_counted_in_ledger_with_file_and_line(self):
        left = [(r["file"], r["line"]) for r in self.ledger_rows() if r["kind"] == "code_left"]
        for want in [("root:./dec/B0_fixture.dec", 6), ("root:./dec/B0_fixture.dec", 8),
                     ("root:./src/EvtGen/testEvtGen.cc", 6),
                     ("root:./src/EvtGen/testEvtGen.cc", 7),
                     ("root:./src/EvtGen/testEvtGen.cc", 11),
                     ("root:./pdl/evt.pdl", 3), ("root:./tcl/run.tcl", 2),
                     ("root:./tcl/run.tcl", 3), ("agents:./records.jsonl", 4)]:
            self.assertIn(want, left)

    def test_jsonl_values_only_keys_left_reserialised(self):
        recs = self.read("records.jsonl", self.agents)
        r1 = json.loads(recs[0])
        self.assertEqual(r1["fixes"][0]["old"],
                         "1.0   Indiason pi-   PHSP; # tuned by <name> <name>")
        r3 = json.loads(recs[2])
        self.assertEqual(r3["line"], "# Author: <name> <name> 2004-05-12")
        r4 = json.loads(recs[3])
        self.assertIn("Golfwick", r4)                      # a key: never replaced
        self.assertEqual(json.loads(recs[4])["note"], "Golfwick ran the fit")
        for line in recs[:5]:
            if line:
                self.assertEqual(json.dumps(json.loads(line), ensure_ascii=True,
                                            sort_keys=True), line)

    def test_p12_noncanonical_record_edited_on_raw_bytes(self):
        recs = self.read("records.jsonl", self.agents)
        self.assertEqual(recs[5], S.NONCANON_AFTER)
        rows = [r for r in self.ledger_rows() if r["kind"] == "record_refused"]
        self.assertEqual(rows, [])

    def test_doc_md(self):
        md = self.read("DOC_fixture.md", self.agents)
        self.assertEqual(md[2], "Written by <name> <name>.")
        self.assertEqual(md[4], "The <name> estimator is described below.")
        self.assertEqual(md[6], "<name> <name>")

    def test_rerun_is_a_fixpoint(self):
        snap = S.snapshot(self.root)
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(S.snapshot(self.root), snap)
        self.assertEqual(self.totals()["files_changed"], 0)


class P3LinePreserving(Base):
    def test_only_replaced_spans_differ_and_line_counts_equal(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        changed = 0
        for top, before in ((self.root, self.before_root), (self.agents, self.before_agents)):
            after = S.snapshot(top)
            self.assertEqual(sorted(after), sorted(before))
            for rel in before:
                old, new = before[rel], after[rel]
                self.assertEqual(old.count(b"\n"), new.count(b"\n"), rel)
                if old != new:
                    changed += 1
                    self.assertTrue(S.only_span_diff(old.decode("latin-1"),
                                                     new.decode("latin-1")), rel)
        self.assertGreaterEqual(changed, 10)          # positive control

    def test_whitelist_lines_keep_their_numbers(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        for rel, nums in S.WHITELIST.items():
            lines = self.read(rel)
            for n in nums:
                self.assertEqual(lines[n - 1], S.WHITELIST_LINE, (rel, n))
        tc = self.read("src/EvtGen/testEvtGen.cc")
        # P24: an identifier in a comment that is no attribution line is left
        self.assertEqual(tc[1908], "    // next token read here (Golfwick)")

    def test_crlf_and_latin1_bytes_preserved(self):
        p = os.path.join(self.root, "txt", "crlf.txt")
        with open(p, "wb") as f:
            f.write(b"caf\xe9 notes\r\n# by Golfwick\r\nend\r\n")
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(p, "rb") as f:
            self.assertEqual(f.read(), b"caf\xe9 notes\r\n# by <name>\r\nend\r\n")

    def test_non_ascii_names_runtime(self):
        names = os.path.join(self.out, "names_utf8.txt")
        with open(names, "wb") as f:
            f.write("Zo\u00e9son\n".encode("utf-8"))
        tree = os.path.join(self.base, "u")
        os.makedirs(tree)
        with open(os.path.join(tree, "a.txt"), "wb") as f:
            f.write("# by Zo\u00e9son\nZo\u00e9sonite stays\n".encode("utf-8"))
        with open(os.path.join(tree, "b.txt"), "wb") as f:
            f.write("# by Zo\u00e9son\n\xff\n".encode("latin-1"))

        rc, out, err = S.run_cli("--names", names, "--root", tree, "--ledger", self.ledger,
                                 "--manifest-out", self.manifest, "--readme-out",
                                 self.readme, "--apply")
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(tree, "a.txt"), "rb") as f:
            self.assertEqual(f.read(), "# by <name>\nZo\u00e9sonite stays\n".encode("utf-8"))
        with open(os.path.join(tree, "b.txt"), "rb") as f:
            self.assertEqual(f.read(), b"# by <name>\n\xff\n")


class P12RawBytes(Base):
    def test_escapes_and_surrogates_mapped_on_raw_bytes(self):
        names = os.path.join(self.out, "names_utf8.txt")
        with open(names, "wb") as f:
            f.write("Zo\u00e9son\n".encode("utf-8"))
        tree = os.path.join(self.base, "agents12")
        os.makedirs(tree)
        rec = ('{ "z":"\\ud83d\\ude00 then by Zo\\u00e9son \\"q\\"",'
               '"a" :[1, 2.50, null, "Zo\\u00e9son 2004-05-12"] }\n')
        want = ('{ "z":"\\ud83d\\ude00 then by <name> \\"q\\"",'
                '"a" :[1, 2.50, null, "<name> 2004-05-12"] }\n')
        with open(os.path.join(tree, "r.jsonl"), "w") as f:
            f.write(rec)
        empty_root = os.path.join(self.base, "empty_root")
        os.makedirs(empty_root)
        rc, out, err = S.run_cli("--names", names, "--root", empty_root, "--agents", tree,
                                 "--ledger", self.ledger,
                                 "--manifest-out", self.manifest, "--readme-out",
                                 self.readme, "--apply")
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(tree, "r.jsonl")) as f:
            self.assertEqual(f.read(), want)


class P15Membership(Base):
    def test_left_rows_carry_membership_and_no_gate_left_outside_source(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        left = [r for r in self.ledger_rows() if r["kind"] == "code_left"]
        self.assertTrue(left)
        for r in left:
            self.assertIn(r["membership"], ("unambiguous", "ambiguous", "identifier"))
            if r["membership"] == "unambiguous":
                self.assertEqual(r["where"], "code", r)
        split = self.totals()["left_by_tree"]
        self.assertEqual(split["agents"]["json_string"]["identifier"], 1)   # r5
        self.assertEqual(split["agents"]["json_code_field"]["identifier"], 1)  # r8
        self.assertNotIn("unambiguous", split["agents"].get("json_string", {}))
        self.assertIn("left outside source code: agents unambiguous 0", out)
        for p in [r for r in self.ledger_rows() if r["kind"] == "post_check"]:
            self.assertEqual(p["comment_attribution"], 0)
            self.assertEqual(p["unambiguous_left_outside_source"], 0)
            self.assertEqual(p["ambiguous_left_on_attribution_lines"], 0)

    def test_gate_in_prose_field_replaced_code_key_comment_only(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        recs = self.read("records.jsonl", self.agents)
        self.assertEqual(json.loads(recs[6])["note"], "the fit <name> ran")
        self.assertEqual(json.loads(recs[7])["new"], "1.0   Indiason K- PHSP; # by <name>")
        self.assertEqual(json.loads(recs[4])["note"], "Golfwick ran the fit")

    def test_gate_token_in_a_json_key_is_residue(self):
        with open(os.path.join(self.agents, "keyed.jsonl"), "w") as f:
            f.write('{"Kiloson": "x"}\n')
        rc, out, err = self.apply()
        self.assertEqual(rc, 1, out + err)
        post = [r for r in self.ledger_rows() if r["kind"] == "post_check"
                and r["tree"] == "agents"][0]
        self.assertEqual(post["unambiguous_left_outside_source"], 1)

    def test_membership_files_must_partition_the_names(self):
        bad = os.path.join(self.out, "gate_bad.txt")
        with open(bad, "w") as f:
            f.write("Zulumark\n")
        rc, out, err = S.run_cli("--names", S.NAMES, "--unambiguous-names", bad,
                                 "--ambiguous-names", S.AMBIG, "--identifier-names", S.IDENT,
                                 "--root", self.root, "--ledger", self.ledger)
        self.assertEqual(rc, 2)
        self.assertIn("not in --names", err)
        # two of three given
        rc, out, err = S.run_cli("--names", S.NAMES, "--unambiguous-names", S.UNAMB,
                                 "--identifier-names", S.IDENT, "--root", self.root,
                                 "--ledger", self.ledger)
        self.assertEqual(rc, 2)
        self.assertIn("2 of 3 given", err)
        # a token in two classes
        both = os.path.join(self.out, "amb_both.txt")
        with open(both, "w") as f:
            f.write("De\nRe\nMax\nGolfwick\n")
        rc, out, err = S.run_cli("--names", S.NAMES, "--unambiguous-names", S.UNAMB,
                                 "--ambiguous-names", both, "--identifier-names", S.IDENT,
                                 "--root", self.root, "--ledger", self.ledger)
        self.assertEqual(rc, 2)
        self.assertIn("1 token(s) are in both the ambiguous and the identifier", err)


class P16OneInvocation(Base):
    def test_quoted_code_line_takes_the_snapshot_decision(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        recs = self.read("records.jsonl", self.agents)
        self.assertEqual(json.loads(recs[8])["note"],
                         "int Golfwick = 0;             // <name> counter, by <name>")
        self.assertIn("quote index: built", out)

    def test_agents_without_root_apply_refused(self):
        rc, out, err = S.run_cli(*(["--names", S.NAMES] + S.MEMBERSHIP + [
            "--agents", self.agents, "--ledger", self.ledger, "--manifest-out", self.manifest,
            "--readme-out", self.readme, "--apply"]))
        self.assertEqual(rc, 2)
        self.assertIn("--root", err)
        self.assertEqual(S.snapshot(self.agents), self.before_agents)

    def test_repeatable_agents_and_check_records_in_the_same_invocation(self):
        second = os.path.join(self.base, "agents_b")
        os.makedirs(second)
        with open(os.path.join(second, "fix.jsonl"), "w") as f:
            f.write(S.FILES["agents/records.jsonl"].split("\n")[0] + "\n")
        rc, out, err = S.run_cli(*(["--names", S.NAMES] + S.MEMBERSHIP + [
                "--root", self.root, "--agents", self.agents, "--agents", second,
                "--ledger", self.ledger, "--manifest-out", self.manifest,
                "--readme-out", self.readme, "--apply"]))
        self.assertEqual(rc, 0, out + err)
        files = set(r["file"].split(":")[0] for r in self.ledger_rows() if "file" in r)
        self.assertTrue({"agents1", "agents2"} <= files, files)
        self.assertIn("check-records (same invocation) agents1: 3 quoted items checked, "
                      "0 UNMATCHED", out)
        self.assertIn("check-records (same invocation) agents2: 1 quoted items checked, "
                      "0 UNMATCHED", out)

    def test_binary_file_named_in_the_ledger(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        rows = [r for r in self.ledger_rows() if r["kind"] == "skipped"]
        self.assertEqual(rows, [{"kind": "skipped", "file": "root:./bin/blob.bin",
                                 "reason": "binary"}])
        post = [r for r in self.ledger_rows() if r["kind"] == "post_check"
                and r["tree"] == "root"][0]
        self.assertEqual(post["binary_files_skipped"], 1)
        self.assertIn("check-records skips NUL-bearing files", post["binary_coverage"])
        self.assertIn("binary files skipped", out)


class P17TreeKind(Base):
    def two_agents(self):
        second = os.path.join(self.base, "agents_b")
        os.makedirs(second)
        with open(os.path.join(second, "notes.md"), "w") as f:
            f.write("Reviewed by Julietta Kiloson.\n")
        return S.run_cli(*(["--names", S.NAMES] + S.MEMBERSHIP + [
            "--root", self.root, "--agents", self.agents, "--agents", second,
            "--ledger", self.ledger, "--manifest-out", self.manifest,
            "--readme-out", self.readme, "--apply"]))

    def test_counters_paragraph_and_summary_keyed_on_tree_kind(self):
        rc, out, err = self.two_agents()
        self.assertEqual(rc, 0, out + err)
        t = self.totals()
        self.assertEqual(t["files_changed_agents"], 3)
        self.assertEqual(t["files_changed"], t["files_changed_root"] + 3)
        self.assertIn("(%d snapshot, 3 agents)" % t["files_changed_root"], out)
        with open(self.readme) as f:
            para = f.read()
        self.assertIn("agents files changed by the fifth pass (3):", para)
        self.assertIn("  agents2:./notes.md\n", para)

    def test_per_tree_table_printed(self):
        rc, out, err = self.two_agents()
        self.assertEqual(rc, 0, out + err)
        self.assertRegex(out, r"tree agents2 \(agents\): 1 files scanned, 1 changed, 1 lines, "
                              r"2 tokens; left unambiguous 0, ambiguous 0, identifier 0")
        self.assertRegex(out, r"tree root \(root\): \d+ files scanned, 13 changed")


class P18EmbeddedNul(Base):
    NUL_DEC = ("# Author: Echoway Foxtrotson 1999-01-02\n"
               "Decay B0\n"
               "1.0 K+ pi- PHSP; # stray \x00 byte, tuned by Golfwick\n"
               "1.0 Indiason pi0 PHSP;\n"
               "Enddecay\n"
               "End\n")

    def write(self, rel, text):
        with open(os.path.join(self.root, rel), "w", newline="") as f:
            f.write(text)

    def test_one_nul_dec_is_text_redacted_nul_kept(self):
        self.write("dec/B0_nul.dec", self.NUL_DEC)
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.root, "dec/B0_nul.dec"), "rb") as f:
            got = f.read()
        # P24 refined: "by <Token>" on a SHORT line is attribution wherever it stands
        self.assertEqual(got, self.NUL_DEC.replace("Echoway Foxtrotson", "<name> <name>")
                         .replace("by Golfwick", "by <name>").encode("ascii"))
        rows = self.ledger_rows()
        self.assertFalse([r for r in rows if r["kind"] == "skipped"
                          and "B0_nul" in r["file"]])
        self.assertIn("text with embedded NUL root:./dec/B0_nul.dec: 1 NUL byte(s), "
                      "2 lines changed, 1 left", out)
        mod = S.load_module()
        self.assertIn("1.0 K+ pi- PHSP; # stray \x00 byte", mod.snapshot_text(self.root))

    def test_three_nuls_stay_binary(self):
        self.write("dec/B0_bin.dec", "# by Golfwick\x00\x00\x00\n")
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        rows = [r for r in self.ledger_rows() if r["kind"] == "skipped"]
        self.assertIn({"kind": "skipped", "file": "root:./dec/B0_bin.dec",
                       "reason": "binary"}, rows)


class P19P22Ambiguous(Base):
    DOC = ("The DE MINIMIS rule covers the re-derivations; use max(a, b) here.\n"
           "Re Bravoson\n"
           "Checked by De Kiloson, re-derivations included\n"
           "DE MINIMIS\n"
           # P24: an identifier and ambiguous tokens in prose survive
           "The Golfwick re-pin check uses max(row error) and a RE-CHECK.\n")
    DOC_AFTER = ("The DE MINIMIS rule covers the re-derivations; use max(a, b) here.\n"
                 "<name> <name>\n"
                 "Checked by <name> <name>, re-derivations included\n"
                 "DE MINIMIS\n"
                 "The Golfwick re-pin check uses max(row error) and a RE-CHECK.\n")
    LONG = ("On 2026-11-17 the De Minimis threshold was applied by the reviewer to the "
            "re-derivations of every fit in the table, as agreed with Golfwick")
    REC = ('{"id": "q1", "rationale": "DE MINIMIS: the re-derivations stay; max(x) kept"}\n'
           '{"id": "q2", "note": "tuned by De"}\n'
           '{"id": "q3", "who": "Re Bravoson"}\n'
           # P24: a long rationale sentence with "by", a date, an ambiguous and an
           # identifier token is no attribution line: it survives whole
           '{"id": "q4", "rationale": "' + LONG + '"}\n')
    REC_AFTER = ('{"id": "q1", "rationale": "DE MINIMIS: the re-derivations stay; max(x) kept"}\n'
                 '{"id": "q2", "note": "tuned by <name>"}\n'
                 '{"id": "q3", "who": "<name> <name>"}\n'
                 '{"id": "q4", "rationale": "' + LONG + '"}\n')

    def plant(self):
        with open(os.path.join(self.agents, "rationale.md"), "w") as f:
            f.write(self.DOC)
        with open(os.path.join(self.agents, "rationale.jsonl"), "w") as f:
            f.write(self.REC)

    def test_rule_name_hyphenated_and_short_word_untouched_name_lines_replaced(self):
        self.plant()
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "rationale.md")) as f:
            self.assertEqual(f.read(), self.DOC_AFTER)
        with open(os.path.join(self.agents, "rationale.jsonl")) as f:
            self.assertEqual(f.read(), self.REC_AFTER)

    def test_ambiguous_left_counted_by_context(self):
        self.plant()
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        left = [r for r in self.ledger_rows()
                if r["kind"] == "code_left" and r["membership"] == "ambiguous"]
        by_where = {}
        for r in left:
            by_where[r["where"]] = by_where.get(r["where"], 0) + 1
        # DE and max in the DOC line (prose), DE and max in q1 (json_string);
        # re-derivations is no occurrence at all (hyphen-joined)
        # DE and max in DOC line 1, DE alone on the heading line (prose);
        # DE and max in q1 (json_string); re-derivations is no occurrence
        # P24 adds max( in prose and De in the long rationale
        self.assertEqual(by_where, {"prose": 4, "json_string": 3})
        self.assertIn("ambiguous 7 (left by rule)", out)

    def test_old_form_breaks_both(self):
        """The pre-P19 form (every token unambiguous) is what the reverted
        pass ran: it mangles the rule name and the short word."""
        self.plant()
        rc, out, err = S.run_cli(*(["--names", S.NAMES] + S.old_form_lists(self.out) + [
                                 "--root", self.root, "--agents",
                                 self.agents, "--ledger", self.ledger, "--manifest-out",
                                 self.manifest, "--readme-out", self.readme, "--apply"]))
        with open(os.path.join(self.agents, "rationale.md")) as f:
            got = f.read()
        self.assertIn("<name> MINIMIS", got)          # the defect, demonstrated
        self.assertIn("<name>(a, b)", got)


class P24IdentifiersAndShortLines(Base):
    def test_auto_partition_precedence(self):
        """No membership files: the tool partitions by itself -- ambiguous
        first (three letters or fewer, a particle, a --dictionary word),
        then identifier (a code occurrence in --root source), then
        unambiguous."""
        rc, out, err = S.run_cli("--names", S.NAMES, "--root", self.root, "--agents",
                                 self.agents, "--ledger", self.ledger)
        self.assertEqual(rc, 0, out + err)
        t = self.totals()
        self.assertEqual((t["membership_ambiguous_tokens"], t["membership_identifier_tokens"],
                          t["membership_unambiguous_tokens"]), (3, 2, 9))
        self.assertTrue(t["membership_source"].startswith("auto"))
        # a dictionary word that is also an identifier is AMBIGUOUS (precedence)
        dic = os.path.join(self.out, "words.txt")
        with open(dic, "w") as f:
            f.write("golfwick\n")
        rc, out, err = S.run_cli("--names", S.NAMES, "--dictionary", dic, "--root", self.root,
                                 "--ledger", self.ledger)
        self.assertEqual(rc, 0, out + err)
        t = self.totals()
        self.assertEqual((t["membership_ambiguous_tokens"], t["membership_identifier_tokens"],
                          t["membership_unambiguous_tokens"]), (4, 1, 9))

    def test_long_sentence_is_no_attribution_line(self):
        mod = S.load_module()
        nl = mod.NameList.load(S.NAMES)
        nl.set_membership(S.UNAMB, S.AMBIG, S.IDENT)
        long_ = P19P22Ambiguous.LONG
        self.assertFalse(mod.is_attribution(long_, nl.find(long_)))
        for short in ("Checked by De Kiloson", "tuned by De", "Re Bravoson",
                      "# Author: Alphonzo Bravoson 2004-05-12", "Golfwick 2004-05-12"):
            self.assertTrue(mod.is_attribution(short, nl.find(short)), short)
        # thirteen whitespace tokens opening with a keyword: since P26(d) the
        # keyword idiom covers the NAME RUN after it, whatever the length --
        # the extent stops at the last listed token of that run
        thirteen = "Written by Alphonzo Bravoson " + " ".join(["x"] * 9)
        ext = mod.attribution_extent(thirteen, nl.find(thirteen))
        self.assertEqual(thirteen[:ext], "Written by Alphonzo Bravoson")
        # thirteen tokens with no keyword opening, no token+date: no attribution
        plain = "the fit then used Alphonzo Bravoson " + " ".join(["x"] * 7)
        self.assertFalse(mod.is_attribution(plain, nl.find(plain)))
        # refinement: "by <Token>" on a short line counts wherever it stands
        for by_mid in ("# stray NUL byte, tuned by Golfwick", "# written by Golfwick 2004",
                       "the fit was rerun later by Alphonzo"):
            self.assertTrue(mod.is_attribution(by_mid, nl.find(by_mid)), by_mid)
        # ... but a keyword idiom must open the line, and "by" must be followed
        # by the token itself
        for no in ("the Golfwick table was modified later", "# Golfwick knob",
                   "the fit applied later by the reviewer to Golfwick"):
            self.assertFalse(mod.is_attribution(no, nl.find(no)), no)


class P25OpeningForm(Base):
    """A listed token followed by a date or an attribution keyword within the
    first four words after the comment marker opens an attribution line of
    ANY length; the opening's tokens are replaced, the remark keeps the
    prose/comment rules."""
    REMARKS = (
        "# Golfwick 4/28/00 made the Bs parallel to the Bd as requested by the group in the last meeting\n"
        "# Golfwick 2004-05-12 changed the form factor model for the semileptonic modes and retuned the fractions\n"
        "# Golfwick Nov 14, 2004 added the missing modes and moved the Indiason ones to the end of the file\n"
        "# Golfwick Aug19,2002 fixed the branching fractions after the update and renormalised all the modes\n"
        "# Golfwick 00-02-10 first version of this decay file for the new release with the full set of modes\n"
        "# Echoway Golfwick modified the Bs modes to match the Bd ones and removed the obsolete channels\n"
        "Decay B0\n1.0 K+ pi- PHSP;\nEnddecay\nEnd\n")
    REMARKS_AFTER = (
        "# <name> 4/28/00 made the Bs parallel to the Bd as requested by the group in the last meeting\n"
        "# <name> 2004-05-12 changed the form factor model for the semileptonic modes and retuned the fractions\n"
        "# <name> Nov 14, 2004 added the missing modes and moved the Indiason ones to the end of the file\n"
        "# <name> Aug19,2002 fixed the branching fractions after the update and renormalised all the modes\n"
        "# <name> 00-02-10 first version of this decay file for the new release with the full set of modes\n"
        "# <name> <name> modified the Bs modes to match the Bd ones and removed the obsolete channels\n"
        "Decay B0\n1.0 K+ pi- PHSP;\nEnddecay\nEnd\n")

    def write(self, rel, text, top=None):
        p = os.path.join(top or self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def test_six_opening_shapes_replaced_whatever_the_length(self):
        self.write("dec/B0_remarks.dec", self.REMARKS)
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.root, "dec/B0_remarks.dec")) as f:
            self.assertEqual(f.read(), self.REMARKS_AFTER)

    def test_quoted_copies_no_longer_ambiguous(self):
        """A record quoting the long remark line, which also contains a
        short snapshot line verbatim: under P24 the long line left the token
        and the short line replaced it -- quote_ambiguous; under P25 both
        replace, so the record is edited and check-records matches."""
        self.write("dec/B0_remarks.dec", self.REMARKS)
        self.write("dec/B0_short.dec", "# Golfwick 2004-05-12\nEnd\n")
        self.write("fixes.jsonl", '{"fixes": [{"new": "x", "old": "# Golfwick 2004-05-12 changed '
                   'the form factor model"}], "id": "f1"}\n', self.agents)
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        self.assertFalse([r for r in self.ledger_rows() if r["kind"] == "record_refused"])
        with open(os.path.join(self.agents, "fixes.jsonl")) as f:
            self.assertIn('"old": "# <name> 2004-05-12 changed the form factor model"', f.read())
        self.assertIn("check-records (same invocation) agents: 4 quoted items checked, "
                      "0 UNMATCHED", out)

    def test_extent_and_bounds(self):
        mod = S.load_module()
        nl = mod.NameList.load(S.NAMES)
        nl.set_membership(S.UNAMB, S.AMBIG, S.IDENT)
        line = "# Golfwick 4/28/00 made the Bs parallel to the Golfwick table as agreed by all of us"
        ext = mod.attribution_extent(line, nl.find(line))
        self.assertEqual(line[:ext], "# Golfwick 4/28/00")           # the opening only
        # the P24 long rationale: no listed token before a date in its first
        # four words -> still no attribution line
        long_ = P19P22Ambiguous.LONG
        self.assertIsNone(mod.attribution_extent(long_, nl.find(long_)))
        # a date or keyword after the fourth word does not open a line
        late = "# the fit was rerun Golfwick 4/28/00 with every mode and all the weights renormalised"
        self.assertIsNone(mod.attribution_extent(late, nl.find(late)))


class P26FormsAndAuthorLines(Base):
    """P26: a soft token in possessive form, or right after "by " / "from ",
    in comment or prose context is attribution context; a long
    "Author: <token> ..." keyword line is the P2(b) idiom whatever its length."""
    DOC = ("Taken from Max's QQ tables for every mode.\n"
           "The analysis uses the Re's QQ tables throughout the whole of this chapter and beyond.\n"
           "See the tables from De for details of the binning and the fit model choices.\n"
           "The yields were cross-checked against the full simulation and refit by Golfwick last week.\n"
           "The DE MINIMIS rule and the re-derivations stay; use max(a, b) here.\n")
    DOC_AFTER = ("Taken from <name>'s QQ tables for every mode.\n"
                 "The analysis uses the <name>'s QQ tables throughout the whole of this chapter and beyond.\n"
                 "See the tables from <name> for details of the binning and the fit model choices.\n"
                 "The yields were cross-checked against the full simulation and refit by <name> last week.\n"
                 "The DE MINIMIS rule and the re-derivations stay; use max(a, b) here.\n")
    DEC = ("# the shape is taken from Golfwick's fit to the full data set of the last run period here\n"
           "# Author: De and a long remark about the decay model and the form factors used in this file\n"
           "Decay B0\n1.0 K+ pi- PHSP;\nEnddecay\nEnd\n")
    DEC_AFTER = ("# the shape is taken from <name>'s fit to the full data set of the last run period here\n"
                 "# Author: <name> and a long remark about the decay model and the form factors used in this file\n"
                 "Decay B0\n1.0 K+ pi- PHSP;\nEnddecay\nEnd\n")
    PY = "from Golfwick import tables  # loader\n"

    def plant(self):
        with open(os.path.join(self.agents, "forms.md"), "w") as f:
            f.write(self.DOC)
        with open(os.path.join(self.root, "dec", "B0_forms.dec"), "w") as f:
            f.write(self.DEC)
        os.makedirs(os.path.join(self.root, "py"), exist_ok=True)
        with open(os.path.join(self.root, "py", "load.py"), "w") as f:
            f.write(self.PY)

    def test_forms_and_long_author_line_replaced_code_left(self):
        self.plant()
        rc, out, err = self.apply("--sample", "10")
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "forms.md")) as f:
            self.assertEqual(f.read(), self.DOC_AFTER)
        with open(os.path.join(self.root, "dec", "B0_forms.dec")) as f:
            self.assertEqual(f.read(), self.DEC_AFTER)
        with open(os.path.join(self.root, "py", "load.py")) as f:
            self.assertEqual(f.read(), self.PY)              # "from X import" is code

    def test_form_counts_by_tree(self):
        self.plant()
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        forms = self.totals()["attribution_forms_by_tree"]
        self.assertEqual(forms["agents"], {"possessive": 2, "from": 1, "by": 1})
        self.assertEqual(forms["root"], {"possessive": 1})
        self.assertIn("attribution forms replaced (P26) agents: possessive 2, from 1, by 1", out)

    def test_sample_left_cell(self):
        self.plant()
        rc, out, err = S.run_cli(*(["--names", S.NAMES] + S.MEMBERSHIP + [
            "--root", self.root, "--agents", self.agents, "--ledger", self.ledger,
            "--sample", "10"]))
        self.assertEqual(rc, 0, out + err)
        with open(os.path.splitext(self.ledger)[0] + ".sample.txt") as f:
            text = f.read()
        self.assertIn("== cell: LEFT kind=agents class=ambiguous context=comment/prose", text)
        # P33: in the outputs an ambiguous token is masked even inside a
        # hyphenated compound ("re-derivations" -> "[-left-]-derivations")
        self.assertIn("LEFT   agents:./forms.md:5: The [-left-] MINIMIS rule and the "
                      "[-left-]-derivations stay; use [-left-](a, b) here.", text)
        self.assertFalse(S.TOKEN_RX.search(text))
        self.assertFalse(S.AMB_RX.search(text))


class P27Citations(Base):
    DOC = ("Bravoson et al., Phys. Rev. D 72, 012004 (2005), arXiv:0503.01234\n"
           "Maintainer: Bravoson\n")

    def plant(self):
        with open(os.path.join(self.agents, "refs.md"), "w") as f:
            f.write(self.DOC)

    def test_flag_off_citation_line_treated_as_today(self):
        self.plant()
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "refs.md")) as f:
            self.assertEqual(f.read(), "<name> et al., Phys. Rev. D 72, 012004 (2005), "
                                       "arXiv:0503.01234\nMaintainer: <name>\n")

    def test_flag_on_citation_left_and_counted_maintainer_replaced(self):
        self.plant()
        rc, out, err = self.apply("--citations-published")
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "refs.md")) as f:
            self.assertEqual(f.read(), "Bravoson et al., Phys. Rev. D 72, 012004 (2005), "
                                       "arXiv:0503.01234\nMaintainer: <name>\n")
        self.assertEqual(self.totals()["citation_left_by_tree"], {"agents": 1})
        self.assertIn("citation (published authorship) left: agents 1", out)
        post = [r for r in self.ledger_rows() if r["kind"] == "post_check"
                and r["tree"] == "agents"][0]
        self.assertEqual(post["unambiguous_left_outside_source"], 0)
        self.assertEqual(post["citation_left_excused"], 1)

    def test_citation_patterns(self):
        mod = S.load_module()
        for yes in ("Nucl. Phys. B 145, 420", "see hep-ph/0105024", "Smith et al. 2004",
                    "JHEP 05 (2006) 026", "arXiv:2208.08573", "Phys.Lett. B 592, 1 (2004)"):
            self.assertTrue(mod.CITATION.search(yes), yes)
        for no in ("Physics was fun in 2004", "the B 145 mode", "et alia"):
            self.assertFalse(mod.CITATION.search(no), no)


class P28RunsCitationSpansLeftCells(Base):
    def test_run_after_an_anchor(self):
        """(a) the attribution context extends over a run of listed tokens
        separated by commas, "and", "&" or "/" after "by "/"from " or a
        possessive anchor."""
        with open(os.path.join(self.agents, "runs.md"), "w") as f:
            f.write("anything else in this table is from Golfwick,Indiason,Re and Max as before\n"
                    "the Golfwick & Indiason's tables were used for every mode in the fit here\n")
        with open(os.path.join(self.root, "dec", "B0_runs.dec"), "w") as f:
            f.write("# (2) anything else is from Golfwick,Indiason,Re\nEnd\n")
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "runs.md")) as f:
            self.assertEqual(f.read(),
                             "anything else in this table is from <name>,<name>,<name> and <name> as before\n"
                             "the <name> & <name>'s tables were used for every mode in the fit here\n")
        with open(os.path.join(self.root, "dec", "B0_runs.dec")) as f:
            self.assertEqual(f.read(), "# (2) anything else is from <name>,<name>,<name>\nEnd\n")
        # every token of the run is replaced BY THE RUN (its anchor's form), not by
        # proximity to a neighbour this pass replaced
        forms = self.totals()["attribution_forms_by_tree"]
        self.assertEqual(forms["agents"], {"from": 4, "possessive": 2})
        self.assertEqual(forms["root"], {"from": 3})

    def test_citation_group_only(self):
        """(b) with the flag only the name run right before the citation
        pattern is left; a token elsewhere on the line keeps its rules."""
        with open(os.path.join(self.agents, "refs.md"), "w") as f:
            f.write("tables from Golfwick, the model as in A. Bravoson and C. Deltason et al., "
                    "Phys. Rev. D 72, 012004 (2005)\n"
                    "Kiloson's tables were used throughout; the model follows the result of "
                    "Charlot, Nucl. Phys. B 145, 420\n")
        rc, out, err = self.apply("--citations-published")
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "refs.md")) as f:
            self.assertEqual(f.read(),
                             "tables from <name>, the model as in A. Bravoson and C. Deltason et al., "
                             "Phys. Rev. D 72, 012004 (2005)\n"
                             "<name>'s tables were used throughout; the model follows the result of "
                             "Charlot, Nucl. Phys. B 145, 420\n")
        self.assertEqual(self.totals()["citation_left_by_tree"], {"agents": 3})

    def test_left_cells_in_the_cell_list_with_ten_lines(self):
        with open(os.path.join(self.agents, "many.md"), "w") as f:
            for i in range(12):
                f.write("line %d: the Golfwick table and max(x) are used here\n" % i)
        rc, out, err = S.run_cli(*(["--names", S.NAMES] + S.MEMBERSHIP + [
            "--root", self.root, "--agents", self.agents, "--ledger", self.ledger,
            "--sample", "3"]))
        self.assertEqual(rc, 0, out + err)
        with open(os.path.splitext(self.ledger)[0] + ".sample.txt") as f:
            text = f.read()
        # identifier: the 12 planted lines plus the base fixture's record r5
        self.assertIn("== cell: LEFT kind=agents class=identifier context=comment/prose "
                      "(sampled 10 of 13 lines", text)
        self.assertIn("== cell: LEFT kind=agents class=ambiguous context=comment/prose "
                      "(sampled 10 of 12 lines", text)
        self.assertIn("  cell LEFT kind=agents class=identifier context=comment/prose: 13 line(s)",
                      text)                                    # in the cell index
        self.assertEqual(text.count("LEFT   agents:./many.md:"), 20)
        self.assertFalse(S.TOKEN_RX.search(text))
        self.assertFalse(S.AMB_RX.search(text))


class P29NearDateLeadPlaceholderSubject(Base):
    DEC = ("# D* production - Golfwick July 19, 2002\n"
           "# further update October 26, 2004 Indiason\n"
           "# a long remark about every mode in this table and the next (Golfwick, July 26, 2000) and more\n"
           "# the model as revised in the last release of the generator code (Max, March 13, 2001\n"
           "# Golfwick - change eta production for all the modes in this file and the next ones too\n"
           "# STV; Indiason: model doesn't exist\n"
           "# 3-body Re Golfwick [email redacted] - Oct 15, 2002\n"
           "# changed Golfwick 4/38/00 ok\n"
           "# Golfwick intersperses modes with the charmless ones in the lower part of the table\n"
           "# Max intersperses modes with the charmless ones in the lower part of the table\n"
           "Decay B0\n1.0 K+ pi- PHSP;\nEnddecay\nEnd\n")
    DEC_AFTER = ("# D* production - <name> July 19, 2002\n"
                 "# further update October 26, 2004 <name>\n"
                 "# a long remark about every mode in this table and the next (<name>, July 26, 2000) and more\n"
                 "# the model as revised in the last release of the generator code (<name>, March 13, 2001\n"
                 "# <name> - change eta production for all the modes in this file and the next ones too\n"
                 "# STV; <name>: model doesn't exist\n"
                 "# 3-body <name> <name> [email redacted] - Oct 15, 2002\n"
                 "# changed <name> 4/38/00 ok\n"
                 "# <name> intersperses modes with the charmless ones in the lower part of the table\n"
                 "# Max intersperses modes with the charmless ones in the lower part of the table\n"
                 "Decay B0\n1.0 K+ pi- PHSP;\nEnddecay\nEnd\n")

    def test_six_shapes_and_the_subject_form(self):
        with open(os.path.join(self.root, "dec", "B0_p29.dec"), "w") as f:
            f.write(self.DEC)
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.root, "dec", "B0_p29.dec")) as f:
            self.assertEqual(f.read(), self.DEC_AFTER)
        t = self.totals()
        # the ambiguous sentence subject is this pass's residual class, by count
        self.assertEqual(t["subject_left_ambiguous_by_tree"], {"root": 1})
        self.assertIn("ambiguous sentence-subject left (residual class): root 1", out)
        rules = t["attribution_rules_by_tree"]["root"]
        self.assertTrue(all(rules.get(k, 0) > 0 for k in ("date", "lead", "placeholder",
                                                           "subject")), rules)

    def test_placeholder_rule_is_a_fixpoint(self):
        """A soft token next to a name THIS pass replaces is taken in the same
        run; a second run changes nothing."""
        path = os.path.join(self.root, "dec", "B0_fix.dec")
        with open(path, "w") as f:
            f.write("# notes on the Re Bravoson tables kept here for the record of the release\nEnd\n")
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(path) as f:
            self.assertEqual(f.read(), "# notes on the <name> <name> tables kept here for the "
                                       "record of the release\nEnd\n")
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.totals()["files_changed"], 0)

    def test_same_shapes_in_record_prose_fields(self):
        with open(os.path.join(self.agents, "p29.jsonl"), "w") as f:
            f.write('{"id": "z1", "note": "# D* production - Golfwick July 19, 2002"}\n'
                    '{"id": "z2", "note": "STV; Indiason: model does not exist"}\n'
                    '{"id": "z3", "note": "3-body Re Golfwick [email redacted] - Oct 15, 2002"}\n')
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "p29.jsonl")) as f:
            self.assertEqual(f.read(),
                             '{"id": "z1", "note": "# D* production - <name> July 19, 2002"}\n'
                             '{"id": "z2", "note": "STV; <name>: model does not exist"}\n'
                             '{"id": "z3", "note": "3-body <name> <name> [email redacted] - Oct 15, 2002"}\n')

    def test_dates_regardless_of_calendar(self):
        mod = S.load_module()
        for d in ("4/38/00", "4-28-00", "July 19, 2002", "July 19 2002", "October 26, 2004",
                  "Oct 15, 2002"):
            self.assertTrue(mod.DATE.search(d), d)


class P30HeaderBoxesDatesLeadsJournals(Base):
    DEC = ("# Golfwick Indiason                      #\n"
           "# 6 sep 00 Golfwick Indiason  (IHB AWG)        #\n"
           "# Golfwick Indiason  (IHB WG4)        #\n"
           "# STV; # Golfwick: model doesn't exist\n"
           "1.0 K+ pi- PHSP; #Indiason: STV does not exist yet\n"
           "Decay B0\n1.0 K+ pi- PHSP;\nEnddecay\nEnd\n")
    DEC_AFTER = ("# <name> <name>                      #\n"
                 "# 6 sep 00 <name> <name>  (IHB AWG)        #\n"
                 "# <name> <name>  (IHB WG4)        #\n"
                 "# STV; # <name>: model doesn't exist\n"
                 "1.0 K+ pi- PHSP; #<name>: STV does not exist yet\n"
                 "Decay B0\n1.0 K+ pi- PHSP;\nEnddecay\nEnd\n")

    def test_header_box_and_lead_after_a_second_marker(self):
        with open(os.path.join(self.root, "dec", "B0_box.dec"), "w") as f:
            f.write(self.DEC)
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.root, "dec", "B0_box.dec")) as f:
            self.assertEqual(f.read(), self.DEC_AFTER)

    def test_day_month_year_dates(self):
        mod = S.load_module()
        for d in ("6 sep 00", "18 jun 01", "01 Jun 2004", "28 Sept 2003", "13/Jun/04"):
            self.assertTrue(mod.DATE.fullmatch(d), d)

    def test_journal_misspellings_form_a_citation_group(self):
        with open(os.path.join(self.agents, "refs2.md"), "w") as f:
            f.write("Alphonzo, Charlot, and Julietta,Phy Rev D 61 (200) 114510\n")
        rc, out, err = self.apply("--citations-published")
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "refs2.md")) as f:
            self.assertEqual(f.read(), "Alphonzo, Charlot, and Julietta,Phy Rev D 61 (200) 114510\n")
        self.assertEqual(self.totals()["citation_left_by_tree"], {"agents": 3})
        # citation groups are printed under their own label; "left unambiguous"
        # stays the residue figure
        self.assertRegex(out, r"tree agents \(agents\): .*; left unambiguous 0, ambiguous \d+, "
                              r"identifier \d+; citation 3")
        self.assertIn("left outside source code: agents unambiguous 0,", out)
        mod = S.load_module()
        for j in ("Phy Rev D 61", "Phys Rev D 61", "Phys. Rev. D 61", "PRD 61", "PRL 92",
                  "Phys Lett B 592", "Nucl Phys B 145", "Z Phys C 30", "JHEP 05", "EPJC 71"):
            self.assertTrue(mod.CITATION.search(j), j)

    def test_month_token_inside_a_date_left_not_residual(self):
        out_ = self.out
        lists = []
        for src, extra in ((S.NAMES, "Jun\n"), (S.UNAMB, ""), (S.AMBIG, "Jun\n"), (S.IDENT, "")):
            dst = os.path.join(out_, "p30_" + os.path.basename(src))
            with open(src) as f, open(dst, "w") as g:
                g.write(f.read() + extra)
            lists.append(dst)
        with open(os.path.join(self.root, "dec", "B0_jun.dec"), "w") as f:
            f.write("# Golfwick 13/Jun/04 retuned the fractions of all the modes in the table\nEnd\n")
        rc, out, err = S.run_cli("--names", lists[0], "--unambiguous-names", lists[1],
                                 "--ambiguous-names", lists[2], "--identifier-names", lists[3],
                                 "--root", self.root, "--agents", self.agents,
                                 "--ledger", self.ledger, "--manifest-out", self.manifest,
                                 "--readme-out", self.readme, "--apply")
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.root, "dec", "B0_jun.dec")) as f:
            self.assertEqual(f.read(), "# <name> 13/Jun/04 retuned the fractions of all the "
                                       "modes in the table\nEnd\n")
        rows = [r for r in self.ledger_rows() if r["kind"] == "code_left"
                and r["file"] == "root:./dec/B0_jun.dec"]
        self.assertEqual([(r["where"], r["membership"]) for r in rows], [("in_date", "ambiguous")])


class P31FourForms(Base):
    MD = ("Many thanks to Golfwick and Indiason for the tables used in this analysis chapter.\n"
          "The tables are courtesy of Max for the whole of the analysis in this long chapter.\n"
          "the fits of g.Golfwick were used for all the modes in this long analysis chapter\n"
          "the fits of J. Indiason were used for all the modes in this long analysis chapter\n"
          "see http://www.example.org/~golfwick/tables for the full set of tables in this chapter\n"
          "V00-04-72 Golfwick Indiason fixed the branching fractions of the charmless modes\n"
          "      Golfwick 10M event run with the new tag for all the modes in this chapter\n"
          "e.g. Max is not a name here and stays as it is in this long sentence of the chapter\n")
    MD_AFTER = ("Many thanks to <name> and <name> for the tables used in this analysis chapter.\n"
                "The tables are courtesy of <name> for the whole of the analysis in this long chapter.\n"
                "the fits of g.<name> were used for all the modes in this long analysis chapter\n"
                "the fits of J. <name> were used for all the modes in this long analysis chapter\n"
                "see http://www.example.org/~<name>/tables for the full set of tables in this chapter\n"
                "V00-04-72 <name> <name> fixed the branching fractions of the charmless modes\n"
                "      <name> 10M event run with the new tag for all the modes in this chapter\n"
                "e.g. Max is not a name here and stays as it is in this long sentence of the chapter\n")

    def test_four_forms_in_prose(self):
        with open(os.path.join(self.agents, "p31.md"), "w") as f:
            f.write(self.MD)
        with open(os.path.join(self.root, "dec", "B0_p31.dec"), "w") as f:
            f.write("# fixed Golfwick 17/2\nEnd\n")
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "p31.md")) as f:
            self.assertEqual(f.read(), self.MD_AFTER)
        with open(os.path.join(self.root, "dec", "B0_p31.dec")) as f:
            self.assertEqual(f.read(), "# fixed <name> 17/2\nEnd\n")


class P32ForceAndSpare(Base):
    def setUp(self):
        Base.setUp(self)
        with open(os.path.join(self.agents, "notes32.md"), "w") as f:
            f.write("The Golfwick and Max tables are used here in this chapter of the note\n"
                    "no listed token on this line at all\n")
        self.force = os.path.join(self.out, "force.txt")
        self.spare = os.path.join(self.out, "spare.txt")
        with open(self.force, "w") as f:
            f.write("# operator closure (invented)\nnotes32.md:1\ndec/B0_fixture.dec:6\n"
                    "nofile.txt:3\nnotes32.md:99\nnotes32.md:2\n")
        with open(self.spare, "w") as f:
            f.write("dec/B0_fixture.dec:2\n")

    def test_force_spare_counts_stale_and_cells(self):
        rc, out, err = self.apply("--force-lines", self.force, "--spare-lines", self.spare,
                                  "--sample", "10")
        self.assertEqual(rc, 0, out + err)
        with open(os.path.join(self.agents, "notes32.md")) as f:
            self.assertEqual(f.read().split("\n")[0],
                             "The <name> and <name> tables are used here in this chapter of the note")
        dec = self.read("dec/B0_fixture.dec")
        self.assertEqual(dec[1], "# Author: Alphonzo Bravoson 2004-05-12")   # spared
        self.assertEqual(dec[5], "Alias Indiason K+")                         # code: never forced
        t = self.totals()
        self.assertEqual(t["force_lines"], {"entries": 5, "applied": 2, "stale": 3, "tokens": 2})
        self.assertEqual(t["spare_lines"], {"entries": 1, "applied": 1, "stale": 0, "tokens": 2})
        stale = sorted(r["reason"] for r in self.ledger_rows() if r["kind"] == "force_stale")
        self.assertEqual(stale, ["no_listed_token", "no_such_file", "no_such_line"])
        self.assertIn("force-lines: 5 entries, 2 applied, 3 stale, 2 tokens forced", out)
        self.assertIn("spare-lines: 1 entries, 1 applied, 0 stale, 2 tokens spared", out)
        with open(os.path.splitext(self.ledger)[0] + ".sample.txt") as f:
            text = f.read()
        self.assertIn("== cell: FORCED", text)
        self.assertIn("== cell: SPARED", text)
        self.assertFalse(S.TOKEN_RX.search(text))
        post = [r for r in self.ledger_rows() if r["kind"] == "post_check" and r["tree"] == "root"][0]
        self.assertEqual(post["unambiguous_left_outside_source"], 0)
        self.assertEqual(post["spared_left"], 2)

    def test_line_in_both_lists_refuses(self):
        with open(self.spare, "a") as f:
            f.write("notes32.md:1\n")
        rc, out, err = self.apply("--force-lines", self.force, "--spare-lines", self.spare)
        self.assertEqual(rc, 2)
        self.assertIn("1 line(s) in both --force-lines and --spare-lines", err)


class P33MaskingInOutputs(Base):
    def test_left_line_compounds_masked_in_the_sample(self):
        with open(os.path.join(self.root, "src", "EvtGen", "p33.cc"), "w") as f:
            f.write("int x = 0; // 0: Ali-Golfwick model = 1, Golfwick model = 2, "
                    "Golfwick/Indiason and Golfwick99 too\n")
        rc, out, err = S.run_cli(*(["--names", S.NAMES] + S.MEMBERSHIP + [
            "--root", self.root, "--agents", self.agents, "--ledger", self.ledger,
            "--sample", "10"]))
        self.assertEqual(rc, 0, out + err)
        with open(os.path.splitext(self.ledger)[0] + ".sample.txt") as f:
            text = f.read()
        self.assertIn("LEFT   root:./src/EvtGen/p33.cc:1: int x = 0; // 0: Ali-[-left-] model = 1, "
                      "[-left-] model = 2, [-left-]/[-left-] and [-left-]99 too", text)
        low = text.lower()
        for tok in S.TOKENS:                         # the substring form: no word boundary
            self.assertNotIn(tok.lower(), low, tok)
        with open(self.ledger) as f:
            low = f.read().lower()
        for tok in ("alphonzo", "bravoson", "charlot", "deltason", "echoway", "foxtrotson",
                    "julietta", "kiloson", "mikel"):  # unambiguous: never in the ledger
            self.assertNotIn(tok, low, tok)

    def test_path_with_a_token_inside_a_longer_run_is_masked(self):
        d = os.path.join(self.root, "people", "Bravoson99")
        os.makedirs(d)
        with open(os.path.join(d, "n.txt"), "w") as f:
            f.write("# by Golfwick\n")
        rc, out, err = self.apply()
        self.assertEqual(rc, 1, out + err)        # degraded: a token-bearing path
        files = [r.get("file") for r in self.ledger_rows()]
        self.assertIn("root:./people/<name>99/n.txt", files)
        self.assertEqual(self.totals()["paths_with_listed_token"], 1)

    def test_output_guard_uses_the_substring_form(self):
        mod = S.load_module()
        nl = mod.NameList.load(S.NAMES)
        nl.set_membership(S.UNAMB, S.AMBIG, S.IDENT)
        for txt in ("Ali-Bravoson", "Bravoson99", "x/Bravoson/y"):
            with self.assertRaises(mod.Refuse):
                nl.guard_text(txt, "the ledger", corpus=False, field="file")
        nl.guard_text("models/Golfwick99/x.dec", "the ledger", corpus=False, field="file")
        with self.assertRaises(mod.Refuse):
            nl.guard_text("Ali-Golfwick", "the sample", corpus=True, field="line text")
        # ambiguous tokens: masked/refused when not joined to a letter
        with self.assertRaises(mod.Refuse):
            nl.guard_text("re-derivations", "the sample", corpus=True, field="line text")
        nl.guard_text("there is nothing here", "the sample", corpus=True, field="line text")


class P34ExitReasons(Base):
    def test_spare_only_run_exits_zero_and_says_so(self):
        spare = os.path.join(self.out, "spare.txt")
        with open(spare, "w") as f:
            f.write("dec/B0_fixture.dec:2\ntxt/notes.txt:2\n")
        rc, out, err = self.dry_with("--spare-lines", spare)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(out.strip().splitlines()[-1],
                         "exit 0: no refusal, no residue (operator-spared tokens 4, excused)")
        rc, out, err = self.apply("--spare-lines", spare)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(out.strip().splitlines()[-1],
                         "exit 0: no refusal, no residue (operator-spared tokens 4, excused)")

    def dry_with(self, *extra):
        return S.run_cli(*(["--names", S.NAMES] + S.MEMBERSHIP + [
            "--root", self.root, "--agents", self.agents, "--ledger", self.ledger] + list(extra)))

    def test_every_nonzero_exit_names_its_reason(self):
        with open(os.path.join(self.agents, "bad.jsonl"), "w") as f:
            f.write('{"note": "# by Golfwick", "id": }\n')
        rc, out, err = self.dry_with()
        self.assertEqual(rc, 1)
        self.assertEqual(out.strip().splitlines()[-1],
                         "exit 1: records refused 1 (not_json 1)")
        rc, out, err = self.apply()
        self.assertEqual(rc, 1)
        self.assertEqual(out.strip().splitlines()[-1],
                         "exit 1: records refused 1 (not_json 1); residue 1")


class P35IdentifierNamedFiles(Base):
    def plant(self):
        with open(os.path.join(self.root, "src", "EvtGen", "EvtBtoXsgammaGolfwick.cc"), "w") as f:
            f.write("// the model of Golfwick and the tables\nint a;\n")
        with open(os.path.join(self.root, "src", "EvtGen", "EvtBravosonModel.cc"), "w") as f:
            f.write("// by Golfwick\nint b;\n")

    def test_identifier_named_written_as_is_unambiguous_named_masked(self):
        self.plant()
        rc, out, err = self.apply("--sample", "10")
        self.assertEqual(rc, 1, out + err)
        t = self.totals()
        self.assertEqual(t["identifier_named_files"], 1)
        self.assertEqual(t["paths_with_listed_token"], 1)
        files = set(r.get("file") for r in self.ledger_rows())
        self.assertIn("root:./src/EvtGen/EvtBtoXsgammaGolfwick.cc", files)
        self.assertIn("root:./src/EvtGen/Evt<name>Model.cc", files)
        self.assertIn("identifier-named files: 1 (written as is; not an exit condition)", out)
        self.assertEqual(out.strip().splitlines()[-1],
                         "exit 1: file paths carrying an unambiguous token 1 (masked); "
                         "identifier-named files 1 (written as is)")
        # the diagnosis: each token-bearing path's hits by names-file line and
        # class, inside a longer word or not -- never the token
        hits = {r["file"]: r["hits"] for r in self.ledger_rows() if r["kind"] == "path_tokens"}
        self.assertEqual(hits["root:./src/EvtGen/EvtBtoXsgammaGolfwick.cc"],
                         [{"class": "identifier", "inside_word": True, "names_line": 6}])
        self.assertEqual(hits["root:./src/EvtGen/Evt<name>Model.cc"],
                         [{"class": "unambiguous", "inside_word": True, "names_line": 3}])
        with open(os.path.splitext(self.ledger)[0] + ".sample.txt") as f:
            text = f.read()
        self.assertIn("root:./src/EvtGen/EvtBtoXsgammaGolfwick.cc:1", text)
        self.assertNotIn("Bravoson", text)

    def test_identifier_named_only_exits_zero(self):
        with open(os.path.join(self.root, "src", "EvtGen", "EvtBtoXsgammaGolfwick.cc"), "w") as f:
            f.write("// by Golfwick\nint a;\n")
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(out.strip().splitlines()[-1],
                         "exit 0: no refusal, no residue; identifier-named files 1 (written as is)")


class P20P21Sample(Base):
    def run_sample(self, *extra):
        with open(os.path.join(self.agents, "rationale.md"), "w") as f:
            f.write(P19P22Ambiguous.DOC)
        return S.run_cli(*(["--names", S.NAMES] + S.MEMBERSHIP + [
            "--root", self.root, "--agents", self.agents, "--ledger", self.ledger,
            "--sample", "3"] + list(extra)))

    def sample(self):
        with open(os.path.splitext(self.ledger)[0] + ".sample.txt") as f:
            return f.read()

    def test_sample_cells_after_before_never_a_token(self):
        rc, out, err = self.run_sample()
        self.assertEqual(rc, 0, out + err)
        text = self.sample()
        self.assertIn("up to 10 changed line(s) per (tree kind, token class, context)", text)
        self.assertIn("== cell: kind=root class=unambiguous context=a", text)
        self.assertIn("== cell: kind=agents class=ambiguous context=b", text)
        self.assertIn("AFTER  root:./dec/B0_fixture.dec:3: # <name> <name> 2004-05-12", text)
        self.assertIn("BEFORE root:./dec/B0_fixture.dec:3: # [--] [--] 2004-05-12", text)
        # a left identifier on a sampled line is masked too
        self.assertIn("1.0   [-left-] pi-   PHSP; # tuned by [--] [--]", text)
        self.assertFalse(S.TOKEN_RX.search(text), S.TOKEN_RX.search(text))
        self.assertFalse(S.AMB_RX.search(text), S.AMB_RX.search(text))
        # dry run: the tree is untouched
        self.assertEqual(S.snapshot(self.root), self.before_root)

    def test_hit_table_flags(self):
        rc, out, err = self.run_sample("--outlier-bound", "5")
        self.assertEqual(rc, 0, out + err)
        text = self.sample()
        self.assertIn("== top 20 names-file lines by replaced occurrences", text)
        rows = [l for l in text.splitlines() if l.startswith("  names line ")]
        self.assertTrue(rows)
        self.assertLessEqual(len(rows), 20)
        self.assertTrue([l for l in rows if "FLAG: count above 5" in l])
        self.assertTrue([l for l in rows if "class ambiguous" in l and "ambiguous class" in l])
        self.assertTrue([l for l in rows if "class unambiguous" in l and "FLAG" not in l])


class P23ScopedGuard(Base):
    """The output guard refuses an UNAMBIGUOUS token anywhere, and an
    ambiguous or identifier token only in a value that carries corpus text."""

    def lists(self, extra_amb=(), extra_unamb=()):
        """Copies of the fixture lists with INVENTED extras appended."""
        out = []
        for src, extra in ((S.NAMES, tuple(extra_amb) + tuple(extra_unamb)),
                           (S.UNAMB, extra_unamb), (S.AMBIG, extra_amb), (S.IDENT, ())):
            dst = os.path.join(self.out, os.path.basename(src))
            with open(src) as f, open(dst, "w") as g:
                g.write(f.read() + "".join(t + "\n" for t in extra))
            out.append(dst)
        return out

    def run_with(self, lists):
        names, unamb, amb, ident = lists
        return S.run_cli("--names", names, "--unambiguous-names", unamb, "--ambiguous-names",
                         amb, "--identifier-names", ident, "--root", self.root, "--agents",
                         self.agents, "--ledger", self.ledger, "--sample", "10")

    def test_dictionary_word_in_labels_and_identifier_in_path_are_written(self):
        # "Prose" is an INVENTED ambiguous token equal to a ledger label
        # (fclass/where "prose"); a model identifier names a directory
        lists = self.lists(extra_amb=("Prose",))
        d = os.path.join(self.root, "models", "Indiason")
        os.makedirs(d)
        with open(os.path.join(d, "notes.txt"), "w") as f:
            f.write("written by Alphonzo Bravoson\n")
        rc, out, err = self.run_with(lists)
        self.assertEqual(rc, 0, out + err)
        rows = self.ledger_rows()
        self.assertIn("prose", [r.get("fclass") for r in rows])
        files = [r.get("file") for r in rows]
        self.assertIn("root:./models/Indiason/notes.txt", files)   # written as is
        self.assertEqual(self.totals()["paths_with_listed_token"], 0)

    def test_unambiguous_name_in_a_path_is_still_masked(self):
        d = os.path.join(self.root, "people", "Bravoson")
        os.makedirs(d)
        with open(os.path.join(d, "notes.txt"), "w") as f:
            f.write("# by Golfwick\n")
        rc, out, err = self.run_with(self.lists())
        self.assertEqual(rc, 1, out + err)                 # degraded: a token-bearing path
        rows = [r for r in self.ledger_rows() if r.get("file", "").startswith("root:./people/")]
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["file"], "root:./people/<name>/notes.txt")
            self.assertIn("path_sha256", r)
        self.assertEqual(self.totals()["paths_with_listed_token"], 1)

    def test_refusal_names_field_and_class_never_the_token(self):
        mod = S.load_module()
        names, unamb, amb, ident = self.lists(extra_amb=("Prose",))
        nl = mod.NameList.load(names)
        nl.set_membership(unamb, amb, ident)
        # tool labels carrying an ambiguous word pass
        nl.guard_rows([{"kind": "code_left", "where": "prose", "fclass": "prose"}], "the ledger")
        # an unambiguous token in any field refuses, naming field and class
        with self.assertRaises(mod.Refuse) as cm:
            nl.guard_rows([{"kind": "skipped", "reason": "binary Bravoson"}], "the ledger")
        msg = str(cm.exception)
        self.assertIn("field reason", msg)
        self.assertIn("class unambiguous", msg)
        self.assertNotIn("Bravoson", msg)
        # an ambiguous token in CORPUS text (a sample line body) refuses
        with self.assertRaises(mod.Refuse) as cm:
            nl.guard_text("the max of it", "the sample", corpus=True, field="line text")
        self.assertIn("class ambiguous", str(cm.exception))
        self.assertIn("field line text", str(cm.exception))


class P4Ledger(Base):
    def test_dry_run_tree_identical_and_ledger_has_would_rows(self):
        rc, out, err = self.dry()
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(S.snapshot(self.root), self.before_root)
        self.assertEqual(S.snapshot(self.agents), self.before_agents)
        rows = self.ledger_rows()
        would = [r for r in rows if r["kind"] == "would_change_line"]
        self.assertGreater(len(would), 10)            # positive control
        self.assertFalse([r for r in rows if r["kind"] == "changed_line"])
        self.assertFalse(os.path.exists(self.readme))

    def test_dry_run_ledger_equals_apply_ledger_modulo_mode(self):
        self.dry()
        dry = self.ledger_rows()
        self.apply()
        app = [r for r in self.ledger_rows()
               if r["kind"] not in ("residue", "post_check", "check_records")]
        norm = lambda rows: [dict(r, kind=r["kind"].replace("would_change_line", "changed_line"),
                                  mode=None) for r in rows]
        self.assertEqual(norm(dry), norm(app))

    def test_ledger_never_carries_a_token(self):
        for fn in (self.dry, self.apply):
            rc, out, err = fn()
            with open(self.ledger) as f:
                text = f.read()
            for tok in S.TOKENS:
                self.assertNotIn(tok.lower(), text.lower(), tok)
                self.assertNotIn(tok.lower(), (out + err).lower(), tok)

    def test_ledger_rows_and_totals(self):
        rc, out, err = self.apply()
        rows = self.ledger_rows()
        t = self.totals()
        changed = [r for r in rows if r["kind"] == "changed_line"]
        for r in changed:
            self.assertEqual(set(r), {"kind", "file", "line", "count", "context", "ftype",
                                      "fclass"})
            self.assertTrue(re.fullmatch(r"[abdglmopqrsy]+", r["context"]), r["context"])
        self.assertEqual(t["lines_changed"], len(changed))
        self.assertEqual(t["tokens_replaced"], sum(r["count"] for r in changed))
        self.assertEqual(t["files_changed"], len(set(r["file"] for r in changed)))
        self.assertEqual(t["code_occurrences_left"],
                         len([r for r in rows if r["kind"] == "code_left"]))
        self.assertEqual(t["files_seen"], t["files_scanned"] + t["files_skipped_binary"]
                         + t["files_skipped_not_regular"])
        self.assertEqual(t["files_skipped_binary"], 1)
        for k in ("files_scanned", "files_changed", "lines_changed", "tokens_replaced",
                  "code_occurrences_left"):
            self.assertIn(k, t)


class P5Manifest(Base):
    def test_single_manifest_header_rows_and_change_field(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        after = S.snapshot(self.root)
        man = sorted(fn for fn in os.listdir(self.out) if fn.startswith("SNAPSHOT_MANIFEST"))
        self.assertEqual(man, ["SNAPSHOT_MANIFEST_pass5.csv"])          # ONE file
        with open(self.manifest, newline="") as f:
            text = f.read()
        self.assertEqual(text.split("\n")[0], S.MANIFEST_HEADER)
        rows = {r["path"]: r for r in csv.DictReader(text.splitlines())}
        changed = sorted(k for k in after if after[k] != self.before_root[k])
        self.assertEqual(sorted(rows), changed)                        # snapshot-relative
        per_file = {}
        for r in self.ledger_rows():
            if r["kind"] == "changed_line" and r["file"].startswith("root:./"):
                f = per_file.setdefault(r["file"][len("root:./"):], [0, 0])
                f[0] += 1
                f[1] += r["count"]
        for path, r in rows.items():
            self.assertEqual(r["sha256_pass4"], S.sha(self.before_root[path]))
            self.assertEqual(r["sha256_pass5"], S.sha(after[path]))
            self.assertEqual(r["change"], "n_redacted_lines=%d;n_tokens=%d" % tuple(per_file[path]))
        with open(self.readme) as f:
            para = f.read()
        self.assertIn("files changed by the fifth pass (%d):" % len(changed), para)
        for p in changed:
            self.assertIn("  ./" + p + "\n", para)
        for tok in S.TOKENS:
            self.assertNotIn(tok.lower(), para.lower())

    def test_path_outside_any_class_directory(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        with open(self.manifest, newline="") as f:
            paths = [r["path"] for r in csv.DictReader(f)]
        self.assertIn("README_EXTRA", paths)
        self.assertIn("pdt.table", paths)
        by = self.totals()["by_class"]
        self.assertEqual({c: v["files_changed"] for c, v in by.items() if v["files_changed"]},
                         S.EXPECTED_CLASSES)
        self.assertIn("class root: 4 files changed", out)
        self.assertIn("class src/EvtGen: 1 files changed", out)

    def test_old_keys_default_is_old_only(self):
        mod = S.load_module()
        self.assertEqual(mod.OLD_KEYS, ("old",))


class P6Neutrality(Base):
    def test_broken_replacer_in_dec_refuses_whole_run_naming_the_file(self):
        mod = S.load_module()
        mod.hash_comment_spans = lambda line: [(0, len(line))]   # a broken replacer
        # every token unambiguous, so the broken replacer reaches the code token
        rc, out, err = S.run_inproc(mod, *(["--names", S.NAMES] + S.old_form_lists(self.out)), "--root", self.root,
                                    "--ledger", self.ledger, "--manifest-out",
                                    self.manifest, "--readme-out", self.readme, "--apply")
        self.assertEqual(rc, 2)
        self.assertIn("parser neutrality", err)
        self.assertRegex(err, r"root:\./(dec|pdl)/")
        self.assertEqual(S.snapshot(self.root), self.before_root)
        self.assertFalse(os.path.exists(self.ledger))
        self.assertFalse(os.path.exists(self.readme))

    def test_neutral_form(self):
        mod = S.load_module()
        self.assertEqual(mod.neutral_form("Decay B0 # by X\n  1.0  K+   PHSP;\n"),
                         "Decay B0 1.0 K+ PHSP;")


class P7PostScan(Base):
    def test_post_scan_zero_residue_reported(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        post = [r for r in self.ledger_rows() if r["kind"] == "post_check"]
        self.assertEqual({p["tree"] for p in post}, {"root", "agents"})
        for p in post:
            self.assertEqual(p["comment_attribution"], 0)
        self.assertIn("residue 0", out)

    def test_refused_record_is_residue_and_exit_nonzero(self):
        with open(os.path.join(self.agents, "bad.jsonl"), "w") as f:
            # not valid JSON -> the only record P12 still refuses
            f.write('{"note": "# by Golfwick", "id": }\n')
        rc, out, err = self.apply()
        self.assertEqual(rc, 1, out + err)
        rows = self.ledger_rows()
        self.assertTrue([r for r in rows if r["kind"] == "record_refused"
                         and r["reason"] == "not_json"])
        with open(os.path.join(self.agents, "bad.jsonl")) as f:
            self.assertEqual(f.read(), '{"note": "# by Golfwick", "id": }\n')
        post = [r for r in rows if r["kind"] == "post_check" and r["tree"] == "agents"][0]
        self.assertEqual(post["comment_attribution"], 1)


class P9Quotes(Base):
    def test_quoted_copies_receive_the_identical_substitution(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        md = self.read("DOC_fixture.md", self.agents)
        self.assertEqual(md[8], "The snapshot line `# <name> <name> 2004-05-12` is the header form.")
        self.assertEqual(md[9], "See `1.0   Indiason pi-   PHSP; # tuned by <name> <name>` in the table.")
        self.assertGreater(self.totals()["tokens_replaced_quoted_copies"], 0)

    def check(self):
        return S.run_cli("--check-records", self.root, self.agents)

    def test_check_records_zero_after_the_full_pass(self):
        self.apply()
        rc, out, err = self.check()
        self.assertEqual(rc, 0, out + err)
        self.assertIn("3 quoted items checked, 0 UNMATCHED", out)

    def test_snapshot_only_leaves_one_unmatched(self):
        # the broken form: redact the snapshot, not the agents files
        rc, out, err = self.apply(agents=False)
        self.assertEqual(rc, 0, out + err)
        rc, out, err = self.check()
        self.assertEqual(rc, 1, out + err)
        self.assertIn("3 quoted items checked, 1 UNMATCHED", out)
        self.assertIn("records.jsonl:1 $.fixes[0].old", out)

    def test_check_records_before_the_pass_matches(self):
        rc, out, err = self.check()
        self.assertEqual(rc, 0, out + err)

    def test_nothing_checked_is_not_a_pass(self):
        empty = os.path.join(self.base, "norec")
        os.makedirs(empty)
        rc, out, err = S.run_cli("--check-records", self.root, empty)
        self.assertEqual(rc, 1)


class P10Hunks(Base):
    def test_hunks_counted_and_zero(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        t = self.totals()
        self.assertEqual(t["c_files_changed"], 2)
        self.assertGreater(t["c_hunks"], 0)
        self.assertEqual(t["c_hunks_outside_comment"], 0)
        self.assertIn("hunks outside comment context 0", out)

    def test_replacement_in_code_is_refused_by_the_hunk_proof(self):
        mod = S.load_module()
        mod._inside = lambda s, e, spans: True          # eligibility broken: code too
        only_cc = os.path.join(self.base, "cc_only")
        os.makedirs(only_cc)
        with open(os.path.join(only_cc, "x.cc"), "w") as f:
            f.write("int Golfwick = 0; // by Golfwick\n")
        rc, out, err = S.run_inproc(mod, "--names", S.NAMES, "--root", only_cc,
                                    "--ledger", self.ledger, "--manifest-out",
                                    self.manifest, "--readme-out", self.readme, "--apply")
        self.assertEqual(rc, 2)
        self.assertIn("P10: 1 diff hunk(s) outside comment context", err)
        with open(os.path.join(only_cc, "x.cc")) as f:
            self.assertEqual(f.read(), "int Golfwick = 0; // by Golfwick\n")


class P11Figures(Base):
    def test_whitelist_line_counts_and_manifest_diff_verdict(self):
        rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        t = self.totals()
        wl = t["whitelist_line_counts"]
        self.assertEqual(wl["root:./src/EvtGen/testEvtGen.cc"], {"before": 1950, "after": 1950})
        self.assertEqual(wl["root:./src/EvtGenBase/EvtDecayTable.cc"],
                         {"before": 430, "after": 430})
        # build v3 (full listing before) and v4 (after) manifests
        after = S.snapshot(self.root)
        v3, v4 = os.path.join(self.out, "v3.csv"), os.path.join(self.out, "v4.csv")
        for path, snap in ((v3, self.before_root), (v4, after)):
            with open(path, "w", newline="") as f:
                w = csv.writer(f, lineterminator="\n")
                w.writerow(["path", "class", "sha256_original", "sha256_snapshot"])
                for rel in sorted(snap):
                    w.writerow(["./" + rel, rel.split("/")[0], "x", S.sha(snap[rel])])
        rc, out, err = S.run_cli("--manifest-diff", v3, v4, "--ledger", self.ledger)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("verdict: EQUAL", out)
        self.assertIn("member diff %d" % t["files_changed_root"], out)
        # a negative control: v4 against itself is a zero diff -> NOT EQUAL
        rc, out, err = S.run_cli("--manifest-diff", v4, v4, "--ledger", self.ledger)
        self.assertEqual(rc, 1)
        self.assertIn("NOT EQUAL", out)

    def test_post_check_split(self):
        rc, out, err = self.apply()
        root = [r for r in self.ledger_rows()
                if r["kind"] == "post_check" and r["tree"] == "root"][0]
        self.assertEqual(root["comment_attribution"], 0)
        self.assertTrue(root["consistent"])
        self.assertEqual(root["tokens_any_context"], root["code_context"])
        # independent count of tokens left anywhere in the text files
        n = 0
        for rel, b in S.snapshot(self.root).items():
            if b"\0" not in b:
                n += len(S.TOKEN_RX.findall(b.decode("latin-1")))
        self.assertEqual(root["tokens_any_context"], n)
        self.assertGreater(root["frozen_hit_lines_excused"], 0)


# Oracle provenance (the package convention, tests/_support.py): every test here
# restates an item of the name-redaction contract the loop wrote and ruled
# before the tool was built; the class name carries the item number.
def _tag_all():
    from _support import oracle
    for name, obj in list(globals().items()):
        if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
            for attr in dir(obj):
                fn = getattr(obj, attr)
                if attr.startswith("test") and callable(fn) and not hasattr(fn, "__oracle__"):
                    oracle("spec", "the loop's name-redaction contract, %s" % name)(fn)


_tag_all()


if __name__ == "__main__":
    unittest.main()
