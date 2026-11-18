"""The local RULINGS file: the only way an exemption enters an instance (X3).

The reference instance carried its rulings inside the scanner's code. The
package ships none of them; an instance writes its own in a RULINGS file
(RULINGS.template), and these tests pin the file's contract: one row per
line, refusal on a malformed row with its line number, never required, exact
addresses matched exactly, domain classes anchored at the tail.
"""
import os
import shutil
import tempfile
import unittest

from _support import oracle, addr, site, AT, assign, run_tool, clean_env
import pii_scan

DATE = "2026-11-17"


def row(target, verdict="EXEMPT", reason="test ruling", ruler="privacy owner", date=DATE):
    return " | ".join((target, verdict, reason, ruler, date))


def emails(text):
    return [f for f in pii_scan.scan_text(text) if f[0] == "email"]


class Base(unittest.TestCase):
    def setUp(self):
        pii_scan.set_rulings([])
        self.tmp = tempfile.mkdtemp(prefix="pii-rulings-")

    def tearDown(self):
        pii_scan.set_rulings([])
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rules(self, *rows):
        pii_scan.set_rulings(pii_scan.parse_rulings("\n".join(rows) + "\n"))

    def write(self, name, text):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="ascii") as fh:
            fh.write(text)
        return p


class Parsing(Base):

    @oracle("spec", "X3: the RULINGS.template form is five '|'-separated fields "
            "-- class:value, EXEMPT or BLOCK, reason, ruler role, date -- with "
            "blank lines and '#' comments allowed.")
    def test_the_template_form_parses(self):
        text = ("# a comment\n\n"
                + row("address:" + addr("desk", "service")) + "\n"
                + row("domain:" + site("agency"), "BLOCK") + "\n"
                + row("literal:-home-" + "brew-") + "\n")
        rows = pii_scan.parse_rulings(text)
        self.assertEqual([(r.lineno, r.cls, r.verdict) for r in rows],
                         [(3, "address", "EXEMPT"), (4, "domain", "BLOCK"),
                          (5, "literal", "EXEMPT")])

    @oracle("spec", "X3: a malformed row REFUSES and names its line number; the "
            "file never half-loads. Every way a row can be malformed is "
            "enumerated here.")
    def test_every_malformed_row_refuses_with_its_line_number(self):
        good = row("address:" + addr("desk", "service"))
        bad_rows = [
            ("too few fields", "address:x | EXEMPT | reason | role"),
            ("too many fields", good + " | extra"),
            ("no class prefix", row(addr("desk", "service"))),
            ("unknown class", row("person:" + addr("desk", "service"))),
            ("bad verdict", row("address:" + addr("desk", "service"), "ALLOW")),
            ("lower-case verdict", row("address:" + addr("desk", "service"), "exempt")),
            ("empty reason", row("address:" + addr("desk", "service"), reason="")),
            ("empty ruler", row("address:" + addr("desk", "service"), ruler="")),
            ("bad date", row("address:" + addr("desk", "service"), date="17.11.2026")),
            ("month 13", row("address:" + addr("desk", "service"), date="2026-13-01")),
            ("address without @", row("address:desk." + site("service"))),
            ("address is a domain", row("address:" + site("service"))),
            ("two addresses", row("address:" + addr("a", "x") + "," + addr("b", "x"))),
            ("domain with @", row("domain:" + addr("desk", "service"))),
            ("domain with wildcard", row("domain:*." + site("service"))),
            ("empty domain", row("domain:")),
            ("short literal", row("literal:abc")),
        ]
        for why, bad in bad_rows:
            with self.subTest(why=why):
                text = "# header\n" + good + "\n\n" + bad + "\n" + good + "\n"
                with self.assertRaises(pii_scan.RulingsError) as cm:
                    pii_scan.parse_rulings(text)
                self.assertEqual(cm.exception.lineno, 4, why)
                self.assertIn("line 4", str(cm.exception))

    @oracle("spec", "X3: the CLI refuses (exit 2) on a malformed RULINGS file "
            "and names the line; via --rulings and via PII_RULINGS alike, and "
            "for every tool that reads it.")
    def test_the_cli_refuses_a_malformed_file_with_exit_2(self):
        bad = self.write("RULINGS", row("address:" + addr("desk", "service")) + "\nnot a row\n")
        target = self.write("doc.txt", "clean text\n")
        for script, args in (("pii_scan.py", [target, "--gate"]),
                             ("pii_scrub.py", [target, "--quarantine",
                                               os.path.join(self.tmp, "q")]),
                             ("scrub_envelopes.py", ["--structure", target,
                                                     "--quarantine",
                                                     os.path.join(self.tmp, "q"),
                                                     "--label", "x"]),
                             ("pii_gate.py", ["--egress", "--gate", "--corpus",
                                              "T:" + os.path.join(self.tmp, "*.json")])):
            with self.subTest(script=script, via="--rulings"):
                r = run_tool(script, *(args + ["--rulings", bad]))
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("line 2", r.stderr)
            with self.subTest(script=script, via="PII_RULINGS"):
                r = run_tool(script, *args, env=clean_env(PII_RULINGS=bad))
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("line 2", r.stderr)

    @oracle("spec", "X3: the file is never required -- absent means no local "
            "exemptions; but a path that is SET and does not exist refuses, "
            "because a mistyped path silently dropping every ruling is an "
            "unauditable state.")
    def test_absent_means_none_and_a_missing_configured_path_refuses(self):
        target = self.write("doc.txt", "clean text\n")
        r = run_tool("pii_scan.py", target, "--gate")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("local rulings       : 0", r.stdout)
        r = run_tool("pii_scan.py", target, "--gate",
                     "--rulings", os.path.join(self.tmp, "nope"))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(pii_scan.configure_rulings(None, environ={}), [])

    @oracle("spec", "X3: --rulings wins over PII_RULINGS, and the environment "
            "variable alone is honoured by the CLI.")
    def test_the_environment_variable_and_the_flag(self):
        a = addr("desk", "service")
        target = self.write("doc.txt", "write to %s\n" % a)
        rules = self.write("RULINGS", row("address:" + a) + "\n")
        empty = self.write("EMPTY", "# no rows\n")
        self.assertEqual(run_tool("pii_scan.py", target, "--gate").returncode, 1)
        self.assertEqual(run_tool("pii_scan.py", target, "--gate",
                                  env=clean_env(PII_RULINGS=rules)).returncode, 0)
        self.assertEqual(run_tool("pii_scan.py", target, "--gate", "--rulings", empty,
                                  env=clean_env(PII_RULINGS=rules)).returncode, 1)


class AddressRulings(Base):

    @oracle("human", "the reference instance's exact-address rulings, restored "
            "through the mechanism: an address ruled by its data subject is "
            "excused in every position, case-insensitively, with a "
            "sentence-final period.")
    def test_an_exact_address_ruling_excuses_that_address(self):
        a = addr("jdoe", "home-domain")
        self.rules(row("address:" + a))
        for blob in ("account whose contact email is %s, controlled by" % a,
                     "route to %s (or personal)" % a.upper(),
                     a, "reach %s." % a):
            with self.subTest(blob=blob):
                self.assertEqual(emails(blob), [])

    @oracle("human", "the reference's refutation cases for the exact-address "
            "rulings, on synthetic values: an exact address is matched exactly "
            "and NEVER as a domain -- a sibling mailbox, a longer local part, a "
            "spoofed tail all still block.")
    def test_an_exact_address_ruling_does_not_over_reach(self):
        a = addr("jdoe", "home-domain")
        self.rules(row("address:" + a))
        for blob, why in (
                ("write to sam" + AT + site("home-domain") + " today", "different local part"),
                ("write to xjdoe" + AT + site("home-domain"), "longer local part"),
                ("write to j.jdoe" + AT + site("home-domain"), "dotted longer local part"),
                (a + ".evil." + "zz here", "spoofed tail on the ruled address"),
                (a + "x here", "label continues"),
                ("jdoe" + AT + "mail." + site("home-domain"), "subdomain: not the exact address"),
                (addr("a.person", "lab"), "unrelated address, control")):
            with self.subTest(why=why):
                self.assertTrue(emails(blob), why)

    @oracle("spec", "a BLOCK row is recorded and creates no exemption.")
    def test_a_block_row_exempts_nothing(self):
        a = addr("desk", "service")
        self.rules(row("address:" + a, "BLOCK"))
        self.assertTrue(emails("write to " + a))
        self.assertEqual(len(pii_scan.active_rulings()), 1)


class DomainRulings(Base):
    GOV = "gov"

    @oracle("human", "the reference instance's government-TLD class ruling, "
            "restored through the mechanism: every address whose domain IS or "
            "ENDS IN the ruled domain is excused, including subdomains, upper "
            "case and a sentence-final period.")
    def test_a_domain_ruling_excuses_the_class(self):
        self.rules(row("domain:" + self.GOV))
        g = "no-such-agency." + self.GOV
        for blob in ("Program contact: officer" + AT + "mail." + g + " -- the",
                     "first.last" + AT + g,
                     ("Someone" + AT + g).upper(),
                     "grants info at helpdesk" + AT + "grants." + g + ".",
                     "reply to pm" + AT + g + ", then"):
            with self.subTest(blob=blob):
                self.assertEqual(emails(blob), [])

    @oracle("external", "X3, the reference's refutation cases on synthetic "
            "domains: a domain-class exemption is ANCHORED at the tail by two "
            "lookaheads. Each shape below is outside the ruled class (DNS label "
            "semantics, RFC 1034 section 3.1) and must still block in a full "
            "scan.")
    def test_a_domain_ruling_is_anchored_at_the_tail(self):
        self.rules(row("domain:" + self.GOV))
        cases = [
            ("mail to someone" + AT + "agency.gov.evil." + "zz now", ".gov.evil.<tld>: spoofed subdomain"),
            ("write to clerk" + AT + "office.gov.uk-shaped." + "zz today", ".gov.uk-shaped"),
            ("write to clerk" + AT + "office.gov." + "zz today", ".gov.<cc>: not the tail"),
            ("write to desk" + AT + "state.govt." + "zz now", ".govt is not .gov"),
            ("email press" + AT + "agency.nongov today", ".nongov ends with gov"),
            ("reach ops" + AT + "agency.gov2." + "zz now", ".gov2: a digit continues the label"),
            ("mail someone" + AT + "agency.government." + "zz here", ".gov is a prefix of the label"),
            ("someone" + AT + "governance." + "zz", "'gov' is not the TLD"),
            (addr("a.person", "lab"), "unrelated address, control"),
        ]
        for blob, why in cases:
            with self.subTest(why=why):
                self.assertTrue(emails(blob), why)

    @oracle("external", "the same refutation cases asserted on the ruling "
            "matcher ALONE, including the contract's literal "
            "'.gov.evil.example' shape: in a full scan the RFC 2606 rule would "
            "excuse an .example address anyway, so the anchoring is proven on "
            "the ruling pattern directly.")
    def test_the_ruling_pattern_alone_rejects_the_spoof_shapes(self):
        pat = pii_scan.ruling_pattern(pii_scan.parse_rulings(row("domain:gov")))
        ok = ["x" + AT + "agency.gov", "x" + AT + "a.b.gov", "x" + AT + "agency.gov."]
        spoof = ["x" + AT + "agency.gov.evil.example", "x" + AT + "agency.gov.uk",
                 "x" + AT + "state.govt.nz", "x" + AT + "agency.nongov",
                 "x" + AT + "agency.gov2.net", "x" + AT + "agency.gov-x.net"]
        for s in ok:
            with self.subTest(ok=s):
                m = pat.match(s)
                self.assertTrue(m and m.group(0).rstrip(".") == s.rstrip("."), s)
        for s in spoof:
            with self.subTest(spoof=s):
                m = pat.match(s)
                self.assertFalse(m, s)

    @oracle("spec", "a domain ruling written with a leading dot means the same "
            "class; it is normalised, not refused.")
    def test_a_leading_dot_is_normalised(self):
        rows = pii_scan.parse_rulings(row("domain:." + site("agency")))
        self.assertEqual(rows[0].value, site("agency"))


class LiteralRulings(Base):

    @oracle("human", "the reference instance's enumerated exact-string rulings "
            "(a call-valued assignment ruled safe; a form-token attribute; a "
            "non-person flattened home token) restored through `literal:` -- "
            "and ONLY the exact text: a sibling of the same shape still blocks.")
    def test_a_literal_ruling_excuses_exactly_its_text(self):
        safe = "secret = getpass" + ".getpass"
        self.rules(row("literal:" + safe), row("literal:-home-" + "brew-"))
        line = safe + '("JWT Secret: ")'
        self.assertEqual([k for k, *_ in pii_scan.scan_text(line)], [])
        self.assertEqual([k for k, *_ in pii_scan.scan_text("in -home-" + "brew-x/bin")], [])
        self.assertIn("secret_assignment",
                      [k for k, *_ in pii_scan.scan_text("secret = mystery" + "_decoder()")])
        self.assertIn("home_path",
                      [k for k, *_ in pii_scan.scan_text("in -home-" + "jdoe-x/bin")])

    @oracle("metamorphic", "the scrubber honours the same rulings: what the "
            "scanner excuses the scrubber leaves byte-identical, and what it "
            "does not the scrubber removes (one definition, two callers).")
    def test_the_scrubber_honours_the_rulings(self):
        import pii_scrub
        safe = "secret = getpass" + ".getpass"
        a = addr("desk", "service")
        self.rules(row("literal:" + safe), row("address:" + a))
        text = "%s()\nwrite to %s or %s\n" % (safe, a, addr("jdoe", "lab"))
        out, removed = pii_scrub.scrub_text(text)
        self.assertIn(safe + "()", out)
        self.assertIn(a, out)
        self.assertNotIn(addr("jdoe", "lab"), out)
        self.assertEqual([k for k, _ in removed], ["address"])


if __name__ == "__main__":
    unittest.main()
