"""The ingress scanner. Carried from the reference instance's suite, re-fixtured.

Every case was drawn there from personal data actually found in a corpus;
here each value is a synthetic stand-in of the same SHAPE (tests/_support.py
explains the convention). Tests whose subject was an instance ruling that the
package does not ship are carried INVERTED: they now prove the shipped scanner
blocks the class, and test_rulings.py proves a local ruling restores it.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from _support import (oracle, addr, site, home, orcid, privkey_armour,
                      gitlab_token, assign, run_tool, AT)
import pii_scan


def kinds(text):
    return [k for k, *_ in pii_scan.scan_text(text)]


def emails(text):
    return [f for f in pii_scan.scan_text(text) if f[0] == "email"]


def homes(text):
    return [f for f in pii_scan.scan_text(text) if f[0] == "home_path"]


class Base(unittest.TestCase):
    def setUp(self):
        pii_scan.set_rulings([])
        self.tmp = tempfile.mkdtemp(prefix="pii-test-")

    def tearDown(self):
        pii_scan.set_rulings([])
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def write(self, name, text):
        p = self.path(name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p


class Detectors(Base):

    @oracle("external", "RFC 5322 addr-spec in its common form: a local part, an "
            "@, and a dotted domain. An address is personal data under GDPR "
            "Art.4(1) regardless of where it appears.")
    def test_email_addresses_are_found_anywhere(self):
        for blob in ("contact %s for details" % addr("a.person", "lab"),
                     "# Email: %s" % addr("someone", "inst"),
                     "<a href='mailto:%s'>x</a>" % addr("x.y", "collab")):
            with self.subTest(blob=blob):
                self.assertIn("email", kinds(blob))

    @oracle("external", "ORCID is a 16-digit identifier in 4-4-4-4 form with an "
            "optional X checksum; it identifies one researcher.")
    def test_orcid_is_found(self):
        self.assertIn("orcid", kinds("ORCID " + orcid()))

    @oracle("spec", "pii_scan contract: confidential review roles leak the "
            "individual named. Enumerated from an internal-note publication "
            "template, which renders Referees and PC Reader onto every internal "
            "note's title page.")
    def test_confidential_role_fields_are_found(self):
        txt = ("Document: EXAMPLE-NOTE-2024-017\n"
               "Referees: C. Reviewer, D. Checker\n"
               "PC Reader: F. Committee\n")
        k = set(kinds(txt))
        self.assertIn("role_field:referees", k)
        self.assertIn("role_field:pc reader", k)

    @oracle("spec", "pii_scan contract: the line is published authorship versus "
            "confidential review, NOT names versus not-names. Author names on a "
            "paper are already public and load-bearing for retrieval.")
    def test_published_authorship_is_not_flagged(self):
        txt = "Authors: A. Author, B. K. Writer\nProponents: B. Person\n"
        self.assertFalse([k for k in kinds(txt) if k.startswith("role_field")])

    @oracle("external", "PEM armour for private key material is a fixed string "
            "defined by RFC 7468.")
    def test_private_key_material_is_found(self):
        self.assertIn("private_key", kinds(privkey_armour()))

    @oracle("external", "GitLab personal access tokens carry the fixed prefix "
            "`glpat-`; this is GitLab's own documented format.")
    def test_gitlab_tokens_are_found(self):
        self.assertIn("gitlab_token", kinds("GITLAB_TOKEN=" + gitlab_token()))

    @oracle("metamorphic", "redaction must be a fixed point: scanning "
            "already-redacted output must find nothing, or every scrubbed corpus "
            "re-fails its own gate forever.")
    def test_redaction_placeholders_are_not_re_flagged(self):
        txt = ("mail REDACTED@example.invalid\nORCID 0000-0000-0000-0000\n"
               "path /home/REDACTED/x\n")
        self.assertEqual(pii_scan.scan_text(txt), [])

    @oracle("metamorphic", "an SSH URL host is not a mailbox. Rewriting "
            "git@<host>: would corrupt a working clone instruction while "
            "protecting nobody.")
    def test_ssh_url_hosts_are_not_addresses(self):
        self.assertEqual(pii_scan.scan_text(
            "git clone git" + AT + "git." + site("lab") + ":group/x.git"), [])

    @oracle("external", "RFC 2606 and RFC 6761: example.com/.net/.org and the "
            ".example/.invalid/.test/.localhost namespaces are reserved by the "
            "IETF precisely so they can never identify a real person.")
    def test_rfc2606_reserved_namespaces_are_benign(self):
        clean = ("write to user@example.com or admin@sub.example.org,\n"
                 "or test@host.invalid and dev@ci.test for the harness\n")
        self.assertFalse(emails(clean))
        # POSITIVE CONTROL: a non-reserved address must still fire, or the
        # generalisation blew a hole instead of encoding a standard.
        self.assertTrue(emails("mail me: " + addr("a.person", "lab")))

    @oracle("external", "RFC 2142 reserves role mailbox names (postmaster, "
            "webmaster, abuse, noc...) for functions, and POSIX reserves "
            "root/daemon/nobody for the system: a role address identifies a "
            "machine or duty, never a person.")
    def test_role_and_system_mailboxes_are_benign(self):
        clean = ("problems? mail root" + AT + "svd." + site("det")
                 + " or postmaster" + AT + site("inst") + "\n")
        self.assertFalse(emails(clean))
        # POSITIVE CONTROL: a personal mailbox at the same host still fires.
        self.assertTrue(emails("mail " + addr("a.person", "inst")))

    @oracle("metamorphic", "scrub output must pass the gate that motivated it -- "
            "on EVERY detector path. The ROLE_FIELD loop once skipped the "
            "exemption check, so the scrub's own '[address removed]' placeholder "
            "re-failed the gate forever, and docstring parameter descriptions "
            "(contact=None) were findings.")
    def test_role_field_respects_benign_and_ignores_parameter_docs(self):
        code = ("contact=None,\n"
                "contact : [address removed]\n"
                "    Contact email address used in the plots.\n"
                "self.contact = contact\n")
        self.assertFalse([k for k in kinds(code) if k.startswith("role_field")])
        # POSITIVE CONTROL: a role field naming an individual still fires.
        self.assertTrue([k for k in kinds("Referees: M. Someone, J. Other\n")
                         if k.startswith("role_field")])

    @oracle("spec", "an exemption excuses a finding only by COVERING it, never by "
            "proximity. The ROLE_FIELD path once searched a +/-24 window, so an "
            "SSH URL on the previous line excused a Referees: line -- a false "
            "NEGATIVE in the fail-closed module.")
    def test_role_field_benign_requires_coverage_not_proximity(self):
        hot = ("clone: git" + AT + "git." + site("lab") + ":x\n"
               "Referees: J. Smith, K. Jones\n")
        self.assertTrue([k for k in kinds(hot) if k.startswith("role_field")],
                        "SSH-URL proximity excused a confidential role line")
        control = "Referees: J. Smith, K. Jones\n"
        self.assertTrue([k for k in kinds(control) if k.startswith("role_field")])
        scrubbed = "contact : [address removed]\n"
        self.assertFalse([k for k in kinds(scrubbed) if k.startswith("role_field")])


class GateCli(Base):

    @oracle("spec", "pii_scan contract: --gate must fail closed. A caller that "
            "cannot interpret a finding must stop, not proceed.")
    def test_gate_exits_nonzero_on_any_finding(self):
        self.write("doc.txt", "Referees: A. Person\ncontact %s\n" % addr("b", "c"))
        r = run_tool("pii_scan.py", self.tmp, "--gate")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("GATE FAILED", r.stderr)

    @oracle("spec", "pii_scan contract: a report of personal data must not itself "
            "contain the personal data. A sanitisation record on the reference "
            "instance reproduced the address it redacted until that was caught.")
    def test_the_report_does_not_reproduce_the_values(self):
        self.write("d.txt", "mail %s here\n" % addr("secret.person", "lab"))
        rep = self.path("r.json")
        r = run_tool("pii_scan.py", self.tmp, "--report", rep)
        with open(rep, encoding="ascii") as fh:
            body = fh.read()
        self.assertNotIn("secret.person", body)
        self.assertNotIn("secret.person", r.stdout + r.stderr)
        self.assertTrue(json.loads(body))

    @oracle("spec", "fail closed on the TARGET too: a mistyped path scanned "
            "nothing and the reference gate exited 0. The package refuses (2).")
    def test_a_missing_target_refuses_rather_than_passing(self):
        r = run_tool("pii_scan.py", self.path("no-such-dir"), "--gate")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)


class Extractable(Base):

    @oracle("metamorphic", "a binary container whose CONTENT is text must be "
            "extracted before scanning. A PDF carrying an address returned zero "
            "findings until this was fixed -- the exact false negative the module "
            "exists to prevent.")
    def test_pdf_content_is_extracted_not_skipped(self):
        if not shutil.which("pdftotext") or not shutil.which("pdflatex"):
            self.skipTest("pdftotext/pdflatex not available")
        tex = self.write("d.tex", "\\documentclass{article}\\begin{document}"
                         "Corresponding author: " + addr("a.person", "uni")
                         + "\\end{document}")
        subprocess.run(["pdflatex", "-interaction=nonstopmode", "-output-directory",
                        self.tmp, tex], capture_output=True, timeout=120)
        pdf = self.path("d.pdf")
        if not os.path.exists(pdf):
            self.skipTest("could not build a test pdf")
        hits = pii_scan.scan_extractable(pdf, ".pdf")
        self.assertIn("email", [k for k, *_ in hits])

    @oracle("spec", "pii_scan contract: a file that cannot be read has NOT been "
            "cleared. Reporting an extraction failure as a clean result is the "
            "failure mode in disguise.")
    def test_unextractable_file_is_reported_not_passed(self):
        bad = self.path("broken.pdf")
        with open(bad, "wb") as fh:
            fh.write(b"not really a pdf at all")
        hits = pii_scan.scan_extractable(bad, ".pdf")
        self.assertTrue(hits)
        self.assertEqual(hits[0][0], "unscannable")

    @oracle("human", "representational failure mode, observed on the reference "
            "instance: an address whose '@' is HTML-entity-encoded (&#64; / "
            "&#x40;) in a fetched page passed the ingress scan and surfaced at "
            "egress after a converter decoded it. HTML/HTM sources are "
            "entity-decoded before scanning; plain text is not altered.")
    def test_html_entity_encoded_addresses_are_found_at_ingress(self):
        dom = site("example-lab")
        p = self.write("page.html", "<p>contact: someone&#64;%s or other&#x40;%s</p>"
                       % (dom, dom))
        self.assertEqual([k for k, *_ in pii_scan.scan_file(p)].count("email"), 2)
        q = self.write("note.txt", "literal someone&#64;%s stays literal" % dom)
        self.assertEqual([k for k, *_ in pii_scan.scan_file(q)], [])


class HomeDirectories(Base):
    """Mount-prefixed two-component home directories (/gpfs/home/<group>/<user>).
    All user and group names are FAKE (jsmith/mygroup/onlygroup), constructed to
    match the SHAPE of two real leaks the reference instance had."""

    @oracle("human", "ruled BLOCKING on the reference instance: on "
            "/gpfs/home/<group>/<user>/... the one-component model redacted the "
            "GROUP and left the USER exposed, and the (?!REDACTED) lookahead then "
            "hid that residue from every later scan. Measured twice there.")
    def test_gpfs_home_directory_redacts_both_group_and_user(self):
        txt = "luminosity file at cluster:/gpfs" + home("mygroup", "jsmith", "lumi", "runs") + " lumi\n"
        hits = homes(txt)
        self.assertTrue(hits, "the two-component home path must fire")
        self.assertTrue(any("mygroup" in s and "jsmith" in s for _k, _l, s, _w in hits), hits)

    @oracle("human", "the EXACT residual state found already embedded on the "
            "reference instance: a prior single-component scrub redacted the "
            "group and left '/home/REDACTED/<user>'. The detector must catch "
            "comp2 even when comp1 already reads REDACTED.")
    def test_gpfs_home_directory_catches_a_half_scrubbed_residue(self):
        txt = "cluster:/gpfs" + home("REDACTED", "jsmith", "lumi", "runs") + " lumi\n"
        self.assertTrue(homes(txt), "the surviving username must still be caught")

    @oracle("metamorphic", "redaction must be a fixed point: once BOTH components "
            "read REDACTED there is nothing left to find.")
    def test_gpfs_home_directory_fully_redacted_is_not_reflagged(self):
        txt = "cluster:/gpfs/home/REDACTED/REDACTED/lumi/runs lumi\n"
        self.assertFalse(homes(txt))

    @oracle("human", "the ruling's own refutation requirement: '<host>/home/<user>/<dir>' "
            "URL paths where /home/ IS the root keep component 2 as a directory, "
            "not a person.")
    def test_url_rooted_home_paths_stay_single_component(self):
        for url, second in (("https://" + site("inst") + home("jsmith", "data"), "data"),
                            ("https://www." + site("uni") + home("jsmith", "nota12.ps"),
                             "nota12.ps")):
            with self.subTest(url=url):
                hits = homes("see %s for the ntuples\n" % url)
                self.assertTrue(hits, "the URL-rooted username itself must still fire")
                self.assertFalse(any(second in s for _k, _l, s, _w in hits))

    @oracle("human", "the mount-prefix trigger must be ANCHORED the same way a "
            "domain exemption's tail is -- a literal '/gpfs' immediately before "
            "'/home/', never a suffix or substring match.")
    def test_gpfs_lookalike_prefixes_do_not_trigger_two_component_mode(self):
        for txt in ("path /notgpfs" + home("jsmith", "output.root") + " here\n",
                    "at s3://mygpfs" + home("jsmith", "output.root") + " now\n"):
            with self.subTest(txt=txt):
                hits = homes(txt)
                self.assertTrue(hits)
                self.assertFalse(any("output" in s for _k, _l, s, _w in hits))

    @oracle("human", "narrowest measured shape: '/nfs/home/<group>/<user>' was proposed as a "
            "sibling but never observed on the reference instance; extending the "
            "rule would be inventing a shape. A first /nfs/home/ finding is a "
            "fresh decision.")
    def test_nfs_home_is_not_yet_a_measured_shape(self):
        hits = homes("output at /nfs" + home("mygroup", "jsmith", "output.root") + " today\n")
        self.assertTrue(hits, "the group component alone still fires via the plain rule")
        self.assertFalse(any("jsmith" in s for _k, _l, s, _w in hits))

    @oracle("human", "a bare mount reference with no second component carries no "
            "username; the plain single-component rule covers whatever IS there.")
    def test_gpfs_mount_with_only_one_component_falls_back_to_plain_rule(self):
        self.assertTrue(homes("mounted at /gpfs" + home("onlygroup") + "\n"))

    @oracle("human", "ruled BLOCKING on the reference instance. Every kind absent "
            "from pii_gate.RECORDED blocks by construction; this pins the ruling "
            "as a fact about the actual set.")
    def test_home_path_is_blocking_in_the_egress_gate(self):
        import pii_gate
        self.assertNotIn("home_path", pii_gate.RECORDED)
        self.assertTrue(pii_gate.is_blocking("home_path"))


class ScrubViaScan(Base):
    """Text-level scrub cases the reference kept beside the scanner tests."""

    @oracle("human", "a case the procedure leaves to the instance's privacy "
            "owner, decided on the reference instance: strip contact addresses, "
            "leave ORCIDs (published beside the author list). The default stays "
            "fail-closed.")
    def test_keep_orcid_strips_the_address_and_spares_the_identifier(self):
        import pii_scrub
        a = addr("aauthor", "uni")
        src = ("by [A. Author](%s)\n[ORCID: %s](%s)\n"
               "This thesis presents a measurement of the branching fraction.\n"
               % (a, orcid(), a))
        out, removed = pii_scrub.scrub_text(src, keep_orcid=True)
        k = {k for k, _ in removed}
        self.assertIn("address", k)
        self.assertNotIn("orcid", k)
        self.assertNotIn(a, out)
        self.assertIn(orcid(), out)
        self.assertIn("branching fraction", out)
        self.assertIn("A. Author", out)
        both, removed2 = pii_scrub.scrub_text(src)
        self.assertNotIn(orcid(), both)
        self.assertIn("orcid", {k for k, _ in removed2})

    @oracle("metamorphic", "scrubbing is idempotent and its output must pass the "
            "gate that motivated it. A scrub whose result still trips the scanner "
            "leaves the gate red forever.")
    def test_email_scrub_output_passes_the_scanner_and_is_idempotent(self):
        import pii_scrub
        src = "contact me at %s or %s for details\n" % (addr("a.person", "lab"),
                                                       addr("b.other", "inst"))
        once, r1 = pii_scrub.scrub_text(src, keep_orcid=True)
        twice, r2 = pii_scrub.scrub_text(once, keep_orcid=True)
        self.assertEqual(once, twice)
        self.assertFalse(r2, "second pass must find nothing to do")
        self.assertEqual(len(r1), 2)
        self.assertFalse(emails(once))

    @oracle("human", "on the reference instance a thesis documented a root-shell "
            "procedure including a literal host password. pii_scan DETECTED it "
            "and pii_scrub had no rule to REMOVE it -- a scanner without a "
            "matching scrub can only report a finding forever.")
    def test_credential_values_are_scrubbed_keys_kept(self):
        import pii_scrub
        src = "su - + Ent PassWord : " + "zq7xk2" + "pw [root" + AT + "node07 root] #\n"
        out, removed = pii_scrub.scrub_text(src, keep_orcid=True)
        self.assertNotIn("zq7xk2pw", out)
        self.assertIn("PassWord", out, "the key stays; only the value goes")
        self.assertIn("credential", {k for k, _ in removed})
        self.assertFalse([f for f in pii_scan.scan_text(out)
                          if f[0] == "secret_assignment"])

    @oracle("spec", "a report of personal data must not contain the personal "
            "data. The home_path branch once stored the raw matched path -- "
            "username included -- as the 'removed' detail, which --apply writes "
            "verbatim into <file>.removed.json.")
    def test_pii_scrub_home_path_detail_never_carries_the_username(self):
        import pii_scrub
        src = "cluster:/gpfs" + home("mygroup", "jsmith", "lumi", "runs") + " lumi\n"
        out, removed = pii_scrub.scrub_text(src, keep_orcid=True)
        details = [v for k, v in removed if k == "home_path"]
        self.assertTrue(details)
        for d in details:
            self.assertNotIn("jsmith", d)
            self.assertNotIn("mygroup", d)
        self.assertFalse(homes(out))
        self.assertNotIn("jsmith", out)
        self.assertNotIn("mygroup", out)


class InstanceRulingsAreNotShipped(Base):
    """Reference tests whose subject was an INSTANCE ruling, carried inverted.
    Each class below blocks in the shipped scanner; test_rulings.py shows the
    local RULINGS row that restores it for an instance that decides so."""

    @oracle("human", "X2 inversion of the reference's exact-personal-address "
            "rulings (two addresses ruled benign by their own data subject). The "
            "shipped scanner carries no personal address: a synthetic personal "
            "address in the same three positions BLOCKS.")
    def test_a_personal_address_blocks_in_the_shipped_scanner(self):
        a = addr("jdoe", "home-domain")
        for blob in ("account whose contact email is %s, controlled by" % a,
                     "route to %s (or personal)" % a.upper(),
                     a,
                     "reach %s." % a):
            with self.subTest(blob=blob):
                self.assertTrue(emails(blob), blob)

    @oracle("human", "X2 inversion of the reference's government-TLD class "
            "ruling. The shipped scanner carries no domain class: a synthetic "
            "address at a government-shaped domain BLOCKS in every position the "
            "reference exempted (subdomain, upper case, sentence-final period).")
    def test_a_government_shaped_address_blocks_in_the_shipped_scanner(self):
        g = "no-such-agency." + "gov"
        for blob in ("Program contact: officer" + AT + "mail." + g + " -- the",
                     "first.last" + AT + g,
                     ("Someone" + AT + g).upper(),
                     "grants info at helpdesk" + AT + "grants." + g + ".",
                     "reply to pm" + AT + g + ", then"):
            with self.subTest(blob=blob):
                self.assertTrue(emails(blob), blob)

    @oracle("human", "inversion of the reference's organisation-office mailbox "
            "ruling (an office whose occupant rotates). That convention is one "
            "organisation's; the shipped scanner blocks it.")
    def test_an_office_mailbox_convention_blocks_in_the_shipped_scanner(self):
        self.assertTrue(emails("write to coll-publications" + AT + site("collab")
                               + " for permissions\n"))

    @oracle("human", "inversion of the reference's call-valued-assignment "
            "dictionary (getpass, os.environ, os.getenv, and instance APIs), an "
            "instance ruling. The shipped scanner blocks a secret-named target "
            "assigned from any call, literal or not -- fail closed until an "
            "instance rules.")
    def test_call_valued_secret_assignments_block_in_the_shipped_scanner(self):
        for line in ("secret = getpass" + ".getpass(\"JWT Secret: \")",
                     "token = os" + ".getenv('SERVICE_TOKEN')",
                     "token = mystery" + "_decoder('x')"):
            with self.subTest(line=line):
                self.assertIn("secret_assignment", kinds(line))
        # and a literal secret still fires, as it always did
        self.assertIn("secret_assignment", kinds(assign("api_key", "AbC123def456GHI789jkl")))

    @oracle("human", "inversion of the reference's form-token attribute ruling "
            "(one wiki engine's CSRF attribute). Ruled by name there; the shipped "
            "scanner blocks the shape until an instance rules.")
    def test_a_form_token_attribute_blocks_in_the_shipped_scanner(self):
        line = '<html data-form-token="' + 'Ab3xY9pQ2mKt7RsL1vNc4Z' + '" lang="en">'
        self.assertIn("secret_assignment", kinds(line))

    @oracle("human", "inversion of the reference's documentation-placeholder "
            "ruling (username@host and placeholder home directories). The shipped "
            "scanner blocks them; generic SHELL-PROMPT and numeric-host local "
            "parts stay enumerated in the detectors themselves.")
    def test_documentation_placeholders_block_in_the_shipped_scanner(self):
        for t in ("ssh username" + AT + "gateway." + site("lab"),
                  "your_username" + AT + "server." + site("inst"),
                  "ls " + home("username") + "/",
                  "cd " + home("project", "tools")):
            with self.subTest(t=t):
                self.assertTrue(kinds(t), t)

    @oracle("structural", "X2: the shipped BENIGN list is the RFC 2142 role "
            "mailboxes and nothing else, and FLAT_HOMEDIR_BENIGN ships empty. "
            "Asserted on the compiled pattern's alternates so a widened list "
            "fails here as well as in the behavioural tests.")
    def test_the_shipped_exemption_list_is_role_mailboxes_only(self):
        self.assertEqual(pii_scan.FLAT_HOMEDIR_BENIGN, ())
        roles = ("root daemon nobody postmaster hostmaster webmaster abuse noc "
                 "security mailer-daemon noreply no-reply donotreply usenet news "
                 "uucp ftp").split()
        for r in roles:
            self.assertTrue(pii_scan.BENIGN.search(" %s%shost " % (r, AT)), r)
        for other in ("someone", "jdoe", "coll-office", "username", "user", "git"):
            self.assertIsNone(pii_scan.BENIGN.search(" %s%shost " % (other, AT)), other)
        self.assertEqual(pii_scan.active_rulings(), [])


class DetectorsBeyondTheCarriedSuite(Base):
    """Package-added cases for detectors the three carried reference files did
    not exercise directly (their tests lived in other reference modules that
    are not part of this package)."""

    @oracle("external", "an IPv4 dotted quad has four octets of 0..255 (RFC 791); "
            "an account on one is a reachable identity, and a version-shaped "
            "string with an octet above 255 is not an address.")
    def test_an_account_on_a_numeric_host_is_found_and_versions_are_not(self):
        self.assertIn("host_account", kinds("ssh jdoe" + AT + "192.0.2.10 then"))
        self.assertNotIn("host_account", kinds("built by build" + AT + "1.2.3.999"))
        self.assertNotIn("host_account", kinds("log in as root" + AT + "192.0.2.10"))

    @oracle("spec", "one identifier, two syntactic forms: a shell prompt carries "
            "an account name with a dotless host EMAIL can never match; generic "
            "local parts are enumerated so a tutorial prompt stays clean.")
    def test_shell_prompts_carry_account_names(self):
        self.assertIn("shell_prompt", kinds("[jdoe" + AT + "login ~]$ ls"))
        self.assertIn("shell_prompt", kinds("jdoe" + AT + "node7:~$ ls"))
        self.assertNotIn("shell_prompt", kinds("[root" + AT + "localhost ~]# ls"))

    @oracle("metamorphic", "a JSON escape letter is not part of a local part: "
            "`\\nuser@host:~$` read as text must not become the fabricated "
            "non-generic 'nuser' (scan and scrub then disagree forever).")
    def test_an_escape_letter_is_not_glued_onto_a_generic_local_part(self):
        self.assertEqual(kinds("known hosts.\\nuser" + AT + "node7:~$ ls"), [])

    @oracle("metamorphic", "JSON escapes are neutralised length-for-length, so "
            "every reported snippet occurs verbatim in the file it names.")
    def test_a_reported_snippet_occurs_verbatim_in_the_file(self):
        body = json.dumps({"t": "ssh\n" + "jsmith" + AT + "node7:~$ ls"})
        p = self.write("page.json", body)
        hits = pii_scan.scan_file(p)
        self.assertTrue(hits)
        with open(p, encoding="utf-8") as fh:
            raw = fh.read()
        for _k, _l, snip, _w in hits:
            self.assertIn(snip, raw)

    @oracle("spec", "the dash-flattened spelling of a home directory is the same "
            "identifier as the slash form; the trailing dash keeps ordinary prose "
            "('go-home-now') clean.")
    def test_a_flattened_home_directory_is_found(self):
        self.assertIn("home_path", kinds("cache at -home-" + "jdoe-project-x"))
        self.assertNotIn("home_path", kinds("time to go-home-now"))

    @oracle("human", "ruled on the reference instance on a census: a SECRET "
            "assignment that wraps to the next line and lands on a plain word "
            "is not a credential; a wrapped mixed-alphanumeric value still is.")
    def test_a_wrapped_plain_word_is_not_a_credential(self):
        self.assertNotIn("secret_assignment", kinds("the password:\nremember to"))
        self.assertIn("secret_assignment", kinds("the password:\n" + "zq7xk2" + "pw99"))

    @oracle("external", "UTF-8 is self-validating (RFC 3629) and ISO-8859-1 maps "
            "every byte; a mixed document must decode without manufacturing "
            "U+FFFD, so a pattern spanning a high byte still matches.")
    def test_a_non_utf8_byte_does_not_hide_an_address(self):
        p = self.path("mixed.txt")
        with open(p, "wb") as fh:
            fh.write(b"caf\xe9 -- write to " + addr("a.person", "lab").encode("ascii") + b"\n")
        self.assertIn("email", [k for k, *_ in pii_scan.scan_file(p)])


if __name__ == "__main__":
    unittest.main()
