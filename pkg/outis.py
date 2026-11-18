#!/usr/bin/env python3
"""outis.py -- one command: a defined corpus in, the same corpus out, stripped.

    python3 outis.py clean IN_DIR --out OUT_DIR [--rulings R] [--names N]
                     [--jobs K] [--apply] [name-tool options]

WHAT IT DOES. OUT_DIR is written as the SAME tree as IN_DIR -- every file
present at the same relative path -- with

  (a) every blocking finding of pii_scan's kinds scrubbed by pii_scrub's rules
      (contact addresses, confidential role lines, key material, access
      tokens, credential assignments, home paths, shell-prompt and
      numeric-host accounts). ORCIDs are KEPT: they are published beside the
      author list (RECORDED, never blocking);
  (b) when --names is given, every LISTED name redacted by redact_names.py
      with its three-class rule (unambiguous / ambiguous / identifier; the
      classes come from --unambiguous-names, --ambiguous-names and
      --identifier-names, or the tool's own partition of --names);
  (c) every binary file -- and every file whose content is not editable as
      text (a PDF) -- copied BYTE-FOR-BYTE and listed in the report.

IN_DIR IS NEVER WRITTEN: it is the quarantine, the original kept for audit.
Its sha256 digests are taken before the run and checked after it.
OUT_DIR may not lie inside IN_DIR (nor IN_DIR inside OUT_DIR), and may not
already exist: a run never merges into an older output.

THE RUN GATES ITS OWN OUTPUT. pii_scan over the finished tree must find no
blocking kind (RECORDED kinds such as ORCID aside), no file path or symlink
target may carry one, and -- with --names -- the name tool's post-scan
residue must be 0. If any of these fails the tree is NOT delivered at
OUT_DIR: it is left at OUT_DIR.FAILED_GATE for inspection, the report names
every file (and line), and the command exits 1.

THE RECORD, BESIDE OUT_DIR (never inside it), in OUT_DIR.outis/:

    REPORT.md          counts, the binary list, the gate verdicts; file:line
                       only, never a value
    ledger.jsonl       one row per input file (ledger.for_each): what was
                       removed, by kind and count
    summary.json       the same counts, machine-readable
    names_*            the name tool's ledger, manifest, README paragraph and,
                       with --sample N, its reviewer's sample and outlier table

DRY RUN BY DEFAULT. Without --apply the whole pipeline runs on a temporary
copy outside both trees, the record is written to OUT_DIR.outis/ (so the
name sample can be READ before anything is delivered), the temporary copy
is deleted, and OUT_DIR is not created. --apply delivers OUT_DIR.

Exit status: 0 delivered (or a dry run whose output would pass every gate);
1 the output failed a gate (named in the report); 2 could not run.
"""

import argparse
import collections
import concurrent.futures
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger
import pii_gate
import pii_scan
import pii_scrub
import redact_names

TOOL_VERSION = "outis.py 0.2.0"
FAILED_SUFFIX = ".FAILED_GATE"
META_SUFFIX = ".outis"


class Refuse(Exception):
    pass


def _real(p):
    return os.path.realpath(os.path.abspath(p))


def _inside(child, parent):
    c, p = _real(child), _real(parent)
    return c == p or c.startswith(p.rstrip(os.sep) + os.sep)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(root):
    """{relpath: ("dir"|"file"|"link"|"other", digest-or-target)} for a tree.
    Nothing is followed: a symlink is recorded by its target string."""
    out = {}
    for d, ds, fs in os.walk(root, followlinks=False):
        ds.sort()
        for name in sorted(ds) + sorted(fs):
            p = os.path.join(d, name)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                out[rel] = ("link", os.readlink(p))
            elif os.path.isdir(p):
                out[rel] = ("dir", None)
            elif os.path.isfile(p):
                out[rel] = ("file", sha256_file(p))
            else:
                out[rel] = ("other", None)
    return out


def _safe(rel):
    """A path as it may appear in the record: ASCII, and with any scanner
    finding inside the path itself replaced (a file NAMED after an address
    must not put the address into the report)."""
    s = rel.encode("ascii", "backslashreplace").decode("ascii")
    new, removed = pii_scrub.scrub_text(s, keep_orcid=True)
    return new if removed else s


# --- the per-file work (runs in a worker under --jobs) ----------------------
def _worker_init(rulings_path):
    pii_scan.configure_rulings(rulings_path)


def scrub_one(task):
    """(rel, src, dst) -> (rel, disposition, {kind: n}). Writes dst only."""
    rel, src, dst = task
    with open(src, "rb") as fh:
        raw = fh.read()
    ext = os.path.splitext(src)[1].lower()
    if ext in pii_scan.EXTRACTABLE or b"\0" in raw[:4096]:
        with open(dst, "wb") as fh:
            fh.write(raw)
        shutil.copymode(src, dst)
        return rel, ("pdf" if ext in pii_scan.EXTRACTABLE else "binary"), {}
    # surrogateescape on both sides: the only bytes changed are the ones
    # removed (pii_scrub's own rule for files it reads and writes).
    text = raw.decode("utf-8", "surrogateescape")
    new, removed = pii_scrub.scrub_file_text(src, text, keep_orcid=True)
    data = new.encode("utf-8", "surrogateescape") if removed else raw
    with open(dst, "wb") as fh:
        fh.write(data)
    shutil.copymode(src, dst)
    return rel, ("scrubbed" if removed else "clean"), dict(collections.Counter(k for k, _v in removed))


def stage_tree(in_dir, stage, inv, jobs, rulings_path):
    """Recreate the tree at `stage`; scrub text files. -> {rel: (disp, kinds)}."""
    os.makedirs(stage)
    tasks, results = [], {}
    for rel, (kind, val) in sorted(inv.items()):
        dst = os.path.join(stage, rel)
        if kind == "dir":
            os.makedirs(dst, exist_ok=True)
        elif kind == "link":
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.symlink(val, dst)
            results[rel] = ("symlink", {})
        elif kind == "file":
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            tasks.append((rel, os.path.join(in_dir, rel), dst))
        else:
            results[rel] = ("not_regular", {})
    if jobs > 1 and len(tasks) > 1:
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=jobs, initializer=_worker_init, initargs=(rulings_path,)) as ex:
            for rel, disp, kinds in ex.map(scrub_one, tasks, chunksize=8):
                results[rel] = (disp, kinds)
    else:
        for t in tasks:
            rel, disp, kinds = scrub_one(t)
            results[rel] = (disp, kinds)
    return results


def run_names(args, stage, meta):
    """Drive redact_names over the staged tree. -> (rc, report lines, ledger rows)."""
    nl = os.path.join(meta, "names_ledger.jsonl")
    argv = ["--names", args.names, "--root", stage, "--ledger", nl,
            "--manifest-out", os.path.join(meta, "names_manifest.csv"),
            "--readme-out", os.path.join(meta, "names_readme.txt"), "--apply"]
    for flag, val in (("--unambiguous-names", args.unambiguous_names),
                      ("--ambiguous-names", args.ambiguous_names),
                      ("--identifier-names", args.identifier_names),
                      ("--dictionary", args.dictionary),
                      ("--force-lines", args.force_lines),
                      ("--spare-lines", args.spare_lines)):
        if val:
            argv += [flag, val]
    if args.citations_published:
        argv.append("--citations-published")
    if args.sample:
        argv += ["--sample", str(args.sample), "--outlier-bound", str(args.outlier_bound)]
    buf = io.StringIO()
    err = io.StringIO()
    old = sys.stderr
    sys.stderr = err
    try:
        rc = redact_names.main(argv, out=buf)
    finally:
        sys.stderr = old
    rows = []
    if os.path.exists(nl):
        with open(nl, encoding="ascii") as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
    lines = buf.getvalue().splitlines() + [l for l in err.getvalue().splitlines() if l]
    return rc, lines, rows


def gate_output(stage, inv):
    """Blocking findings left in the staged tree: [(rel, line, kind)]."""
    bad = []
    found = pii_scan.scan_path(stage)
    for rel, hits in sorted(found.items()):
        for kind, line, _snip, _why in hits:
            if pii_gate.is_blocking(kind):
                bad.append((rel, line, kind))
    for rel, (kind, val) in sorted(inv.items()):
        for k, _l, _s, _w in pii_scan.scan_text(rel, "<path>"):
            if pii_gate.is_blocking(k):
                bad.append((rel, 0, "path:" + k))
        if kind == "link":
            for k, _l, _s, _w in pii_scan.scan_text(val, "<link>"):
                if pii_gate.is_blocking(k):
                    bad.append((rel, 0, "symlink_target:" + k))
    return bad


def clean(args):
    in_dir, out_dir = args.in_dir, args.out
    if not os.path.isdir(in_dir):
        raise Refuse("IN_DIR is not a directory: %s" % in_dir)
    out_dir = out_dir.rstrip(os.sep) or out_dir
    if _inside(out_dir, in_dir):
        raise Refuse("OUT_DIR lies inside IN_DIR; IN_DIR is the quarantine and is never written")
    if _inside(in_dir, out_dir):
        raise Refuse("IN_DIR lies inside OUT_DIR")
    meta = out_dir + META_SUFFIX
    failed = out_dir + FAILED_SUFFIX
    for p in (out_dir, failed):
        if os.path.lexists(p):
            raise Refuse("%s already exists; a run never merges into an older output" % p)
    if _inside(meta, in_dir):
        raise Refuse("the record directory would lie inside IN_DIR")
    if args.names and not os.path.isfile(args.names):
        raise Refuse("--names file missing")
    try:
        pii_scan.configure_rulings(args.rulings)
    except pii_scan.RulingsError as e:
        raise Refuse(str(e))
    rulings_path = args.rulings or os.environ.get(pii_scan.RULINGS_ENV) or None

    inv_before = inventory(in_dir)
    parent = os.path.dirname(_real(out_dir)) or "."
    if args.apply:
        stage = out_dir + ".partial"
        if os.path.lexists(stage):
            raise Refuse("%s exists (an interrupted run?); remove it first" % stage)
        tmp_holder = None
    else:
        tmp_holder = tempfile.mkdtemp(prefix="outis-dry-")
        stage = os.path.join(tmp_holder, "tree")
    if os.path.isdir(meta):
        shutil.rmtree(meta)             # the record of THIS run only
    os.makedirs(meta)

    try:
        results = stage_tree(in_dir, stage, inv_before, max(1, args.jobs), rulings_path)
        names_rc, names_lines, names_rows = (None, [], [])
        if args.names:
            names_rc, names_lines, names_rows = run_names(args, stage, meta)
        inv_after_stage = inventory(stage)
        same_set = (sorted((r, k) for r, (k, _v) in inv_before.items())
                    == sorted((r, k) for r, (k, _v) in inv_after_stage.items()))
        binaries_intact = all(
            inv_after_stage.get(r, (None, None))[1] == inv_before[r][1]
            for r, (disp, _k) in results.items() if disp in ("binary", "pdf"))
        bad = gate_output(stage, inv_before)
        inv_end = inventory(in_dir)
        input_unchanged = inv_end == inv_before

        names_residue = 0
        names_files = []
        if args.names:
            for l in names_lines:
                if l.startswith("residue "):
                    names_residue = int(l.split()[1])
            for r in names_rows:
                if r.get("kind") == "residue":
                    names_files.append("%s:%s" % (r.get("file"), r.get("line")))
                elif r.get("kind") == "path_tokens":
                    names_files.append("%s (file path)" % r.get("file"))
        names_ok = (not args.names) or (names_rc == 0 and names_residue == 0)
        gate_ok = not bad and names_ok and same_set and binaries_intact and input_unchanged

        # --- the record -------------------------------------------------
        disp_counts = collections.Counter(d for d, _k in results.values())
        kind_counts = collections.Counter()
        for _d, kinds in results.values():
            kind_counts.update(kinds)
        names_tot = next((r for r in names_rows if r.get("kind") == "totals"), {})
        summary = {
            "tool": TOOL_VERSION, "mode": "apply" if args.apply else "dry run",
            "files_in": sum(1 for k, _v in inv_before.values() if k == "file"),
            "dirs_in": sum(1 for k, _v in inv_before.values() if k == "dir"),
            "symlinks_in": sum(1 for k, _v in inv_before.values() if k == "link"),
            "dispositions": dict(disp_counts),
            "removed_by_kind": dict(kind_counts),
            "local_rulings": len(pii_scan.active_rulings()),
            "names_given": bool(args.names),
            "names_exit": names_rc,
            "names_tokens_replaced": names_tot.get("tokens_replaced"),
            "names_lines_changed": names_tot.get("lines_changed"),
            "names_files_changed": names_tot.get("files_changed"),
            "names_code_occurrences_left": names_tot.get("code_occurrences_left"),
            "names_residue": names_residue if args.names else None,
            "output_blocking_findings": len(bad),
            "file_set_equal": same_set,
            "binaries_byte_identical": binaries_intact,
            "input_unchanged": input_unchanged,
            "gate": "PASS" if gate_ok else "FAIL",
        }
        led_path = os.path.join(meta, "ledger.jsonl")

        def handle(rel):
            disp, kinds = results.get(rel, ("missing", {}))
            detail = disp + (": " + ", ".join("%s %d" % kv for kv in sorted(kinds.items()))
                             if kinds else "")
            if disp == "missing":
                return ledger.failed("not staged", files=(1, 0))
            if disp in ("binary", "pdf", "symlink", "not_regular"):
                return ledger.skipped(detail + " (copied as is)", files=(1, 1))
            return ledger.ok(detail, files=(1, 1))
        keys = sorted(r for r, (k, _v) in inv_before.items() if k != "dir")
        _rows, balance = ledger.for_each(keys, handle, led_path,
                                         key_of=_safe, stream=None)
        summary["ledger_rows"] = len(_rows)
        summary["ledger_balanced"] = not ledger.unbalanced(balance)
        with open(os.path.join(meta, "summary.json"), "w", encoding="ascii") as fh:
            json.dump(summary, fh, ensure_ascii=True, sort_keys=True, indent=1)
            fh.write("\n")
        report = render_report(args, summary, results, bad, names_lines, names_files)
        with open(os.path.join(meta, "REPORT.md"), "w", encoding="ascii") as fh:
            fh.write(report)

        # --- delivery -----------------------------------------------------
        if args.apply:
            target = out_dir if gate_ok else failed
            os.replace(stage, target)
        for line in report_console(summary, bad, names_files, out_dir, meta):
            print(line)
        if not input_unchanged:
            sys.stderr.write("ERROR: IN_DIR changed during the run\n")
            return 2
        return 0 if gate_ok else 1
    finally:
        if tmp_holder:
            shutil.rmtree(tmp_holder, ignore_errors=True)
        elif args.apply and os.path.lexists(stage) and not os.path.lexists(failed):
            # a crash before delivery: never leave a half tree where output
            # is expected; park it beside, under the failed name
            os.replace(stage, failed)


def render_report(args, s, results, bad, names_lines, names_files):
    L = ["# Outis clean -- report", "",
         "Tool: %s. Mode: %s. Values never appear here: counts, file paths and "
         "line numbers only." % (s["tool"], s["mode"]), "",
         "## Verdict", "",
         "- gate: **%s**" % s["gate"],
         "- blocking findings left in the output: %d" % s["output_blocking_findings"],
         "- name residue: %s" % ("n/a (no --names)" if s["names_residue"] is None
                                 else s["names_residue"]),
         "- file set equal to the input: %s" % s["file_set_equal"],
         "- binaries byte-identical: %s" % s["binaries_byte_identical"],
         "- input unchanged (sha256 before = after): %s" % s["input_unchanged"],
         "", "## Counts", "",
         "- files in: %d (directories %d, symlinks %d)" % (s["files_in"], s["dirs_in"],
                                                            s["symlinks_in"]),
         "- dispositions: %s" % ", ".join("%s %d" % kv for kv in sorted(s["dispositions"].items())),
         "- removed by kind: %s" % (", ".join("%s %d" % kv for kv in
                                             sorted(s["removed_by_kind"].items())) or "none"),
         "- ORCIDs: kept (published identifiers; RECORDED, never blocking)",
         "- local rulings applied: %d" % s["local_rulings"],
         "- ledger: %d rows, balanced %s" % (s["ledger_rows"], s["ledger_balanced"])]
    if s["names_given"]:
        L += ["- names: %s tokens replaced on %s lines in %s files; code occurrences left %s; "
              "exit %s" % (s["names_tokens_replaced"], s["names_lines_changed"],
                           s["names_files_changed"], s["names_code_occurrences_left"],
                           s["names_exit"])]
    else:
        L += ["- names: not redacted (no --names given)"]
    copied = sorted(r for r, (d, _k) in results.items() if d in ("binary", "pdf", "symlink"))
    L += ["", "## Copied byte-for-byte (%d)" % len(copied), ""]
    L += ["- %s (%s)" % (_safe(r), results[r][0]) for r in copied] or ["- none"]
    if bad or names_files:
        L += ["", "## Gate failures (file:line, kind)", ""]
        L += ["- %s:%d %s" % (_safe(r), ln, k) for r, ln, k in bad]
        L += ["- %s names residue" % f for f in names_files]
    if s["names_given"]:
        L += ["", "## Name tool summary", "", "```"] + [
            l.encode("ascii", "backslashreplace").decode("ascii") for l in names_lines] + ["```"]
    return "\n".join(L) + "\n"


def report_console(s, bad, names_files, out_dir, meta):
    out = ["  outis clean (%s)" % s["mode"],
           "  %d files in: %s" % (s["files_in"], ", ".join(
               "%s %d" % kv for kv in sorted(s["dispositions"].items()))),
           "  removed by kind: %s" % (", ".join("%s %d" % kv for kv in
                                               sorted(s["removed_by_kind"].items())) or "none")]
    if s["names_given"]:
        out.append("  names: %s tokens replaced, residue %s"
                   % (s["names_tokens_replaced"], s["names_residue"]))
    out.append("  gate: %s (blocking left %d; file set equal %s; input unchanged %s)"
               % (s["gate"], s["output_blocking_findings"], s["file_set_equal"],
                  s["input_unchanged"]))
    for r, ln, k in bad:
        out.append("    FAIL %s:%d %s" % (_safe(r), ln, k))
    for f in names_files:
        out.append("    FAIL %s names residue" % f)
    if s["mode"] == "apply":
        out.append("  output: %s" % (out_dir if s["gate"] == "PASS" else out_dir + FAILED_SUFFIX))
    else:
        out.append("  DRY RUN: nothing delivered; re-run with --apply")
    out.append("  record: %s" % meta)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="outis.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=TOOL_VERSION)
    sub = ap.add_subparsers(dest="command")
    c = sub.add_parser("clean", help="write a stripped copy of a corpus tree")
    c.add_argument("in_dir", metavar="IN_DIR")
    c.add_argument("--out", required=True, metavar="OUT_DIR")
    c.add_argument("--rulings", default=None)
    c.add_argument("--names", default=None, help="the roster: one name per line")
    c.add_argument("--unambiguous-names", default=None)
    c.add_argument("--ambiguous-names", default=None)
    c.add_argument("--identifier-names", default=None)
    c.add_argument("--dictionary", default=None)
    c.add_argument("--citations-published", action="store_true")
    c.add_argument("--force-lines", default=None)
    c.add_argument("--spare-lines", default=None)
    c.add_argument("--sample", type=int, default=0, metavar="N")
    c.add_argument("--outlier-bound", type=int, default=100)
    c.add_argument("--jobs", type=int, default=1, metavar="K")
    c.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)
    if args.command != "clean":
        ap.print_help()
        return 2
    try:
        return clean(args)
    except (Refuse, redact_names.Refuse) as e:
        sys.stderr.write("REFUSED: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
