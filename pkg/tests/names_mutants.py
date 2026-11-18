#!/usr/bin/env python3
"""Mutation harness for redact_names.py (carried from the loop's harness for
redact_pass5.py): re-introduces a deliberately broken
form of each contract item, runs the whole unit suite against the mutated
copy, and requires the suite to FAIL (the mutant killed). The run of each
mutant is kept as red-first evidence under tests/red/<id>.txt, with the home
directory written as <HOME>.

A baseline run of the UNMUTATED tool must pass first: a suite that cannot
run scores every mutant as killed for the wrong reason (the inverse of the
collection-state hazard), so a failing baseline stops the harness (exit 2).

    python3 tests/mutants.py          # exit 0 only when every mutant is killed
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "redact_names.py")
# Red-first evidence goes OUTSIDE the package tree (OUTIS_RED_DIR, else a
# temporary directory), so a run never adds files to the package.
RED = os.environ.get("OUTIS_RED_DIR") or os.path.join(tempfile.gettempdir(), "outis-names-red")
TMP = os.path.join(tempfile.gettempdir(), "outis-names-tests")
HOME = os.path.expanduser("~")

# (id, contract item, what the broken form does, [(old, new), ...])
MUTANTS = [
    ("P1_empty_names_accepted", "P1",
     "an empty names file is not refused",
     [("        if not entries:\n            raise Refuse(",
       "        if False:\n            raise Refuse(")]),
    ("P2_code_eligible", "P2",
     "a listed token in CODE is replaced (code-family eligibility ignores comment spans)",
     [("            if not _inside(s, e, spans):\n                left.append((s, \"code\", mem[(s, e)]))",
       "            if False:\n                left.append((s, \"code\", mem[(s, e)]))")]),
    ("P2_c_string_literal_as_comment", "P2",
     "the C lexer forgets string literals, so '//' inside a string is taken as a comment",
     [("            if c == '\"':\n                if i >= 1 and line[i - 1] == \"R\":",
       "            if c == '\\x01':\n                if i >= 1 and line[i - 1] == \"R\":")]),
    ("P2_json_key_replaced", "P2",
     "JSON keys are treated as string values",
     [("            if is_key:\n                for ms, me, _ln in names.find(dec):",
       "            if False:\n                for ms, me, _ln in names.find(dec):")]),
    ("P3_dropped_line", "P3",
     "a line is dropped when the file is written in place",
     [("        f.write(data)\n    os.chmod(tmp",
       "        f.write(data.replace(b\"\\n\", b\"\", 1))\n    os.chmod(tmp")]),
    ("P3_byte_after_span_eaten", "P3",
     "the splice eats the byte after each replaced span",
     [("        out.append(PLACEHOLDER)\n        prev = e\n",
       "        out.append(PLACEHOLDER)\n        prev = e + 1\n")]),
    ("P4_token_in_ledger", "P4",
     "the ledger row carries the changed line's old text, and the ledger guard is off",
     [("            row = {\"kind\": kind, \"file\": shown, \"line\": ch.lineno,",
       "            row = {\"kind\": kind, \"file\": shown + r.old_bytes.decode(r.codec)"
       ".split(\"\\n\")[idx], \"line\": ch.lineno,"),
      ("            if cls == \"unambiguous\" or corpus:",
       "            if False:")]),
    ("P4_token_in_ledger_guard_on", "P4",
     "the ledger row carries the old line text; the run-time guard is left on",
     [("            row = {\"kind\": kind, \"file\": shown, \"line\": ch.lineno,",
       "            row = {\"kind\": kind, \"file\": shown + r.old_bytes.decode(r.codec)"
       ".split(\"\\n\")[idx], \"line\": ch.lineno,")]),
    ("P4_dry_run_writes_tree", "P4",
     "the dry run writes the tree",
     [("    if not args.apply:\n        text = _jsonl(rows + [t])",
       "    if not args.apply:\n        [write_in_place(r.path, r.new_bytes) for r in results"
       " if r.changes]\n        text = _jsonl(rows + [t])")]),
    ("P5_header_not_the_pass4_form", "P5",
     "the manifest header is not the ruled pass-4 form",
     [("MANIFEST_COLUMNS = (\"path\", \"sha256_pass4\", \"sha256_pass5\", \"change\")",
       "MANIFEST_COLUMNS = (\"file\", \"sha256_pass4\", \"sha256_pass5\", \"change\")")]),
    ("P5_root_file_given_a_class", "P5",
     "a path outside any class directory is counted under its own name, not root",
     [("    if len(parts) == 1:\n        return \"root\"",
       "    if len(parts) == 1:\n        return parts[0]")]),
    ("P5_change_field_counts_lines_twice", "P5",
     "the change field's n_tokens repeats the line count",
     [("            len(r.changes), sum(len(ch.spans) for ch in r.changes.values()))",
       "            len(r.changes), len(r.changes))")]),
    ("P6_neutrality_off", "P6",
     "the parser-neutrality check never refuses",
     [("        if before != after:\n            raise Refuse(\"parser neutrality",
       "        if False:\n            raise Refuse(\"parser neutrality")]),
    ("P7_exit_zero_with_residue", "P7",
     "exit 0 whatever the residue",
     [("    rc = 0 if (residue == 0 and consistent and not degraded and unmatched_all == 0) else 1",
       "    rc = 0")]),
    ("P9_quotes_not_mapped", "P9",
     "quoted copies under --agents get the ordinary rules, not the snapshot's substitution",
     [("    index = (QuoteIndex() if has_root and any(lab.startswith(\"agents\") for lab, _t in trees)\n"
       "             else None)",
       "    index = None")]),
    ("P12_reserialised", "P12",
     "the edited record is re-serialised (sorted keys, ensure_ascii) instead of kept as bytes",
     [("            new_core = splice(core, raw_spans)\n",
       "            new_core = json.dumps(json.loads(splice(core, raw_spans)), "
       "ensure_ascii=True, sort_keys=True)\n")]),
    ("P12_escape_width_wrong", "P12",
     "a two-character escape is mapped as one raw character",
     [("            else:\n                i += 2\n        else:\n            i += 1",
       "            else:\n                i += 1\n        else:\n            i += 1")]),
    ("P13_prose_attribution_only", "P13",
     "prose files get only the name-only/attribution rule",
     [("    if family == FAM_PROSE:\n        elig.extend",
       "    if False:\n        elig.extend")]),
    ("P13_shebang_as_prose", "P13",
     "an extensionless shebang script is treated as prose",
     [("        return FAM_SHELLISH if text.startswith(\"#!\") else FAM_PROSE",
       "        return FAM_PROSE")]),
    ("P15_gate_left_in_record_prose", "P15",
     "an unambiguous (gate-list) token outside comment/attribution context in a record prose field is left",
     [("        elif _inside(s, e, spans or []):\n            elig.append((s, e, ln, \"a\"))\n"
       "        else:\n            elig.append((s, e, ln, \"g\"))",
       "        elif _inside(s, e, spans or []):\n            elig.append((s, e, ln, \"a\"))\n"
       "        else:\n            left.append((s, ctx_where, \"unambiguous\"))")]),
    ("P15_gate_residue_not_counted", "P15",
     "the post-check does not count a gate-list token left outside source code",
     [("    gate_out = sum(1 for r in rs for _i, _c, w, m in r.left\n"
       "                   if m == \"unambiguous\" and w not in (\"code\", \"citation\", \"spared\"))",
       "    gate_out = 0")]),
    ("P15_code_keys_as_prose", "P15",
     "--code-keys fields get the prose-field rules (a quoted decay line loses its model name)",
     [("                                 \"code\" if ekey in CODE_KEYS else \"prose\", (over or {}).get(idx))",
       "                                 \"prose\", (over or {}).get(idx))")]),
    ("P16_agents_apply_without_root", "P16",
     "--apply on agents trees proceeds without --root (no quote index)",
     [("    if args.apply and args.agents and not args.root:",
       "    if False:")]),
    ("P16_binary_not_named", "P16",
     "skipped binary files get no ledger row",
     [("    for lab, rel, reason in skipped:", "    for lab, rel, reason in []:")]),
    ("P16_check_records_not_in_invocation", "P16",
     "check-records does not run after --apply in the same invocation",
     [("    if args.root and args.agents:\n        big = snapshot_text(args.root)",
       "    if False:\n        big = snapshot_text(args.root)")]),
    ("P17_counter_keyed_on_label", "P17",
     "the agents counter tests label == agents (the reported defect)",
     [("         \"files_changed_agents\": sum(1 for r in results if r.changes and r.kind == \"agents\"),",
       "         \"files_changed_agents\": sum(1 for r in results if r.changes and r.label == \"agents\"),")]),
    ("P17_paragraph_keyed_on_label", "P17",
     "the README paragraph selects agents files by label",
     [("        rs = sorted((r for r in results if r.changes and r.kind == kind),",
       "        rs = sorted((r for r in results if r.changes and r.label == kind),")]),
    ("P18_any_nul_is_binary", "P18",
     "any NUL byte makes a file binary (the reported defect)",
     [("    if data.count(b\"\\0\") > MAX_TEXT_NULS:", "    if b\"\\0\" in data:")]),
    ("P18_check_records_skips_nul_text", "P18",
     "check-records' snapshot reader skips any NUL-bearing file",
     [("        if is_binary(data):\n            continue\n        parts.append(decode(data)[0])",
       "        if b\"\\0\" in data:\n            continue\n        parts.append(decode(data)[0])")]),
    ("P19_old_form_all_unambiguous", "P19",
     "the pre-P19 form: every token unambiguous (the reverted pass)",
     [("                self.member_of_token[k] = next(c for c in sets if k in sets[c])",
       "                self.member_of_token[k] = \"unambiguous\"")]),
    ("P22_hyphen_joins_ambiguous_off", "P22",
     "an ambiguous token matches inside a hyphenated compound",
     [("        self.rx_amb = (re.compile(r\"(?<![\\w-])(?:%s)(?![\\w-])\" % alt(amb), re.IGNORECASE)",
       "        self.rx_amb = (re.compile(r\"(?<!\\w)(?:%s)(?!\\w)\" % alt(amb), re.IGNORECASE)")]),
    ("P22_caps_heading_as_name", "P22",
     "an unlisted ALL-CAPS word counts as a given name (a 'DE MINIMIS' heading is name-only)",
     [("                and not (len(w) > 1 and w.isupper())):",
       "                and True):")]),
    ("P20_left_tokens_not_masked", "P20",
     "the sample shows listed tokens left on a sampled line",
     [("            left = [(s, e) for s, e in names.find_mask(core)\n"
       "                    if not any(s < b and a < e for a, b in repl)]",
       "            left = []")]),
    ("P21_ambiguous_not_flagged", "P21",
     "the hit table does not flag an ambiguous-class line",
     [("        if \"ambiguous\" in cls.replace(\"unambiguous\", \"\"):",
       "        if False:")]),
    ("P23_guard_refuses_every_class", "P23",
     "the output guard refuses any listed token anywhere (the form that refused the real dry run)",
     [("            if cls == \"unambiguous\" or corpus:", "            if True:")]),
    ("P23_path_masks_every_class", "P23",
     "a path is masked for an ambiguous or identifier token too",
     [("    hits = names.find_mask_unambiguous(shown)      # P33: the output form",
       "    hits = names.find_mask(shown)")]),
    ("P24_identifier_as_unambiguous_outside_code", "P24",
     "an identifier token outside code takes the unambiguous rules (every prose occurrence)",
     [("    soft = lambda s, e: mem[(s, e)] in (\"ambiguous\", \"identifier\")",
       "    soft = lambda s, e: mem[(s, e)] in (\"ambiguous\",)")]),
    ("P24_long_lines_unbounded", "P24",
     "the attribution classifier has no length bound",
     [("    if len(body.split()) > ATTR_MAX_WORDS:\n        # P26(d)",
       "    if False:\n        # P26(d)")]),
    ("P24_idiom_anywhere", "P24",
     "the idiom may sit anywhere on the line, not at its start",
     [("    if ATTR_START.match(body) or DATE.match(body):",
       "    if ATTR_START.search(body) or DATE.search(body):")]),
    ("P24_auto_precedence_inverted", "P24",
     "the tool's own partition tests identifier before ambiguous",
     [("            if len(tok) <= 3 or k in NAME_PARTICLES or k in words:\n"
       "                cls = \"ambiguous\"\n            elif k in code:\n"
       "                cls = \"identifier\"",
       "            if k in code:\n                cls = \"identifier\"\n"
       "            elif len(tok) <= 3 or k in NAME_PARTICLES or k in words:\n"
       "                cls = \"ambiguous\"")]),
    ("P24b_by_token_anywhere_off", "P24",
     "'by <Token>' on a short line counts only within the first three words",
     [("        if BY_TOKEN.search(body[:s]):", "        if False:")]),
    ("P24b_code_field_whole_line", "P24",
     "a --code-keys field judges attribution on the whole line (the model name is replaced)",
     [("    if soft_rest and family is None and field == \"code\":", "    if False:")]),
    ("P25_opening_form_off", "P25",
     "a token + date/keyword opening a long remark is no attribution line (the regression)",
     [("        if ends:\n            return off + min(ends)", "        if False:\n            return off + min(ends)")]),
    ("P25_opening_is_whole_line", "P25",
     "the opening form replaces soft tokens in the remark too",
     [("        if ends:\n            return off + min(ends)", "        if ends:\n            return len(line)")]),
    ("P25_opening_any_word", "P25",
     "the token + date/keyword may stand anywhere, not in the first four words",
     [("    limit = words[-1][1]", "    limit = len(body)")]),
    ("P25_mdy_date_missing", "P25",
     "the M/D/YY date form (4/28/00) is not a date",
     [("    r\"|(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\\d|3[01])[-/.](?:19|20)?\\d\\d\"      # 4/28/00 (P25)\n",
       "")]),
    ("P26_prose_forms_off", "P26",
     "possessive / by / from forms of a soft token in prose are left",
     [("            elif prose_ctx and forms.get((s, e)):", "            elif False:")]),
    ("P26_comment_forms_off", "P26",
     "possessive / by / from forms of a soft token in a source comment are left",
     [("                elif forms.get((s, e)):", "                elif False:")]),
    ("P26_long_author_line_left", "P26",
     "a long keyword-opened line is no attribution line (the recorded residual)",
     [("        km = KEYWORD_START.match(body)\n        if km:",
       "        km = KEYWORD_START.match(body)\n        if False:")]),
    ("P26_sample_left_cell_off", "P26",
     "the sample carries no LEFT cell",
     [("            if m in (\"ambiguous\", \"identifier\") and w in (\"comment\", \"prose\", \"json_string\",\n"
       "                                                           \"subject\"):",
       "            if False:")]),
    ("P27_citation_rule_off", "P27",
     "with the flag, citation lines are treated as today",
     [("    if CITATIONS:\n        # P27/P28(b)", "    if False:\n        # P27/P28(b)")]),
    ("P27_citation_counted_as_residue", "P27",
     "the post-scan counts a citation-left unambiguous token as residue",
     [("                   if m == \"unambiguous\" and w not in (\"code\", \"citation\", \"spared\"))",
       "                   if m == \"unambiguous\" and w not in (\"code\", \"spared\"))")]),
    ("P27_flag_always_on", "P27",
     "citation lines are left without the flag",
     [("    CITATIONS = bool(args.citations_published)", "    CITATIONS = True")]),
    ("P28_run_off", "P28",
     "an anchor covers only the first token of a run of names",
     [("        if cur and RUN_SEP.fullmatch(line[cur[-1][1]:m[0]]):",
       "        if False:")]),
    ("P28_citation_whole_line", "P28",
     "with the flag, every listed token on a citation line is left (the over-exemption)",
     [("        cit = citation_group(line, matches)",
       "        cit = set((m[0], m[1]) for m in matches) if CITATION.search(line) else set()")]),
    ("P28_citation_gap_unchecked", "P28",
     "the citation group swallows any token before the pattern within the window",
     [("            if c.start() - s > CITATION_WINDOW or not CIT_GAP.fullmatch(line[e:edge]):",
       "            if c.start() - s > CITATION_WINDOW:")]),
    ("P28_left_cell_header_apart", "P28",
     "the LEFT cell header does not share the cell list's prefix (the eleventh sample's miss)",
     [("        out.append(\"== cell: LEFT kind=%s class=%s context=comment/prose \"",
       "        out.append(\"== LEFT cell: kind=%s class=%s context=comment/prose \"")]),
    ("P28_left_cell_identifier_off", "P28",
     "the sample has no LEFT cell for identifier tokens",
     [("            if m in (\"ambiguous\", \"identifier\") and w in (\"comment\", \"prose\", \"json_string\",\n"
       "                                                           \"subject\"):",
       "            if m in (\"ambiguous\",) and w in (\"comment\", \"prose\", \"json_string\",\n"
       "                                                           \"subject\"):")]),
    ("P29_lead_off", "P29",
     "a leading token followed by ' - ', ':' or ',' and a remark is left",
     [("            if _LEAD_SEP.match(seg, pos):\n                return \"lead\"",
       "            if False:\n                return \"lead\"")]),
    ("P29_date_near_off", "P29",
     "a token within two words of a date is left",
     [("            if _gap_words(gap) <= 1:\n                return \"date\"",
       "            if False:\n                return \"date\"")]),
    ("P29_placeholder_off", "P29",
     "a token within two words of a redaction placeholder is left",
     [("                    and near_placeholder(line, a, end_of[a], ph):",
       "                    and False:")]),
    ("P29_placeholder_this_pass_off", "P29",
     "only an earlier pass's placeholders count (the pass stops being a fixpoint)",
     [("    ph = [m.span() for m in OLD_PLACEHOLDERS.finditer(line)] + [(a, b) for a, b, _l, _c in elig]",
       "    ph = [m.span() for m in OLD_PLACEHOLDERS.finditer(line)]")]),
    ("P29_ambiguous_subject_replaced", "P29",
     "an ambiguous sentence subject in a source comment is replaced (the residual class erased)",
     [("                    if rule == \"subject\" and mem[(s, e)] == \"ambiguous\":",
       "                    if False:")]),
    ("P29_calendar_strict", "P29",
     "a digit/digit/digit date that is no calendar date (4/38/00) is not a date",
     [("    r\"|\\d{1,2}/\\d{1,2}/\\d{2,4}\"                                                   # 4/38/00 (P29)\n",
       "")]),
    ("P30_box_border_kept", "P30",
     "a boxed header line is judged with its trailing border run",
     [("    body = re.sub(r\"[\\s#*|/]+$\", \"\", body)\n    if not body:",
       "    body = body.rstrip(\" \\t\\r*/\")\n    if not body:")]),
    ("P30_group_label_off", "P30",
     "a parenthesised group label breaks a name line",
     [("    masked = GROUP_LABEL.sub(\" \", masked)\n", "")]),
    ("P30_dmy_two_digit_year_off", "P30",
     "day-month-year needs a four-digit year ('6 sep 00' is no date)",
     [("_MON + r\"[-/. ,]*(?:19|20)?\\d\\d\"     # 6 sep 00 (P30)",
       "_MON + r\"[-/. ,]*(?:19|20)\\d\\d\"     # 6 sep 00 (P30)")]),
    ("P30_second_marker_lead_off", "P30",
     "a lead after a second comment marker is not a lead",
     [("                      re.finditer(r\"(?:;\\s*|(?<!\\S)#+\\s*|//\\s*)[#/*!%>\\s-]*\", seg)]",
       "                      re.finditer(r\";\\s*\", seg)]")]),
    ("P30_phy_misspelling_off", "P30",
     "'Phy Rev' is no journal",
     [("_JOURNAL = (r\"(?:Phys?\\.?\\s*Rev", "_JOURNAL = (r\"(?:Phys\\.?\\s*Rev")]),
    ("P30_in_date_off", "P30",
     "a soft token inside a date takes the attribution rules (13/<tok>/04 replaced)",
     [("    if in_date:\n", "    if False:\n")]),
    ("P31q_citation_under_unambiguous", "P31",
     "the per-tree line counts citation groups under 'left unambiguous' (the question)",
     [("        lwc = {w: v for w, v in lw.items() if w not in (\"citation\", \"spared\")}",
       "        lwc = lw")]),
    ("P31_thanks_courtesy_off", "P31",
     "'thanks to' and 'courtesy of' are no anchors",
     [("(by|from|thanks\\s+to|courtesy\\s+of)", "(by|from)")]),
    ("P31_initial_off", "P31",
     "the initial-dot-surname form is not attribution",
     [("    if _INITIAL_BEFORE.search(seg[:s]):\n        return \"initial\"",
       "    if False:\n        return \"initial\"")]),
    ("P31_url_off", "P31",
     "a personal URL path is not attribution",
     [("    if _URL_BEFORE.search(seg[:s]) and", "    if False and")]),
    ("P31_yearless_date_off", "P31",
     "a date without a year does not count near a token",
     [("list(DATE.finditer(seg)) + list(YEARLESS_DATE.finditer(seg))", "list(DATE.finditer(seg))")]),
    ("P31_changelog_tag_off", "P31",
     "the line's text does not begin after a changelog tag",
     [("    text_starts = [off] + ([tag.end()] if tag else [])", "    text_starts = [off]")]),
    ("P31_subject_prose_off", "P31",
     "the identifier subject rule applies to comments only, not prose lines",
     [("                is_comment = family in (FAM_PROSE, FAM_TEXT) or quoted_comment",
       "                is_comment = quoted_comment")]),
    ("P32_force_off", "P32",
     "--force-lines does nothing",
     [("    if override == \"force\":", "    if False:")]),
    ("P32_spare_off", "P32",
     "--spare-lines does nothing",
     [("    if override == \"spare\":\n        # P32: an operator-spared",
       "    if False:\n        # P32: an operator-spared")]),
    ("P32_force_reaches_code", "P32",
     "a forced line's CODE tokens are replaced",
     [("FORCE_WHERE = (\"comment\",", "FORCE_WHERE = (\"code\", \"comment\",")]),
    ("P32_stale_line_unchecked", "P32",
     "an entry naming a line without a listed token is not reported stale",
     [("            elif not names.find(lines[ln - 1]) and \"\\\\u\" not in lines[ln - 1]:\n"
       "                reason = \"no_listed_token\"",
       "            elif False:\n                reason = \"no_listed_token\"")]),
    ("P32_conflict_unchecked", "P32",
     "a line in both lists is not refused",
     [("    if both:\n        raise Refuse(", "    if False:\n        raise Refuse(")]),
    ("P32_spared_is_residue", "P32",
     "an operator-spared unambiguous token counts as residue",
     [("if m == \"unambiguous\" and w not in (\"code\", \"citation\", \"spared\"))",
       "if m == \"unambiguous\" and w not in (\"code\", \"citation\"))")]),
    ("P32_spared_line_decides_quotes", "P32",
     "a spared line enters the quote index (its quotes turn ambiguous and are refused)",
     [("        if index is not None and (over or {}).get(idx) != \"spare\":",
       "        if index is not None:")]),
    ("P33_mask_hyphen_joined", "P33",
     "the outputs mask with the corpus's hyphen-joined form (the landed sample's defect)",
     [("        self.rx_mask_sub = re.compile(\"(?:%s)\" % alt(rest), re.IGNORECASE) if rest else None",
       "        self.rx_mask_sub = (re.compile(r\"(?<![\\w-])(?:%s)(?![\\w-])\" % alt(rest), "
       "re.IGNORECASE) if rest else None)")]),
    ("P33_guard_word_form", "P33",
     "the output guard keeps the word-bounded form",
     [("        for s, e in self.find_mask(text):     # P33: the output form",
       "        for s, e, _ln in self.find(text):")]),
    ("P33_path_mask_word_form", "P33",
     "a path is masked in the word-bounded form ('<tok>99' slips through, the guard refuses)",
     [("    hits = names.find_mask_unambiguous(shown)      # P33: the output form",
       "    hits = [(a, b) for a, b, _l in names.find_unambiguous(shown)]")]),
    ("P33_short_tokens_as_substrings", "P33",
     "a token of three characters or fewer is masked as a substring",
     [("               if self.member_of_token.get(self.token_of_key[v.casefold()]) == \"ambiguous\"\n"
       "               or len(v) <= 3]",
       "               if self.member_of_token.get(self.token_of_key[v.casefold()]) == \"ambiguous\"]")]),
    ("P34_dry_exit_line_off", "P34",
     "the dry run ends without naming its exit status (the orchestrator's observation)",
     [("        report.append(exit_line(rc, t))\n", "")]),
    ("P34_refusal_reason_missing", "P34",
     "a refused record is not named as the reason for exit 1",
     [("    if t[\"records_refused\"]:\n        by = {}", "    if False:\n        by = {}")]),
    ("P34_residue_reason_missing", "P34",
     "residue is not named as the reason for exit 1",
     [("    if residue:\n        extra.append(\"residue %d\" % residue)",
       "    if False:\n        extra.append(\"residue %d\" % residue)")]),
    ("P35_identifier_named_is_exit", "P35",
     "an identifier-named file is an exit condition",
     [("    degraded = bool(t[\"records_refused\"] or t[\"paths_with_listed_token\"]",
       "    degraded = bool(t[\"records_refused\"] or t[\"paths_with_listed_token\"] "
       "or t[\"identifier_named_files\"]")]),
    ("P35_identifier_named_uncounted", "P35",
     "identifier-named files are not counted",
     [("         \"identifier_named_files\": sum(1 for r in results",
       "         \"identifier_named_files\": 0 * sum(1 for r in results")]),
    ("P35_path_diagnosis_off", "P35",
     "no per-path hit diagnosis in the ledger",
     [("        if hits:\n            shown, psha = display_path", "        if False:\n            shown, psha = display_path")]),
    ("P10_hunk_proof_off", "P10",
     "the C/C++ hunk proof never refuses",
     [("        if r.c_hunks_outside:\n            raise Refuse(\"P10:",
       "        if False:\n            raise Refuse(\"P10:")]),
    ("P11_verdict_always_equal", "P11",
     "the manifest-diff verdict is EQUAL whatever the counts",
     [("    verdict = \"EQUAL\" if same_count and same_set else \"NOT EQUAL\"",
       "    verdict = \"EQUAL\"")]),
    ("P11_any_context_count_zero", "P11",
     "the post-check's any-context token count is not counted",
     [("    raw = sum(r.raw_hits for r in rs if r.family != FAM_JSONL)\n",
       "    raw = 0\n")]),
]


def sanitize(text):
    return text.replace(HOME, "<HOME>")


def run_suite(module):
    env = dict(os.environ, REDACT_NAMES_MODULE=module, TMPDIR=TMP, PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", HERE,
                        "-p", "test_redact_names.py"], cwd=HERE, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout


def main():
    os.makedirs(TMP, exist_ok=True)
    os.makedirs(RED, exist_ok=True)
    rc, out = run_suite(TOOL)
    if rc != 0:
        sys.stdout.write(sanitize(out))
        sys.stdout.write("BASELINE FAILED: the unmutated tool does not pass; no mutant "
                         "can be scored\n")
        return 2
    with open(TOOL) as f:
        src = f.read()
    killed = 0
    for mid, item, what, edits in MUTANTS:
        msrc = src
        for old, new in edits:
            n = msrc.count(old)
            if n != 1:
                sys.stdout.write("MUTANT %s: site found %d times (need 1); harness stale\n"
                                 % (mid, n))
                return 2
            msrc = msrc.replace(old, new)
        d = os.path.join(TMP, "mut_" + mid)
        os.makedirs(d, exist_ok=True)
        mpath = os.path.join(d, "redact_names.py")
        with open(mpath, "w") as f:
            f.write(msrc)
        rc, out = run_suite(mpath)
        verdict = "KILLED" if rc != 0 else "SURVIVED"
        killed += rc != 0
        with open(os.path.join(RED, mid + ".txt"), "w", encoding="ascii",
                  errors="backslashreplace") as f:
            f.write("mutant: %s\ncontract item: %s\nbroken form: %s\n"
                    "suite exit status: %d\nverdict: %s\n\n%s"
                    % (mid, item, what, rc, verdict, sanitize(out)))
        shutil.rmtree(d, ignore_errors=True)
        sys.stdout.write("%-34s %-4s %s\n" % (mid, item, verdict))
    sys.stdout.write("baseline passed; mutants killed %d of %d (evidence under %s)\n"
                     % (killed, len(MUTANTS), RED))
    p9_ok = p9_snapshot_only_evidence()
    p22_ok = p22_old_form_evidence()
    return 0 if killed == len(MUTANTS) and p9_ok and p22_ok else 1


def p22_old_form_evidence():
    """P22's red: the pre-P19 form (every token unambiguous -- what the
    reverted pass ran; here, membership files putting every token in the
    unambiguous class and the other two classes empty) on the planted fixture.
    Expected red: the rule name and the hyphenated compound are mangled."""
    sys.path.insert(0, HERE)
    import names_support as S
    import test_redact_names as T
    base = S.mkdtemp()
    try:
        root, agents = S.build(base)
        with open(os.path.join(agents, "rationale.md"), "w") as f:
            f.write(T.P19P22Ambiguous.DOC)
        with open(os.path.join(agents, "rationale.jsonl"), "w") as f:
            f.write(T.P19P22Ambiguous.REC)
        out = os.path.join(base, "out")
        os.makedirs(out)
        p = subprocess.run([sys.executable, TOOL, "--names", S.NAMES]
                           + S.old_form_lists(out) + ["--root", root,
                            "--agents", agents, "--ledger", os.path.join(out, "l.jsonl"),
                            "--manifest-out", os.path.join(out, "m.csv"), "--readme-out",
                            os.path.join(out, "r.txt"), "--apply"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with open(os.path.join(agents, "rationale.md")) as f:
            doc = f.read()
        with open(os.path.join(agents, "rationale.jsonl")) as f:
            rec = f.read()
        ok = ("<name> MINIMIS" in doc and "<name>-derivations" in doc
              and "<name> MINIMIS" in rec and "<name>-derivations" in rec)
        with open(os.path.join(RED, "P22_old_form_on_fixture.txt"), "w", encoding="ascii",
                  errors="backslashreplace") as f:
            f.write("broken form: P22 -- the pre-P19 form (every token unambiguous; the ambiguous\n"
                    "and identifier membership files empty), as the reverted pass ran\n"
                    "expected: the rule name and the hyphenated compound mangled\n"
                    "verdict: %s\n\nexit status %d\n\n--- DOC before\n%s--- DOC after\n%s"
                    "--- records before\n%s--- records after\n%s"
                    % ("RED AS EXPECTED" if ok else "NOT RED", p.returncode,
                       T.P19P22Ambiguous.DOC, doc, T.P19P22Ambiguous.REC, rec))
        sys.stdout.write("P22 old-form evidence: %s\n" % ("red as expected" if ok else "NOT RED"))
        return ok
    finally:
        S.rmtree(base)


def p9_snapshot_only_evidence():
    """P9's named broken form is an operator act, not a code defect: redact
    the snapshot only (no --agents). Run it on the fixture and keep the
    --check-records output: exactly 1 UNMATCHED item is the expected red."""
    sys.path.insert(0, HERE)
    import names_support as S
    base = S.mkdtemp()
    try:
        root, agents = S.build(base)
        out = os.path.join(base, "out")
        os.makedirs(out)
        log = []
        for label, args in (
                ("snapshot-only pass", ["--names", S.NAMES, "--root", root, "--ledger",
                                        os.path.join(out, "l.jsonl"), "--manifest-out",
                                        os.path.join(out, "m_<class>.csv"), "--readme-out",
                                        os.path.join(out, "r.txt"), "--apply"]),
                ("check-records after it", ["--check-records", root, agents])):
            p = subprocess.run([sys.executable, TOOL] + args, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
            log.append("$ redact_names.py %s\n%sexit status %d\n"
                       % (label, p.stdout, p.returncode))
        ok = "1 UNMATCHED" in log[1] and log[1].rstrip().endswith("exit status 1")
        with open(os.path.join(RED, "P9_snapshot_only_check_records.txt"), "w",
                  encoding="ascii", errors="backslashreplace") as f:
            f.write("broken form: P9 -- the snapshot redacted, the agents files not\n"
                    "expected: check-records reports 1 UNMATCHED and exits 1\n"
                    "verdict: %s\n\n%s" % ("RED AS EXPECTED" if ok else "NOT RED",
                                            sanitize("\n".join(log).replace(base, "<FIXTURE>"))))
        sys.stdout.write("P9 snapshot-only evidence: %s\n" % ("red as expected" if ok else "NOT RED"))
        return ok
    finally:
        S.rmtree(base)


if __name__ == "__main__":
    sys.exit(main())
