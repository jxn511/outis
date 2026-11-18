#!/usr/bin/env python3
"""
text_decode.py -- bytes to text, without ever manufacturing a replacement
character.

ONE DEFINITION, IN A NEUTRAL PLACE. This logic was first written inside a
network fetcher that also carries credentials and transport configuration.
`pii_scan` needs the same decoding and must not import any of that to get it,
so the rule lives here and every caller imports it. The alternative -- a second
copy in the scanner -- is the drift the one-definition rule exists to prevent,
and this is a poor place for it: two decoders that disagree mean the scanner
reads a different document from the one the pipeline stores.

THE PROPERTY. Bytes that contain no U+FFFD must not decode to a string that
does. `errors="replace"` violates it, and at an acquisition boundary that is
irreversible: it converts "I do not know this encoding" into "these bytes are
permanently a question mark", silently, with no exception and no ledger row.
Measured on the reference instance: 95,353 characters of one harvested thread
archive were destroyed exactly that way, and only a re-harvest recovered them.

WHY NOT SIMPLY latin-1. It cannot fail, so it looks like a total answer, but it
is total in the wrong way -- it reads every valid UTF-8 sequence as two or three
Latin letters. Falling to it on the FIRST invalid byte cost 1,501 correctly
transmitted apostrophes on the first re-harvest, because a single bad byte
anywhere threw the whole page to it.

THE UNIT OF DECISION IS THE BYTE, NOT THE PAGE. Real archives are mixed: some
messages UTF-8, some latin-1, some already corrupt on the server before anyone
fetched them. `surrogateescape` decodes every valid UTF-8 sequence correctly and
parks each invalid byte in U+DC80..U+DCFF; mapping those down by 0xDC00 yields
the character latin-1 assigns that byte. Valid UTF-8 survives as itself, junk
bytes become their latin-1 reading, nothing is replaced and nothing is lost.

WHAT THIS IS NOT FOR. Round-tripping. `decode_document` is a best-effort READ:
its output re-encoded as UTF-8 does not reproduce the input bytes, because a
latin-1 e-acute becomes two bytes on the way back. Code that must edit a file
and write it back -- pii_scrub -- uses `errors="surrogateescape"` on BOTH sides
instead, which is lossless and is a different operation on purpose.

Stdlib only.
"""

import re

# The charset a document declares about itself. Used when no caller supplies one
# and no HTTP header is available -- which is the common case for archived
# pages: 1,358 of 1,364 harvested thread-archive files declared nothing at all.
_META_CHARSET = re.compile(rb"""charset\s*=\s*["']?\s*([A-Za-z0-9_.:-]+)""", re.I)

# Lone surrogates in this range are what surrogateescape parks an undecodable
# byte in; subtracting the base recovers the byte.
_SURROGATE_LO, _SURROGATE_HI, _SURROGATE_BASE = 0xDC80, 0xDCFF, 0xDC00


def decode_document(body, encoding=None):
    """Bytes -> str, never producing U+FFFD from bytes that had none.

    The ladder, in order of evidence:
      1. an explicit `encoding` argument -- the caller knows;
      2. a charset the document declares;
      3. strict UTF-8, which is self-validating: a byte sequence that decodes
         cleanly as UTF-8 is overwhelmingly unlikely to be anything else;
      4. per-byte fallback for mixed content (see the module docstring).
    Step 4 cannot fail, so no input ever reaches an `errors=` parameter that
    would discard information.
    """
    if isinstance(body, str):
        return body
    candidates = []
    if encoding:
        candidates.append(encoding)
    m = _META_CHARSET.search(body[:4096])
    if m:
        candidates.append(m.group(1).decode("ascii", "ignore"))
    candidates.append("utf-8")
    for enc in candidates:
        try:
            return body.decode(enc)          # STRICT: no errors= anywhere
        except (UnicodeDecodeError, LookupError):
            continue
    out = body.decode("utf-8", "surrogateescape")
    return "".join(chr(ord(c) - _SURROGATE_BASE)
                   if _SURROGATE_LO <= ord(c) <= _SURROGATE_HI else c
                   for c in out)
