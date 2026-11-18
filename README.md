# Outis

Outis is a procedural personal-data filter for private corpus instances: an ingress scanner, an egress gate over what is actually
embedded, a scrubber that quarantines originals and invalidates the embeddings of anything it touches, and the tests that prove each
detector can fail. Python 3, standard library only, no network, no model.

The package lives in `pkg/`. Start with `pkg/README.md` (install, prove, scan, rule, scrub, re-embed, gate, record) and
`pkg/PROCEDURE.md` (the collaboration procedure, including how names are found without a language model). The rulings file and the
member roster are local inputs the package never ships; see `pkg/RULINGS.template`.

`make_release.sh` builds the reproducible archive `outis-<version>.tar.gz` and refuses unless the suite and both gates pass; the
current archive's digest is in `outis-<version>.tar.gz.sha256`.

License: `pkg/LICENSE` -- private to the collaboration and to any other non-commercial entity that supplies its own PII-gate database.

The name: Outis is the Greek for "nobody", the name Odysseus gives so that no one can be called out by name. Every person in a
filtered corpus becomes nobody; only the work stays.
