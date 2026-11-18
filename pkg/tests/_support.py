"""Shared test support: the oracle-provenance convention and synthetic fixtures.

ORACLE PROVENANCE. Every test declares where its authority comes from, with
`@oracle(cls, authority)`. The classes, by logical power:

  VERIFICATION-CAPABLE -- can establish correctness, not merely detect error
    external      authority outside this package: an RFC, a published format,
                  POSIX path semantics. Nobody here can be wrong about it in a
                  way that makes the test agree with the code.
    human         a human-ratified requirement (on the reference instance, a
                  ruling by its privacy owner; the authority string says which).

  REFUTATION-ONLY -- sound but incomplete: flags real errors, proves nothing
    spec          a requirement stated in this package's own documents.
    metamorphic   a relation that holds without knowing the right answer
                  (idempotence, convergence, byte identity).
    structural    internal consistency of a structure against itself.

  NOT AN ORACLE
    implementation  the assertion restates the code. Kept only as a drift net.

An untagged test is an error, not a default: tests/test_package.py fails the
suite when any test method lacks a valid tag (the pytest-free form of the
reference instance's collection-time refusal).

SYNTHETIC FIXTURES. No literal in this package may itself be personal-data
shaped, or the package fails its own gate (and a real value travels as a test
case). So every value a detector must FIRE on is ASSEMBLED AT RUN TIME from
fragments: the source holds `"jdoe" + AT + site("lab")`, and the assembled
address exists only in memory while the test runs.

Domains: values that must PASS use the RFC 2606 reserved names (example.org,
.invalid, .test), which the scanner excuses by design. Values that must BLOCK
cannot use them for exactly that reason, so they use the top-level label `zz`
-- an ISO 3166-1 user-assigned code, never delegated as a country-code TLD --
which no real mailbox can carry. Names are generic placeholders (jdoe, jsmith,
A. Person).
"""

import os
import subprocess
import sys

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PKG not in sys.path:
    sys.path.insert(0, PKG)

# Hermetic: a PII_RULINGS set in the caller's shell must not leak into tests.
os.environ.pop("PII_RULINGS", None)

CLASSES = {
    "external": "verification-capable",
    "human": "verification-capable",
    "spec": "refutation-only",
    "metamorphic": "refutation-only",
    "structural": "refutation-only",
    "implementation": "NOT AN ORACLE (tautology)",
}


def oracle(cls, authority):
    """Tag a test with its oracle class and authority. Refuses unknown classes."""
    if cls not in CLASSES:
        raise ValueError("unknown oracle class %r; expected one of %s"
                         % (cls, ", ".join(sorted(CLASSES))))
    if not authority or not authority.strip():
        raise ValueError("an oracle tag needs an authority string")

    def deco(fn):
        fn.__oracle__ = (cls, authority)
        return fn
    return deco


# --- synthetic fragments ------------------------------------------------------
AT = "@"
TLD = "z" + "z"
HOME = "/" + "home" + "/"


def site(label="lab"):
    """A must-block domain: <label>.zz (never a real mailbox domain)."""
    return label + "." + TLD


def addr(local="a.person", label="lab"):
    """A must-block address assembled at run time."""
    return local + AT + site(label)


def home(*parts):
    """/home/<parts...> assembled at run time."""
    return HOME + "/".join(parts)


def orcid():
    """A synthetic ORCID-shaped identifier (not a registered iD)."""
    return "0000-0001-" + "2345-678X"


def privkey_armour():
    return "-----BEGIN OPENSSH PRIVATE" + " KEY-----"


def gitlab_token():
    return "glpat" + "-" + "AbCdEf0123456789xyz"


def assign(key, value, quote='"'):
    """`key = "value"` assembled so the literal never appears in the source."""
    return key + " = " + quote + value + quote


# --- running the tools ----------------------------------------------------------
def clean_env(**extra):
    env = dict(os.environ)
    env.pop("PII_RULINGS", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra)
    return env


def run_tool(script, *args, **kw):
    """Run a package CLI as a subprocess; never through a pipe."""
    env = kw.pop("env", None) or clean_env()
    return subprocess.run([sys.executable, os.path.join(PKG, script)] + list(args),
                          capture_output=True, text=True, env=env, **kw)
