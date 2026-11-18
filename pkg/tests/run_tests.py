#!/usr/bin/env python3
"""run_tests.py -- the suite runner. Standard library only.

    python3 tests/run_tests.py          # from the package root, or anywhere

Equivalent to `python3 -m unittest discover -s tests` run from the package
root; the exit status is the runner's own (0 all passed, 1 any failure or
error, 5 when no test ran). Never read it through a pipe.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.dont_write_bytecode = True
    sys.path.insert(0, HERE)
    suite = unittest.defaultTestLoader.discover(HERE, top_level_dir=HERE)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if result.testsRun == 0:
        return 5
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
