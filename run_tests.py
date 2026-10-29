"""
AEGIS Test Runner — Executes tests via pytest (if installed) or native test runner.
"""

from __future__ import annotations

import importlib
import inspect
import sys
import time
import unittest
from pathlib import Path


def main() -> int:
    """Run all AEGIS tests."""
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root))

    try:
        import pytest
        print("Running tests via pytest...")
        return pytest.main(["-v", str(root / "tests")])
    except ImportError:
        print("pytest not installed; using AEGIS unified test discovery runner...\n")

        test_dir = root / "tests"
        test_files = sorted(test_dir.glob("test_*.py"))
        total_tests = 0
        failed_tests = 0
        start_time = time.time()

        for test_file in test_files:
            mod_name = f"tests.{test_file.stem}"
            try:
                mod = importlib.import_module(mod_name)
            except Exception as e:
                print(f"[ERROR] Failed to import {mod_name}: {e}")
                failed_tests += 1
                continue

            # 1. Run unittest.TestCase classes in module
            suite = unittest.defaultTestLoader.loadTestsFromModule(mod)
            if suite.countTestCases() > 0:
                runner = unittest.TextTestRunner(verbosity=1)
                result = runner.run(suite)
                total_tests += result.testsRun
                failed_tests += len(result.failures) + len(result.errors)

            # 2. Run standalone test_* functions in module
            for attr_name in dir(mod):
                if attr_name.startswith("test_") and inspect.isfunction(getattr(mod, attr_name)):
                    func = getattr(mod, attr_name)
                    total_tests += 1
                    try:
                        func()
                        print(f"  {test_file.name}::{attr_name} ... ok")
                    except Exception as e:
                        failed_tests += 1
                        print(f"  {test_file.name}::{attr_name} ... FAILED: {e}")

        duration = time.time() - start_time
        print(f"\nRan {total_tests} tests in {duration:.3f}s")
        if failed_tests == 0:
            print("OK - ALL TESTS PASSED!")
            return 0
        else:
            print(f"FAILED ({failed_tests} failure(s))")
            return 1


if __name__ == "__main__":
    sys.exit(main())
