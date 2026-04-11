import unittest
import os
import tempfile
from run_pipeline import parse_makefile, _is_fake_target, get_trace_flag

class TestMakefileParser(unittest.TestCase):
    def test_is_fake_target(self):
        # ALL_CAPS variables are fake targets
        self.assertTrue(_is_fake_target("VAR_NAME"))
        self.assertTrue(_is_fake_target("CGO_ENABLED"))
        
        # Real targets include lower case and files
        self.assertFalse(_is_fake_target("build"))
        self.assertFalse(_is_fake_target("test"))
        self.assertFalse(_is_fake_target("bin/server"))
        self.assertFalse(_is_fake_target(".build-cache"))

    def test_get_trace_flag(self):
        # test, vet, lint should be excluded
        self.assertIsNone(get_trace_flag("test", "deep"))
        self.assertIsNone(get_trace_flag("go-test", "deep"))
        self.assertIsNone(get_trace_flag("lint", "deep"))
        self.assertIsNone(get_trace_flag("go-vet-code", "deep"))

        # exact matches should be included based on deep mode
        self.assertEqual(get_trace_flag("build", "deep"), "--trace")
        self.assertIsNone(get_trace_flag("build", "quick"))
        
        self.assertEqual(get_trace_flag("fmt", "deep"), "--trace")

    def test_parse_makefile(self):
        content = """
# comment
.PHONY: all build test

all: build

build: test
\tgo build -o bin/server .

test:
\tgo test ./...

bin/server:
\tgo build -o bin/server .

VAR_NAME:
\t@echo "var"
"""
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(content)
            f.flush()
            targets = parse_makefile(f.name)
            os.unlink(f.name)
            
        self.assertNotIn("all", targets) # Skipped by GLOBAL_SKIP
        self.assertIn("build", targets)
        self.assertIn("test", targets)
        self.assertIn("bin/server", targets)
        self.assertNotIn("VAR_NAME", targets)

if __name__ == '__main__':
    unittest.main()
