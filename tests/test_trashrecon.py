"""Unit tests for TrashRecon's pure helper functions.

Run from the repo root with:

    python3 -m unittest discover -s tests -v

No third-party dependencies — stdlib unittest only.
"""

import argparse
import os
import sys
import unittest
from unittest import mock

# Make the top-level trashrecon.py importable when run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import trashrecon as tr  # noqa: E402


def _write(path, text):
    with open(path, 'w') as f:
        f.write(text)


class ValidateDomainTests(unittest.TestCase):
    def test_valid(self):
        for d in ('example.com', 'a.example.com', 'a-b.example.co.uk', 'x.y.z.io'):
            self.assertTrue(tr.validate_domain(d), d)

    def test_invalid(self):
        for d in ('not a domain', 'example', 'http://example.com',
                  'example..com', '-example.com', 'example.com/', ''):
            self.assertFalse(tr.validate_domain(d), d)

    def test_too_long(self):
        self.assertFalse(tr.validate_domain('a.' * 130 + 'com'))


class InScopeTests(unittest.TestCase):
    def test_accepts_domain_and_subdomains(self):
        self.assertTrue(tr.in_scope('example.com', 'example.com'))
        self.assertTrue(tr.in_scope('a.example.com', 'example.com'))
        self.assertTrue(tr.in_scope('a.b.example.com', 'example.com'))
        self.assertTrue(tr.in_scope('A.Example.COM', 'example.com'))
        self.assertTrue(tr.in_scope('a.example.com.', 'example.com'))

    def test_rejects_lookalikes(self):
        # The substring-matching bug this replaces would wrongly accept these.
        self.assertFalse(tr.in_scope('example.com.evil.net', 'example.com'))
        self.assertFalse(tr.in_scope('notexample.com', 'example.com'))
        self.assertFalse(tr.in_scope('fooexample.com', 'example.com'))
        self.assertFalse(tr.in_scope('example.community', 'example.com'))


class ParseSkipPhasesTests(unittest.TestCase):
    def test_valid_list_and_whitespace(self):
        self.assertEqual(tr.parse_skip_phases('4,5,10'), {4, 5, 10})
        self.assertEqual(tr.parse_skip_phases(' 1 , 2 ,'), {1, 2})
        self.assertEqual(tr.parse_skip_phases(''), set())

    def test_non_integer_raises(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            tr.parse_skip_phases('4,foo')

    def test_out_of_range_raises(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            tr.parse_skip_phases('0')
        with self.assertRaises(argparse.ArgumentTypeError):
            tr.parse_skip_phases('11')


class FileHelperTests(unittest.TestCase):
    def setUp(self):
        self._tmp = __import__('tempfile').TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def p(self, name):
        return os.path.join(self.tmp, name)

    def test_count_and_read_lines(self):
        _write(self.p('a.txt'), 'one\n\ntwo\n  \nthree\n')
        self.assertEqual(tr.count_lines(self.p('a.txt')), 3)
        self.assertEqual(tr.read_lines(self.p('a.txt')), ['one', 'two', 'three'])

    def test_missing_file(self):
        self.assertEqual(tr.count_lines(self.p('nope.txt')), 0)
        self.assertEqual(tr.read_lines(self.p('nope.txt')), [])

    def test_merge_files_dedup_sort_and_skip_missing(self):
        _write(self.p('a.txt'), 'b\na\nb\n')
        _write(self.p('b.txt'), 'c\na\n')
        n = tr.merge_files([self.p('a.txt'), self.p('b.txt'), self.p('missing.txt')],
                           self.p('out.txt'))
        self.assertEqual(n, 3)
        self.assertEqual(tr.read_lines(self.p('out.txt')), ['a', 'b', 'c'])

    def test_extract_hostnames_scopes_correctly(self):
        _write(self.p('in.txt'),
               'https://a.example.com/path?x=1\n'
               'example.com\n'
               'http://b.example.com\n'
               'https://example.com.evil.net/login\n'   # out of scope
               'notexample.com\n'                        # out of scope
               'sub.other.org\n')                         # out of scope
        n = tr.extract_hostnames(self.p('in.txt'), self.p('out.txt'),
                                 filter_domain='example.com')
        self.assertEqual(n, 3)
        self.assertEqual(tr.read_lines(self.p('out.txt')),
                         ['a.example.com', 'b.example.com', 'example.com'])

    def test_extract_hostnames_no_filter(self):
        _write(self.p('in.txt'), 'a.example.com\nsub.other.org\n')
        n = tr.extract_hostnames(self.p('in.txt'), self.p('out.txt'))
        self.assertEqual(n, 2)

    def test_parse_asn_output(self):
        _write(self.p('asn.jsonl'),
               '{"as_number": 13335, "as_range": ["1.1.1.0/24", "1.0.0.0/24"]}\n'
               '{"as_number": 13335, "as_range": ["1.1.1.0/24"]}\n'
               'not-json\n'
               '{"as_number": 15169, "as_range": ["8.8.8.0/24"]}\n')
        asn_count, cidr_count = tr.parse_asn_output(self.p('asn.jsonl'),
                                                    self.p('cidr.txt'))
        self.assertEqual(asn_count, 2)
        self.assertEqual(cidr_count, 3)
        self.assertEqual(tr.read_lines(self.p('cidr.txt')),
                         ['1.0.0.0/24', '1.1.1.0/24', '8.8.8.0/24'])


class CheckDependenciesTests(unittest.TestCase):
    def test_respects_skip_and_reports_missing(self):
        # Only nuclei (phase 10) is "installed"; everything else missing.
        def fake_which(tool):
            return '/usr/bin/' + tool if tool == 'nuclei' else None

        with mock.patch('trashrecon.shutil.which', side_effect=fake_which):
            # Skip every phase except 10 -> only nuclei required -> present -> none missing.
            self.assertEqual(tr.check_dependencies({1, 2, 3, 4, 5, 6, 7, 8, 9}), [])
            # Skip nothing -> phase 6 needs subzy (missing) -> appears in result.
            missing = tr.check_dependencies(set())
            self.assertIn('subzy', missing)
            self.assertNotIn('nuclei', missing)
            self.assertEqual(missing, sorted(missing))


if __name__ == '__main__':
    unittest.main()
