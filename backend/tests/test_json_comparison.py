import unittest

from json_comparison import fingerprints,valid_owner_pointer
import hashlib


class JsonComparisonTests(unittest.TestCase):
    def test_values_ignore_object_key_order_and_structure_ignores_values(self):
        first=fingerprints(b'{"a":1,"b":"x"}')
        reordered=fingerprints(b'{"b":"x","a":1}')
        changed=fingerprints(b'{"a":2,"b":"y"}')
        different_structure=fingerprints(b'{"a":2,"b":true}')
        self.assertEqual(first,reordered)
        self.assertNotEqual(first[0],changed[0])
        self.assertEqual(first[1],changed[1])
        self.assertNotEqual(first[1],different_structure[1])

    def test_rejects_ambiguous_invalid_or_excessive_input(self):
        for body in (b'{"a":1,"a":2}',b'{"a":NaN}',b'not-json',b'['*34+b'0'+b']'*34,b' '*32769):
            with self.subTest(body=body[:100]):
                self.assertEqual(fingerprints(body),(None,None))

    def test_owner_pointer_extracts_only_a_digest_and_handles_missing(self):
        body=b'{"data":{"owner/id":"account-a"}}'
        result=fingerprints(body,'/data/owner~1id')
        self.assertEqual(result[2],hashlib.sha256(b'account-a').digest())
        self.assertIsNone(fingerprints(body,'/data/missing')[2])
        self.assertFalse(valid_owner_pointer('/data/~2invalid'))
        self.assertFalse(valid_owner_pointer('/data//id'))
        self.assertTrue(valid_owner_pointer('/data/owner~1id'))
