import hashlib
import sqlite3
import tempfile
import unittest
import sys
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from portable_evidence import export_originals, import_originals


class PortableEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / 'evidence.sqlite3'
        self.text = 'synthetic confidential evidence'
        self.digest = hashlib.sha256(self.text.encode()).hexdigest()
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE security_evidence(id TEXT PRIMARY KEY, original_hash TEXT)')
            db.execute('CREATE TABLE security_evidence_originals(evidence_id TEXT PRIMARY KEY, cipher BLOB)')
            db.execute('INSERT INTO security_evidence VALUES (?,?)', ('e1', self.digest))
            db.execute('INSERT INTO security_evidence_originals VALUES (?,?)', ('e1', b'account-a-cipher'))

    def tearDown(self):
        self.temp.cleanup()

    def cipher(self):
        with closing(sqlite3.connect(self.db)) as db:
            return db.execute('SELECT cipher FROM security_evidence_originals').fetchone()[0]

    def test_transfer_reprotects_for_destination_and_rejects_wrong_password(self):
        with patch('evidence_archive.available', return_value=True), patch('evidence_archive.unprotect', return_value=self.text):
            encrypted = export_originals(self.db, 'long safe passphrase')
        self.assertNotIn(self.text.encode(), encrypted)
        with patch('evidence_archive.available', return_value=True), patch('evidence_archive.protect', return_value=b'account-b-cipher') as protect:
            with self.assertRaises(ValueError):
                import_originals(self.db, encrypted, 'incorrect passphrase')
            self.assertEqual(self.cipher(), b'account-a-cipher')
            import_originals(self.db, encrypted, 'long safe passphrase')
            protect.assert_called_once_with(self.text, 'e1', self.digest)
        self.assertEqual(self.cipher(), b'account-b-cipher')

    def test_missing_passphrase_and_wrong_source_account_fail(self):
        with self.assertRaises(ValueError):
            export_originals(self.db, None)
        with patch('evidence_archive.available', return_value=True), patch('evidence_archive.unprotect', side_effect=ValueError('wrong user')):
            with self.assertRaises(ValueError):
                export_originals(self.db, 'long safe passphrase')

    @unittest.skipUnless(sys.platform == 'win32', 'DPAPI requires Windows')
    def test_real_dpapi_roundtrip_on_current_account(self):
        import evidence_archive
        if not evidence_archive.available():
            self.skipTest('win32crypt unavailable')
        with closing(sqlite3.connect(self.db)) as db, db:
            cipher = evidence_archive.protect(self.text, 'e1', self.digest)
            db.execute('UPDATE security_evidence_originals SET cipher=?', (cipher,))
        encrypted = export_originals(self.db, 'long safe passphrase')
        import_originals(self.db, encrypted, 'long safe passphrase')
        self.assertEqual(evidence_archive.unprotect(self.cipher(), 'e1', self.digest), self.text)


if __name__ == '__main__':
    unittest.main()
