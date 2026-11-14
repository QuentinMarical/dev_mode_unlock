# -*- coding: utf-8 -*-
"""Tests unitaires de dev_mode_unlock.py (bibliothèque standard uniquement).

Lancer depuis la racine du dépôt :
    python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import dev_mode_unlock as dmu  # noqa: E402


class AesTests(unittest.TestCase):
    def test_aes256_fips197_vector(self):
        # Vecteur de test FIPS-197, annexe C.3 (AES-256).
        key = bytes(range(32))
        plain = bytes.fromhex('00112233445566778899aabbccddeeff')
        expected = bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')
        self.assertEqual(dmu._aes256_ecb(plain, key), expected)

    def test_aes256_ecb_multiple_blocks(self):
        key = bytes(range(32))
        plain = bytes.fromhex('00112233445566778899aabbccddeeff') * 2
        out = dmu._aes256_ecb(plain, key)
        expected = bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')
        # ECB : deux blocs identiques donnent deux sorties identiques.
        self.assertEqual(out, expected + expected)


class PaddingTests(unittest.TestCase):
    def test_pkcs7_full_block_when_aligned(self):
        self.assertEqual(dmu._pkcs7(b'A' * 16), b'A' * 16 + bytes([16]) * 16)

    def test_pkcs7_pads_to_block(self):
        self.assertEqual(dmu._pkcs7(b'abc'), b'abc' + bytes([13]) * 13)
        self.assertEqual(len(dmu._pkcs7(b'abc')) % 16, 0)


class DexTests(unittest.TestCase):
    def test_uleb128(self):
        # 624485 est encodé en ULEB128 par E5 8E 26.
        self.assertEqual(dmu._uleb(bytes([0xe5, 0x8e, 0x26]), 0), (624485, 3))

    def test_dex_strings_rejects_invalid_header(self):
        with self.assertRaises(ValueError):
            dmu.dex_strings(b'\x00' * 10)
        with self.assertRaises(ValueError):
            dmu.dex_strings(b'pas un dex' + b'\x00' * 200)


class ComputePinTests(unittest.TestCase):
    def test_format_six_lowercase_chars(self):
        pin = dmu.compute_pin('1234567890AB', 'aa' * 16)
        self.assertEqual(len(pin), 6)
        self.assertEqual(pin, pin.lower())

    def test_deterministic(self):
        a = dmu.compute_pin('SN123', '0123456789abcdef' * 2)
        b = dmu.compute_pin('SN123', '0123456789abcdef' * 2)
        self.assertEqual(a, b)

    def test_depends_on_serial(self):
        secret = '0123456789abcdef' * 2
        self.assertNotEqual(dmu.compute_pin('SN1', secret), dmu.compute_pin('SN2', secret))


class AnalyzeTests(unittest.TestCase):
    def _make_apk(self, members):
        fd, path = tempfile.mkstemp(suffix='.apk')
        os.close(fd)
        self.addCleanup(os.remove, path)
        with zipfile.ZipFile(path, 'w') as z:
            for name, data in members.items():
                z.writestr(name, data)
        return path

    def test_apk_without_dex(self):
        path = self._make_apk({'AndroidManifest.xml': b'<manifest/>'})
        r = dmu.analyze(path)
        self.assertIsNone(r['aes_const'])
        self.assertIsNone(r['fixed_pin'])
        self.assertFalse(r['saw_aes'])
        self.assertFalse(r['saw_pin'])
        self.assertEqual(r['errors'], [])

    def test_corrupt_dex_reports_error_instead_of_hiding_it(self):
        # Un DEX qui contient le marqueur mais est tronqué doit produire une erreur signalée.
        broken = dmu.AES_MARKER + b'\x00' * 8
        path = self._make_apk({'classes.dex': broken})
        r = dmu.analyze(path)
        self.assertTrue(r['saw_aes'])
        self.assertTrue(r['errors'])
        self.assertIn('classes.dex', r['errors'][0])

    def test_not_a_zip_raises(self):
        fd, path = tempfile.mkstemp(suffix='.apk')
        with os.fdopen(fd, 'wb') as f:
            f.write(b'pas une archive')
        self.addCleanup(os.remove, path)
        with self.assertRaises(zipfile.BadZipFile):
            dmu.analyze(path)


if __name__ == '__main__':
    unittest.main()
