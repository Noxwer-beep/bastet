"""Decoding tests — chains are the whole point, so they get fuzzed with real shapes."""

import os
import tempfile
import unittest

os.environ.setdefault("BASTET_DATA_DIR", tempfile.mkdtemp(prefix="bastet-test-"))

from bastet import codec  # noqa: E402


class TestBase64(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(codec.try_base64("aGVsbG8gd29ybGQ="), "hello world")

    def test_unpadded(self):
        self.assertEqual(codec.try_base64("aGVsbG8gd29ybGQ"), "hello world")

    def test_rejects_binary(self):
        self.assertIsNone(codec.try_base64("/w=="))

    def test_rejects_short(self):
        self.assertIsNone(codec.try_base64("abc"))

    def test_rejects_plain_text(self):
        self.assertIsNone(codec.try_base64("this is just a sentence"))


class TestHex(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(codec.try_hex("68656c6c6f"), "hello")

    def test_prefixed(self):
        self.assertEqual(codec.try_hex("0x68656c6c6f"), "hello")

    def test_odd_length(self):
        self.assertIsNone(codec.try_hex("68656c6c6"))

    def test_non_hex(self):
        self.assertIsNone(codec.try_hex("zzzzzzzzzzzzzzzz"))


class TestUrlHtml(unittest.TestCase):
    def test_url_decode(self):
        self.assertEqual(codec.try_url("hello%20world"), "hello world")

    def test_url_noop(self):
        self.assertIsNone(codec.try_url("hello world"))

    def test_html_decode(self):
        self.assertEqual(codec.try_html("&lt;script&gt;"), "<script>")

    def test_html_noop(self):
        self.assertIsNone(codec.try_html("plain"))


class TestChain(unittest.TestCase):
    def test_single_layer(self):
        chain = codec.decode_chain("aGVsbG8gd29ybGQ=")
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[0].kind, "input")
        self.assertEqual(chain[-1].value, "hello world")

    def test_peels_two_layers(self):
        # base64 of a 5-byte string carries padding, so url-encoding it is a real layer
        inner = "hello"
        once = codec.encode(inner, "base64")
        twice = codec.encode(once, "url")
        self.assertIn("%3D", twice)
        chain = codec.decode_chain(twice)
        self.assertEqual(chain[-1].value, inner)
        self.assertGreaterEqual(len(chain), 3)

    def test_plain_text_stays_plain(self):
        chain = codec.decode_chain("just a sentence about nothing")
        self.assertEqual(len(chain), 1)

    def test_stops_at_limit(self):
        text = "aGVsbG8gd29ybGQ="
        for _ in range(6):
            text = codec.encode(text, "base64")
        chain = codec.decode_chain(text, max_steps=2)
        self.assertEqual(len(chain), 3)

    def test_rot13_is_opt_in(self):
        self.assertEqual(len(codec.decode_chain("uryyb")), 1)
        self.assertEqual(codec.decode_chain("uryyb", include_rot13=True)[-1].value, "hello")


class TestEncode(unittest.TestCase):
    def test_roundtrip_each(self):
        text = "hello <world> & co=1"
        for kind in ("base64", "hex", "url", "html"):
            encoded = codec.encode(text, kind)
            self.assertNotEqual(encoded, text, kind)

    def test_html_leaves_plain_text_alone(self):
        self.assertEqual(codec.encode("hello world", "html"), "hello world")

    def test_base64url_has_no_padding(self):
        self.assertNotIn("=", codec.encode("a" * 9, "base64url"))

    def test_unknown_raises(self):
        with self.assertRaises(ValueError):
            codec.encode("x", "rot26")

    def test_rot13(self):
        self.assertEqual(codec.encode("hello", "rot13"), "uryyb")


if __name__ == "__main__":
    unittest.main()
