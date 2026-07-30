from __future__ import annotations

from decimal import Decimal
import hashlib
import json
from pathlib import Path
import unittest

from quicperf_harness.canonical import (
    canonical_bytes,
    canonical_sha256,
    loads_strict,
    normalize_decimal,
)
from quicperf_harness.errors import CanonicalizationError
from quicperf_harness.identity import domain_hash


class StrictJsonTests(unittest.TestCase):
    def test_canonical_json_sorts_recursively_and_is_compact_utf8(self) -> None:
        value = {"z": [3, {"é": True, "a": None}], "a": "snowman ☃"}
        self.assertEqual(
            canonical_bytes(value),
            '{"a":"snowman ☃","z":[3,{"a":null,"é":true}]}'.encode(),
        )

    def test_duplicate_keys_are_rejected_at_every_depth(self) -> None:
        for document in ('{"a":1,"a":2}', '{"outer":{"x":1,"x":2}}'):
            with self.subTest(document=document), self.assertRaisesRegex(
                CanonicalizationError, "duplicate JSON key"
            ):
                loads_strict(document)

    def test_malformed_nonfinite_overflow_and_binary_float_are_rejected(self) -> None:
        documents = (
            "{",
            '{"n":NaN}',
            '{"n":Infinity}',
            '{"n":9223372036854775808}',
            '{"n":1e309}',
        )
        for document in documents:
            with self.subTest(document=document), self.assertRaises(CanonicalizationError):
                loads_strict(document)
        with self.assertRaisesRegex(CanonicalizationError, "binary floating-point"):
            canonical_bytes({"n": 0.1})

    def test_utf8_bom_invalid_utf8_and_surrogates_are_rejected(self) -> None:
        for document in (b"\xef\xbb\xbf{}", b'"\xff"'):
            with self.subTest(document=document), self.assertRaises(CanonicalizationError):
                loads_strict(document)
        with self.assertRaises(CanonicalizationError):
            canonical_bytes("\ud800")

    def test_decimal_has_one_normalized_string_form(self) -> None:
        cases = {
            Decimal("0.000"): "0",
            Decimal("-0"): "0",
            Decimal("12.3400"): "12.34",
            Decimal("1E+3"): "1000",
        }
        for value, expected in cases.items():
            self.assertEqual(normalize_decimal(value), expected)
            self.assertEqual(canonical_bytes(value), json.dumps(expected).encode())
        for invalid in ("+1", "01", "1.0", "1e3", " NaN"):
            with self.subTest(invalid=invalid), self.assertRaises(CanonicalizationError):
                normalize_decimal(invalid)

    def test_canonical_hash_uses_exact_bytes(self) -> None:
        value = {"b": 2, "a": 1}
        self.assertEqual(
            canonical_sha256(value), hashlib.sha256(b'{"a":1,"b":2}').hexdigest()
        )

    def test_domain_hash_length_prefix_prevents_ambiguous_field_splits(self) -> None:
        self.assertNotEqual(domain_hash("example", b"ab", b"c"), domain_hash("example", b"a", b"bc"))
        tag = b"example"
        expected = hashlib.sha256(
            b"quicperf-v2\0"
            + len(tag).to_bytes(4, "big")
            + tag
            + (2).to_bytes(8, "big")
            + b"ab"
            + (1).to_bytes(8, "big")
            + b"c"
        ).hexdigest()
        self.assertEqual(domain_hash("example", b"ab", b"c"), expected)


class SchemaDocumentTests(unittest.TestCase):
    def test_schema_documents_are_strict_json_with_closed_roots(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for path in sorted((root / "schemas").glob("*-v2.schema.json")):
            with self.subTest(path=path.name):
                schema = loads_strict(path.read_bytes())
                self.assertEqual(schema["type"], "object")
                self.assertIs(schema["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
