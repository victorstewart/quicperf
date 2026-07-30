"""Strict JSON loading and content-addressed canonical serialization."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
from typing import Any

from .errors import CanonicalizationError


MIN_I64 = -(1 << 63)
MAX_I64 = (1 << 63) - 1
MAX_DECIMAL_TOKEN_BYTES = 128
MAX_DECIMAL_ADJUSTED_EXPONENT = 308


def _reject_constant(token: str) -> None:
    raise CanonicalizationError(f"non-finite JSON number is forbidden: {token}")


def _parse_int(token: str) -> int:
    value = int(token, 10)
    if not MIN_I64 <= value <= MAX_I64:
        raise CanonicalizationError(f"integer exceeds signed 64-bit range: {token}")
    return value


def _parse_decimal(token: str) -> Decimal:
    if len(token.encode("ascii")) > MAX_DECIMAL_TOKEN_BYTES:
        raise CanonicalizationError("decimal token is unreasonably large")
    try:
        value = Decimal(token)
    except InvalidOperation as exc:
        raise CanonicalizationError(f"malformed decimal: {token}") from exc
    if not value.is_finite():
        raise CanonicalizationError("non-finite decimal is forbidden")
    if value and abs(value.adjusted()) > MAX_DECIMAL_ADJUSTED_EXPONENT:
        raise CanonicalizationError(f"decimal magnitude exceeds 1e{MAX_DECIMAL_ADJUSTED_EXPONENT}")
    return value


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def loads_strict(data: str | bytes | bytearray) -> Any:
    """Load one JSON value while rejecting duplicate keys and unsafe numbers."""

    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CanonicalizationError("JSON must be valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise CanonicalizationError("JSON input must be text or bytes")
    if text.startswith("\ufeff"):
        raise CanonicalizationError("a UTF-8 BOM is forbidden")
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_no_duplicates,
            parse_int=_parse_int,
            parse_float=_parse_decimal,
            parse_constant=_reject_constant,
        )
    except CanonicalizationError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise CanonicalizationError(f"malformed JSON: {exc}") from exc


def load_strict(path: str | Path) -> Any:
    try:
        return loads_strict(Path(path).read_bytes())
    except OSError as exc:
        raise CanonicalizationError(f"cannot read JSON file {path}: {exc}") from exc


def normalize_decimal(value: Decimal | str) -> str:
    """Return the sole accepted non-exponent decimal representation."""

    if isinstance(value, str):
        if not value or value.strip() != value or value.startswith("+"):
            raise CanonicalizationError(f"non-canonical decimal string: {value!r}")
        try:
            decimal = Decimal(value)
        except InvalidOperation as exc:
            raise CanonicalizationError(f"malformed decimal string: {value!r}") from exc
    elif isinstance(value, Decimal):
        decimal = value
    else:
        raise CanonicalizationError("decimal must be a Decimal or string")
    if not decimal.is_finite():
        raise CanonicalizationError("non-finite decimal is forbidden")
    if decimal and abs(decimal.adjusted()) > MAX_DECIMAL_ADJUSTED_EXPONENT:
        raise CanonicalizationError(f"decimal magnitude exceeds 1e{MAX_DECIMAL_ADJUSTED_EXPONENT}")
    if decimal.is_zero():
        normalized = "0"
    else:
        normalized = format(decimal, "f")
        if "." in normalized:
            normalized = normalized.rstrip("0").rstrip(".")
    if isinstance(value, str) and normalized != value:
        raise CanonicalizationError(
            f"decimal string must use normalized form {normalized!r}, got {value!r}"
        )
    return normalized


def _validate_string(value: str, *, what: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"{what} contains an invalid Unicode surrogate") from exc


def _canonical_fragment(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not MIN_I64 <= value <= MAX_I64:
            raise CanonicalizationError(f"integer exceeds signed 64-bit range: {value}")
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError("binary floating-point values are forbidden")
    if isinstance(value, Decimal):
        # Non-integers have one identity representation: a normalized JSON string.
        return json.dumps(normalize_decimal(value), ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, str):
        _validate_string(value, what="string")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, Mapping):
        items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object keys must be strings")
            _validate_string(key, what="object key")
            items.append((key, item))
        items.sort(key=lambda pair: pair[0].encode("utf-8"))
        return "{" + ",".join(
            f"{json.dumps(key, ensure_ascii=False, separators=(',', ':'))}:{_canonical_fragment(item)}"
            for key, item in items
        ) + "}"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "[" + ",".join(_canonical_fragment(item) for item in value) + "]"
    raise CanonicalizationError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Serialize a JSON-like value with stable recursive ordering and encoding."""

    return _canonical_fragment(value).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
