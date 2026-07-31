from __future__ import annotations

import enum
import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAGIC = 0x51504332
VERSION = 1
MAX_PACKET = 65_536
HEADER = struct.Struct("!IHHIIQ")
TLV_HEADER = struct.Struct("!HBBI")
WIRE_U64 = 1
WIRE_I64 = 2
WIRE_UTF8 = 3
WIRE_BYTES = 4
WIRE_BOOL = 5


class ProtocolError(ValueError):
    pass


_DEFINITION_PATH = Path(__file__).resolve().parents[1] / "schemas" / "control-v1-fields.json"
_DEFINITION = json.loads(_DEFINITION_PATH.read_text(encoding="utf-8"))


MessageType = enum.IntEnum(
    "MessageType",
    {name: int(definition["id"]) for name, definition in _DEFINITION["messages"].items()},
)


@dataclass(frozen=True)
class FieldSpec:
    field_id: int
    wire_type: int


MESSAGE_FIELDS: dict[MessageType, dict[str, FieldSpec]] = {
    MessageType[name]: {
        field: FieldSpec(int(spec[0]), int(spec[1]))
        for field, spec in definition["required"].items()
    }
    for name, definition in _DEFINITION["messages"].items()
}
FIELD_BY_ID = {
    spec.field_id: (name, spec)
    for fields in MESSAGE_FIELDS.values()
    for name, spec in fields.items()
}


@dataclass(frozen=True)
class Packet:
    message_type: MessageType
    sequence: int
    flags: int
    fields: dict[str, Any]


def _encode_value(wire_type: int, value: Any) -> bytes:
    if wire_type == WIRE_U64:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
            raise ProtocolError("u64 field is out of range")
        return struct.pack("!Q", value)
    if wire_type == WIRE_I64:
        if isinstance(value, bool) or not isinstance(value, int) or not -(1 << 63) <= value < (1 << 63):
            raise ProtocolError("i64 field is out of range")
        return struct.pack("!q", value)
    if wire_type == WIRE_UTF8:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ProtocolError("UTF-8 field must be a nonempty NUL-free string")
        try:
            return value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ProtocolError("invalid UTF-8 field") from exc
    if wire_type == WIRE_BYTES:
        if not isinstance(value, bytes):
            raise ProtocolError("raw field must be bytes")
        return value
    if wire_type == WIRE_BOOL:
        if type(value) is not bool:
            raise ProtocolError("boolean field must be bool")
        return bytes((int(value),))
    raise ProtocolError(f"unknown wire type {wire_type}")


def _decode_value(wire_type: int, data: bytes) -> Any:
    if wire_type == WIRE_U64:
        if len(data) != 8:
            raise ProtocolError("u64 field length is not eight")
        return struct.unpack("!Q", data)[0]
    if wire_type == WIRE_I64:
        if len(data) != 8:
            raise ProtocolError("i64 field length is not eight")
        return struct.unpack("!q", data)[0]
    if wire_type == WIRE_UTF8:
        try:
            value = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ProtocolError("invalid UTF-8 field") from exc
        if not value or "\x00" in value:
            raise ProtocolError("UTF-8 field must be nonempty and NUL-free")
        return value
    if wire_type == WIRE_BYTES:
        return data
    if wire_type == WIRE_BOOL:
        if data not in {b"\x00", b"\x01"}:
            raise ProtocolError("invalid boolean field")
        return data == b"\x01"
    raise ProtocolError(f"unknown wire type {wire_type}")


def encode_packet(message_type: MessageType, sequence: int, fields: dict[str, Any], *, flags: int = 0) -> bytes:
    if not isinstance(message_type, MessageType):
        raise ProtocolError("invalid message type")
    if not 1 <= sequence <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ProtocolError("sequence must be positive u64")
    if not 0 <= flags <= 0xFFFF_FFFF:
        raise ProtocolError("flags are out of range")
    expected = MESSAGE_FIELDS[message_type]
    if set(fields) != set(expected):
        missing = sorted(set(expected) - set(fields))
        unknown = sorted(set(fields) - set(expected))
        raise ProtocolError(f"field mismatch missing={missing} unknown={unknown}")
    payload = bytearray()
    for name, spec in sorted(expected.items(), key=lambda item: item[1].field_id):
        encoded = _encode_value(spec.wire_type, fields[name])
        payload.extend(TLV_HEADER.pack(spec.field_id, spec.wire_type, 0, len(encoded)))
        payload.extend(encoded)
    packet = HEADER.pack(MAGIC, VERSION, int(message_type), len(payload), flags, sequence) + payload
    if len(packet) > MAX_PACKET:
        raise ProtocolError("packet exceeds 64 KiB")
    return bytes(packet)


def decode_packet(
    data: bytes,
    *,
    expected_sequence: int | None = None,
    expected_trial_id: bytes | None = None,
) -> Packet:
    if not isinstance(data, bytes) or len(data) < HEADER.size or len(data) > MAX_PACKET:
        raise ProtocolError("invalid packet size")
    magic, version, raw_type, payload_length, flags, sequence = HEADER.unpack_from(data)
    if magic != MAGIC or version != VERSION:
        raise ProtocolError("bad magic or protocol version")
    try:
        message_type = MessageType(raw_type)
    except ValueError as exc:
        raise ProtocolError("unknown message type") from exc
    if payload_length != len(data) - HEADER.size:
        raise ProtocolError("payload length mismatch or trailing bytes")
    if sequence == 0 or (expected_sequence is not None and sequence != expected_sequence):
        raise ProtocolError("non-monotonic sequence")
    expected = MESSAGE_FIELDS[message_type]
    expected_by_id = {spec.field_id: (name, spec) for name, spec in expected.items()}
    offset = HEADER.size
    fields: dict[str, Any] = {}
    seen_ids: set[int] = set()
    while offset < len(data):
        if len(data) - offset < TLV_HEADER.size:
            raise ProtocolError("truncated TLV header")
        field_id, wire_type, reserved, length = TLV_HEADER.unpack_from(data, offset)
        offset += TLV_HEADER.size
        if reserved != 0 or length > len(data) - offset:
            raise ProtocolError("malformed TLV length or reserved byte")
        if field_id in seen_ids:
            raise ProtocolError("duplicate field")
        seen_ids.add(field_id)
        value_bytes = data[offset : offset + length]
        offset += length
        known = expected_by_id.get(field_id)
        if known is None:
            if field_id & 0x8000:
                continue
            raise ProtocolError("unknown required field")
        name, spec = known
        if wire_type != spec.wire_type:
            raise ProtocolError("wire type mismatch")
        fields[name] = _decode_value(wire_type, value_bytes)
    missing = set(expected) - set(fields)
    if missing:
        raise ProtocolError(f"missing required fields: {sorted(missing)}")
    if "trial_id" in fields:
        if len(fields["trial_id"]) != 32:
            raise ProtocolError("trial_id must be 32 bytes")
        if expected_trial_id is not None and fields["trial_id"] != expected_trial_id:
            raise ProtocolError("wrong trial_id")
    if "cell_id" in fields and len(fields["cell_id"]) != 32:
        raise ProtocolError("cell_id must be 32 bytes")
    return Packet(message_type, sequence, flags, fields)


class SeqPacketChannel:
    def __init__(self, sock: socket.socket):
        if sock.type & socket.SOCK_SEQPACKET != socket.SOCK_SEQPACKET:
            raise ProtocolError("control socket must be SOCK_SEQPACKET")
        self.sock = sock
        self.send_sequence = 0
        self.receive_sequence = 0

    def send(self, message_type: MessageType, fields: dict[str, Any], *, flags: int = 0) -> None:
        self.send_sequence += 1
        packet = encode_packet(message_type, self.send_sequence, fields, flags=flags)
        if self.sock.send(packet) != len(packet):
            raise ProtocolError("short control send")

    def receive(self, *, expected_trial_id: bytes | None = None) -> Packet:
        data, _ancillary, msg_flags, _address = self.sock.recvmsg(MAX_PACKET)
        if msg_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise ProtocolError("truncated control packet")
        if not data:
            raise ProtocolError("control channel closed")
        packet = decode_packet(data, expected_sequence=self.receive_sequence + 1, expected_trial_id=expected_trial_id)
        self.receive_sequence = packet.sequence
        return packet
