import socket
import struct
import unittest

from quicperf_harness.protocol import (
    HEADER,
    MAX_PACKET,
    MessageType,
    ProtocolError,
    SeqPacketChannel,
    decode_packet,
    encode_packet,
)


class ControlProtocolTests(unittest.TestCase):
    def test_arm_rejected_round_trip(self):
        fields = {
            "trial_id": b"a" * 32,
            "raw_now_ns": 456,
            "reason": "arm_window_not_in_future",
        }
        packet = encode_packet(MessageType.ARM_REJECTED, 1, fields)
        decoded = decode_packet(packet, expected_trial_id=fields["trial_id"])
        self.assertEqual(decoded.message_type, MessageType.ARM_REJECTED)
        self.assertEqual(decoded.fields, fields)

    def test_exercise_and_exercised_round_trip(self):
        trial = b"e" * 32
        exercise = {
            "trial_id": trial,
            "exercise_deadline_raw_ns": 123_456_789,
        }
        self.assertEqual(
            decode_packet(encode_packet(MessageType.EXERCISE, 1, exercise)).fields,
            exercise,
        )
        exercised = {
            "trial_id": trial,
            "live_connections": 16,
            "live_streams": 4,
            "live_tickets": 0,
            "work_inventory": 20,
        }
        self.assertEqual(
            decode_packet(encode_packet(MessageType.EXERCISED, 2, exercised)).fields,
            exercised,
        )

    def test_reset_ack_requires_exact_zero_state_inventory_fields(self):
        trial = b"r" * 32
        fields = {
            "trial_id": trial,
            "live_connections": 0,
            "live_streams": 0,
            "live_tickets": 0,
            "work_inventory": 0,
        }
        packet = encode_packet(MessageType.RESET_ACK, 1, fields)
        self.assertEqual(decode_packet(packet).fields, fields)
        with self.assertRaisesRegex(ProtocolError, "field mismatch"):
            encode_packet(MessageType.RESET_ACK, 1, {"trial_id": trial})

    def test_arm_golden_vector_round_trip(self):
        trial = bytes(range(32))
        fields = {
            "trial_id": trial,
            "warmup_start_raw_ns": 100,
            "measurement_start_raw_ns": 200,
            "measurement_end_raw_ns": 300,
            "trace_epoch_raw_ns": 200,
        }
        packet = encode_packet(MessageType.ARM, 9, fields)
        self.assertEqual(
            packet.hex(),
            "515043320001000600000068000000000000000000000009"
            "000b040000000020" + trial.hex() +
            "00120100000000080000000000000064"
            "001301000000000800000000000000c8"
            "0014010000000008000000000000012c"
            "001501000000000800000000000000c8",
        )
        self.assertEqual(decode_packet(packet, expected_sequence=9, expected_trial_id=trial).fields, fields)

    def test_rejects_truncation_length_duplicates_unknown_and_wrong_identity(self):
        trial = b"t" * 32
        packet = encode_packet(MessageType.RESET, 1, {"trial_id": trial})
        cases = [
            packet[:-1],
            packet + b"x",
            packet + packet[HEADER.size:],
            packet[:HEADER.size] + struct.pack("!HBBI", 77, 1, 0, 8) + b"\0" * 8,
        ]
        for malformed in cases:
            with self.subTest(data=malformed.hex()[:32]), self.assertRaises(ProtocolError):
                decode_packet(malformed)
        with self.assertRaisesRegex(ProtocolError, "wrong trial_id"):
            decode_packet(packet, expected_trial_id=b"x" * 32)
        with self.assertRaisesRegex(ProtocolError, "non-monotonic"):
            decode_packet(packet, expected_sequence=2)

    def test_unknown_optional_field_is_forward_compatible(self):
        base = encode_packet(MessageType.SHUTDOWN, 1, {})
        optional = struct.pack("!HBBI", 0x8001, 3, 0, 3) + b"new"
        magic, version, kind, length, flags, sequence = HEADER.unpack_from(base)
        packet = HEADER.pack(magic, version, kind, length + len(optional), flags, sequence) + optional
        self.assertEqual(decode_packet(packet).message_type, MessageType.SHUTDOWN)

    def test_seqpacket_channel_enforces_monotonic_packets(self):
        left_sock, right_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left_sock.close)
        self.addCleanup(right_sock.close)
        left = SeqPacketChannel(left_sock)
        right = SeqPacketChannel(right_sock)
        left.send(MessageType.HELLO, {"role": "server", "build_id": b"id", "control_version": 1})
        self.assertEqual(right.receive().fields["role"], "server")
        left_sock.send(encode_packet(MessageType.SHUTDOWN, 1, {}))
        with self.assertRaisesRegex(ProtocolError, "non-monotonic"):
            right.receive()

    def test_seqpacket_channel_distinguishes_peer_exit_from_malformed_packet(self):
        left_sock, right_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(right_sock.close)
        right = SeqPacketChannel(right_sock)
        left_sock.close()
        with self.assertRaisesRegex(ProtocolError, "control channel closed"):
            right.receive()

    def test_oversized_packet_is_rejected(self):
        with self.assertRaises(ProtocolError):
            decode_packet(b"x" * (MAX_PACKET + 1))


if __name__ == "__main__":
    unittest.main()
