from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATCH_OWNERS = {
    "folly",
    "lsquic",
    "mvfst",
    "neqosource",
    "ngtcp2",
    "noqsource",
    "nssquicperf",
    "nssrssource",
    "picoquic",
    "quiche",
    "quiczig",
    "quinnsource",
    "s2nsource",
    "tquic",
    "xquic",
}
GIT_OID = r"[0-9a-f]{40}"


class V2DependencyPatchTests(unittest.TestCase):
    def test_every_source_patch_is_depofile_owned_and_tree_pinned(self) -> None:
        owners: set[str] = set()
        for path in sorted((ROOT / "depofiles").glob("*.DepoFile")):
            text = path.read_text(encoding="utf-8")
            has_patch = "QUICPERF_DEPENDENCY_PATCH" in text
            self.assertEqual(has_patch, "git -C \"$source_dir\" apply" in text, path.name)
            if not has_patch:
                continue

            owners.add(path.stem)
            self.assertRegex(text, rf"SOURCE GIT \S+ {GIT_OID}")
            self.assertRegex(
                text,
                rf"rev-parse HEAD\)\" = \"{GIT_OID}\"",
            )
            self.assertRegex(
                text,
                rf"rev-parse 'HEAD\^\{{tree\}}'\)\" = \"{GIT_OID}\"",
            )
            self.assertIn("source_index=\"$DEPO_BUILD_DIR/quicperf-source.index\"", text)
            self.assertRegex(
                text,
                r"GIT_INDEX_FILE=\"\$source_index\" git -C \"\$source_dir\" "
                r"apply (?:--unidiff-zero )?--cached \"\$patch_file\"",
            )
            self.assertIn(
                "GIT_INDEX_FILE=\"$source_index\" git -C \"$source_dir\" "
                "diff --quiet --no-ext-diff -- .",
                text,
            )
            self.assertRegex(
                text,
                rf"write-tree\)\" = \"{GIT_OID}\"",
            )
            self.assertRegex(
                text,
                r"apply (?:--unidiff-zero )?--check \"\$(?:patch_file|current_patch)\"",
            )
            self.assertIn("patch does not match pinned source", text)

        self.assertEqual(owners, PATCH_OWNERS)

    def test_top_level_builds_only_consume_depofile_outputs(self) -> None:
        for relative in (
            "CMakeLists.txt",
            "rust-packet-ffi/Cargo.toml",
            "zig-packet-ffi/build.zig.zon",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("git apply", text, relative)
            self.assertNotIn("QUICPERF_DEPENDENCY_PATCH", text, relative)

        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("quinnsource::source", cmake)
        self.assertIn("noqsource::source", cmake)
        self.assertIn("neqosource::source", cmake)
        self.assertIn("nssrssource::source", cmake)
        self.assertIn("quiczig::source", cmake)

    def test_folly_source_compatibility_change_is_an_embedded_patch(self) -> None:
        text = (ROOT / "depofiles" / "folly.DepoFile").read_text(encoding="utf-8")
        build = text.split("CMAKE_BUILD_SH <<'EOF'", 1)[1].split("\nEOF", 1)[0]
        self.assertIn("diff --git a/folly/io/async/ssl/OpenSSLUtils.cpp", build)
        self.assertIn("diff --git a/folly/ssl/OpenSSLCertUtils.cpp", build)
        self.assertNotIn("perl -0pi", build)

    def test_quiczig_keeps_quic_tls_early_data_wire_sentinel(self) -> None:
        text = (ROOT / "depofiles" / "quiczig.DepoFile").read_text(encoding="utf-8")
        self.assertNotIn(
            "+        std.mem.writeInt(u32, nst[nst_pos..][0..4], 4096, .big);",
            text,
        )
        self.assertNotIn(
            "-        std.mem.writeInt(u32, nst[nst_pos..][0..4], 0xffffffff, .big);",
            text,
        )

    def test_zero_application_close_codes_remain_application_errors(self) -> None:
        lsquic = (ROOT / "depofiles" / "lsquic.DepoFile").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            lsquic.count(
                "+    if (conn->ifc_error.u.err != 0 || "
                "conn->ifc_error.app_error)"
            ),
            2,
        )

        xquic = (ROOT / "depofiles" / "xquic.DepoFile").read_text(
            encoding="utf-8"
        )
        self.assertIn("VERSION 1.9.2-quicperf12", xquic)
        self.assertIn("+xqc_conn_close_application", xquic)
        self.assertIn("+    conn->local_application_close = XQC_TRUE;", xquic)
        self.assertIn(
            "-    if (stream->stream_state_send < XQC_SEND_STREAM_ST_RESET_SENT) {",
            xquic,
        )
        self.assertIn(
            "+    return xqc_conn_close(conn->engine, &conn->scid_set.user_scid);",
            xquic,
        )
        self.assertNotIn("+        conn->conn_flag |= XQC_CONN_FLAG_ERROR;", xquic)
        self.assertIn(
            "+        conn->local_application_close || err_code >= H3_NO_ERROR, 0);",
            xquic,
        )
        adapter = (ROOT / "src" / "adapters" / "xquic_adapter.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "xqc_conn_close_application(connection->conn, applicationError)",
            adapter,
        )
        self.assertIn(
            'capabilities_.buildId = "xquic-1.9.2-quicperf12-transport-v2";',
            adapter,
        )

    def test_tquic_retained_stream_bytes_are_exact_and_depofile_owned(self) -> None:
        text = (ROOT / "depofiles" / "tquic.DepoFile").read_text(encoding="utf-8")
        self.assertIn("VERSION datagram-t2-50f5a55-quicperf8", text)
        self.assertIn(
            'buffer_patch_file="$DEPO_BUILD_DIR/quicperf-stream-buffer-accounting.patch"',
            text,
        )
        self.assertIn(
            "+uint64_t quic_conn_stream_send_buffered(const struct quic_conn_t *conn);",
            text,
        )
        self.assertIn("+    pub fn send_buffered(&self) -> usize {", text)
        self.assertIn("+        assert_eq!(map.send_buffered(), 18);", text)
        self.assertIn("+        assert_eq!(map.send_buffered(), 0);", text)
        self.assertIn(
            'write-tree)" = "7f0fe6865bf8e2a6c87b098b3591d1c62972567e"',
            text,
        )
        self.assertIn(
            "+static RAW_EPOCH_NS: OnceLock<u64> = OnceLock::new();", text
        )
        self.assertIn(
            "+            .zip(RAW_EPOCH_NS.get().copied())", text
        )
        self.assertNotIn("+    raw_epoch_ns: Option<u64>,", text)
        adapter = (ROOT / "src" / "adapters" / "tquic_adapter.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'capabilities_.buildId = "tquic-50f5a55-quicperf8-exact-treatment-v1";',
            adapter,
        )

    def test_ngtcp2_block_counters_are_serialized_frame_facts(self) -> None:
        text = (ROOT / "depofiles" / "ngtcp2.DepoFile").read_text(
            encoding="utf-8"
        )
        self.assertIn("VERSION 1.22.1-quicperf8", text)
        self.assertIn(
            "+NGTCP2_EXTERN void ngtcp2_conn_get_quicperf_blocked_frame_counts(",
            text,
        )
        self.assertIn("+  return strm->rx.window < 128 * inc;", text)
        self.assertIn("+  return conn->rx.window < 128 * inc;", text)
        self.assertIn(
            "     return rv;\n   }\n-\n+\n+  switch (fr->hd.type) {", text
        )
        self.assertIn("+  case NGTCP2_FRAME_DATA_BLOCKED:", text)
        self.assertIn("+  case NGTCP2_FRAME_STREAM_DATA_BLOCKED:", text)
        self.assertIn(
            'write-tree)" = "de62489b58ae6964241e4d5a7b438f74c89515ef"',
            text,
        )

        adapter = (ROOT / "src" / "adapters" / "ngtcp2_adapter.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'capabilities_.buildId = "ngtcp2-1.22.1-quicperf8-transport-v2";',
            adapter,
        )
        self.assertIn(
            "ngtcp2_conn_get_quicperf_blocked_frame_counts(", adapter
        )
        self.assertNotIn(
            "++counters_.flowControlBlockedEvents", adapter
        )
        self.assertNotIn(
            "++counters_.streamCreditBlockedEvents", adapter
        )

    def test_libsodium_uses_the_immutable_git_tree_in_rootless_builds(self) -> None:
        text = (ROOT / "depofiles" / "libsodium.DepoFile").read_text(encoding="utf-8")
        self.assertIn("VERSION 1.0.22-quicperf3", text)
        self.assertIn(
            "SOURCE GIT https://github.com/jedisct1/libsodium.git "
            "77e1ce5d6dee871c49ef211222ba18ef0c486bda",
            text,
        )
        self.assertNotIn("SOURCE URL", text)
        for dependent in ("fizz.DepoFile", "folly.DepoFile"):
            dependency_text = (ROOT / "depofiles" / dependent).read_text(encoding="utf-8")
            self.assertIn(
                "DEPENDS libsodium VERSION 1.0.22-quicperf3", dependency_text
            )
            self.assertNotIn("1.0.22-quicperf2", dependency_text)


if __name__ == "__main__":
    unittest.main()
