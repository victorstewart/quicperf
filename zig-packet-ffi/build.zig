const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const quic_src = b.option([]const u8, "quic-src", "path to upstream quic-zig source tree") orelse "../quic-zig";
    const need_libc: ?bool = if (target.result.os.tag == .windows) null else true;
    const xev_dep = b.dependency("libxev", .{ .target = target, .optimize = optimize });

    const quic_root = b.pathJoin(&.{ quic_src, "src/lib.zig" });
    const quic_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = quic_root },
        .target = target,
        .optimize = optimize,
        .link_libc = need_libc,
        .imports = &.{.{ .name = "xev", .module = xev_dep.module("xev") }},
    });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "quicperf_zig_packet_ffi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = need_libc,
            .imports = &.{.{ .name = "quic", .module = quic_mod }},
        }),
    });
    b.installArtifact(lib);
}
