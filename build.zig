const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const lib = b.addLibrary(.{
        .name = "netsec",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    const lib_tests = b.addTest(.{ .root_module = lib_mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Chạy unit test của thư viện");
    test_step.dependOn(&run_lib_tests.step);

    // Ba tool ví dụ, mỗi cái là một file main riêng dùng thư viện.
    const examples = [_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "netsec-scan", .path = "examples/scan.zig" },
        .{ .name = "netsec-banner", .path = "examples/banner.zig" },
        .{ .name = "netsec-http", .path = "examples/http_check.zig" },
    };
    for (examples) |ex| {
        const exe_mod = b.createModule(.{
            .root_source_file = b.path(ex.path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "netsec", .module = lib_mod }},
        });
        const exe = b.addExecutable(.{
            .name = ex.name,
            .root_module = exe_mod,
        });
        b.installArtifact(exe);
    }
}
