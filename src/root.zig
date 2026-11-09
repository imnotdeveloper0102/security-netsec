// netsec — Thư viện an ninh mạng viết bằng Zig.
//
// Dùng cho học tập và kiểm tra mạng của chính mình (hoặc mạng được phép quét).
// Không dùng để quét mạng của người khác khi chưa được phép.
//
// Các module:
//   ip        — IPv4, CIDR, tên dịch vụ theo port
//   dns       — phân giải tên host sang IPv4 (qua libc getaddrinfo)
//   scanner   — TCP connect scan, tuần tự + song song
//   banner    — lấy banner dịch vụ, đoán dịch vụ từ banner
//   http      — HEAD request, kiểm tra header bảo mật còn thiếu
//   discovery — host có sống không (TCP probe), quét host trong CIDR
//   sys       — (nội bộ) socket POSIX + timeout
//
// Ví dụ nhanh:
//   const ip = try netsec.dns.resolveFirstIpv4(alloc, "scanme.nmap.org");
//   const results = try netsec.scanner.scanPorts(alloc, ip, &.{ 22, 80, 443 }, .{});
const std = @import("std");

pub const version = "0.1.0";
pub const zig_version = "0.17.1";

pub const ip = @import("ip.zig");
pub const dns = @import("dns.zig");
pub const scanner = @import("scanner.zig");
pub const banner = @import("banner.zig");
pub const http = @import("http.zig");
pub const discovery = @import("discovery.zig");

// Re-export những kiểu dùng nhiều nhất, để khỏi viết `netsec.scanner.` dài.
pub const Cidr = ip.Cidr;
pub const ScanResult = scanner.ScanResult;
pub const PortStatus = scanner.PortStatus;
pub const ScanOptions = scanner.ScanOptions;

test {
    // Chạy toàn bộ test trong các module con.
    std.testing.refAllDecls(@This());
    _ = @import("ip.zig");
    _ = @import("dns.zig");
    _ = @import("scanner.zig");
    _ = @import("banner.zig");
    _ = @import("http.zig");
    _ = @import("discovery.zig");
}
