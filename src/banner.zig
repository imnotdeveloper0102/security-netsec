// banner.zig — Lấy banner: phần chữ dịch vụ tự giới thiệu khi có kết nối.
//
// Nhiều dịch vụ (SSH, FTP, SMTP...) gửi banner ngay khi client nối vào.
// Banner giúp đoán dịch vụ và phiên bản — giống `nmap -sV` ở mức cơ bản.
// Lưu ý: banner do server tự khai, có thể bị giả mạo hoặc tắt hẳn; một port
// không có banner không có nghĩa là không có dịch vụ.
const std = @import("std");
const sys = @import("sys.zig");
const ip_mod = @import("ip.zig");

pub const BannerOptions = struct {
    timeout_ms: i32 = 2000,
    /// Số byte tối đa đọc về. Banner thường chỉ vài trăm byte.
    max_bytes: usize = 4096,
    /// Nếu có, gửi chuỗi này ngay sau khi nối (ví dụ "HELLO\r\n" cho SMTP).
    probe: ?[]const u8 = null,
};

pub const BannerError = error{
    NoBanner,
    Timeout,
    ConnectionRefused,
    HostUnreachable,
    NetworkUnreachable,
    NetworkDown,
    AddressUnavailable,
    AccessDenied,
    SystemResources,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    Unexpected,
    OutOfMemory,
    EndOfStream,
};

/// Kết nối, gửi probe (nếu có), đọc banner. Trả về chuỗi do người gọi sở hữu.
/// Banner trả về đã cắt khoảng trắng / \r\n ở hai đầu.
pub fn grabBanner(allocator: std.mem.Allocator, ip: [4]u8, port: u16, opts: BannerOptions) BannerError![]u8 {
    const fd = sys.connectTimeout(ip, port, opts.timeout_ms) catch |err| switch (err) {
        error.Timeout => return error.Timeout,
        error.ConnectionRefused => return error.ConnectionRefused,
        error.HostUnreachable => return error.HostUnreachable,
        error.NetworkUnreachable => return error.NetworkUnreachable,
        error.NetworkDown => return error.NetworkDown,
        error.AddressUnavailable => return error.AddressUnavailable,
        error.AccessDenied => return error.AccessDenied,
        error.SystemResources => return error.SystemResources,
        error.ProcessFdQuotaExceeded => return error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded => return error.SystemFdQuotaExceeded,
        else => return error.Unexpected,
    };
    defer sys.closeFd(fd);

    if (opts.probe) |probe| {
        sys.writeAll(fd, probe) catch |err| switch (err) {
            error.Timeout => return error.Timeout,
            else => return error.Unexpected,
        };
    }

    const buf = try allocator.alloc(u8, opts.max_bytes);
    errdefer allocator.free(buf);
    var total: usize = 0;
    while (total < buf.len) {
        const n = sys.readTimeout(fd, buf[total..]) catch |err| switch (err) {
            error.Timeout => break,
            error.EndOfStream => break,
            error.ConnectionReset => break,
            else => return error.Unexpected,
        };
        total += n;
        // Nhiều banner kết thúc bằng \n — đọc được một dòng là đủ.
        if (std.mem.indexOfScalar(u8, buf[0..total], '\n') != null) break;
    }
    if (total == 0) {
        allocator.free(buf);
        return error.NoBanner;
    }
    const trimmed = std.mem.trim(u8, buf[0..total], " \t\r\n");
    const out = try allocator.dupe(u8, trimmed);
    allocator.free(buf);
    return out;
}

/// Đoán dịch vụ từ port và banner. Trả về tên, ví dụ "ssh-2.0-openssh_9.6".
pub fn guessService(port: u16, banner: ?[]const u8) []const u8 {
    if (banner) |b| {
        if (std.mem.startsWith(u8, b, "SSH-")) return "ssh";
        if (std.mem.startsWith(u8, b, "220 ")) {
            if (std.mem.indexOf(u8, b, "SMTP") != null or std.mem.indexOf(u8, b, "smtp") != null) return "smtp";
            if (std.mem.indexOf(u8, b, "FTP") != null or std.mem.indexOf(u8, b, "ftp") != null) return "ftp";
            return "smtp/ftp";
        }
        if (std.mem.startsWith(u8, b, "HTTP/")) return "http";
        if (std.mem.indexOf(u8, b, "MySQL") != null) return "mysql";
        if (std.mem.indexOf(u8, b, "PostgreSQL") != null) return "postgres";
        if (std.mem.indexOf(u8, b, "Redis") != null) return "redis";
    }
    return ip_mod.serviceName(port);
}

test "guessService" {
    const t = std.testing;
    try t.expectEqualStrings("ssh", guessService(22, "SSH-2.0-OpenSSH_9.6"));
    try t.expectEqualStrings("http", guessService(80, "HTTP/1.1 400 Bad Request"));
    try t.expectEqualStrings("smtp", guessService(25, "220 mail.example.com ESMTP Postfix"));
    try t.expectEqualStrings("ssh", guessService(22, null));
    try t.expectEqualStrings("unknown", guessService(9999, null));
}
