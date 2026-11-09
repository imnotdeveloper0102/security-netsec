// ip.zig — IPv4, CIDR, port. Toàn hàm thuần, không đụng tới mạng.
const std = @import("std");

pub const IpError = error{
    InvalidIp,
    InvalidCidr,
    InvalidPort,
};

/// "192.168.1.10" -> .{ 192, 168, 1, 10 }. Chặt: đủ 4 octet, mỗi octet 0-255.
pub fn parseIpv4(text: []const u8) IpError![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return error.InvalidIp;
        if (part.len == 0 or part.len > 3) return error.InvalidIp;
        var v: u16 = 0;
        for (part) |c| {
            if (c < '0' or c > '9') return error.InvalidIp;
            v = v * 10 + (@as(u16, c) - '0');
            if (v > 255) return error.InvalidIp;
        }
        out[i] = @intCast(v);
        i += 1;
    }
    if (i != 4) return error.InvalidIp;
    return out;
}

/// [4]u8 -> "192.168.1.10" (ghi vào buf do người gọi cấp, tối thiểu 16 byte).
pub fn formatIpv4(ip: [4]u8, buf: *[16]u8) []u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch unreachable;
}

pub fn isLoopback(ip: [4]u8) bool {
    return ip[0] == 127;
}

pub fn isPrivate(ip: [4]u8) bool {
    // 10/8, 172.16/12, 192.168/16 — RFC 1918.
    if (ip[0] == 10) return true;
    if (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) return true;
    if (ip[0] == 192 and ip[1] == 168) return true;
    return false;
}

pub fn isLinkLocal(ip: [4]u8) bool {
    return ip[0] == 169 and ip[1] == 254;
}

pub fn isUnspecified(ip: [4]u8) bool {
    return ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] == 0;
}

/// Kiểu của một địa chỉ: để tool in ra cho dễ đọc, và để nhắc người dùng
/// chỉ quét mạng của mình.
pub fn classify(ip: [4]u8) []const u8 {
    if (isUnspecified(ip)) return "unspecified";
    if (isLoopback(ip)) return "loopback";
    if (isPrivate(ip)) return "private";
    if (isLinkLocal(ip)) return "link-local";
    return "public";
}

pub fn isValidPort(port: u32) bool {
    return port >= 1 and port <= 65535;
}

/// Tên dịch vụ thường gặp. Chỉ để hiển thị, không dùng để kết luận —
/// banner thật mới là bằng chứng (xem banner.zig).
pub fn serviceName(port: u16) []const u8 {
    return switch (port) {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        3306 => "mysql",
        5432 => "postgres",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        else => "unknown",
    };
}

/// Các port hay dùng để thử "host có sống không" (xem discovery.zig).
pub const common_probe_ports: []const u16 = &.{ 80, 443, 22, 445, 53 };

/// Một dải CIDR, ví dụ "192.168.1.0/24".
pub const Cidr = struct {
    network: [4]u8,
    prefix: u6,

    pub fn parse(text: []const u8) IpError!Cidr {
        const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidCidr;
        const ip = parseIpv4(text[0..slash]) catch return error.InvalidCidr;
        const prefix = std.fmt.parseInt(u6, text[slash + 1 ..], 10) catch return error.InvalidCidr;
        if (prefix > 32) return error.InvalidCidr;
        return .{ .network = mask(ip, prefix), .prefix = prefix };
    }

    fn mask(ip: [4]u8, prefix: u6) [4]u8 {
        const bits: u32 = if (prefix == 0) 0 else @as(u32, 0xFFFFFFFF) << @intCast(32 - prefix);
        const raw: u32 = @bitCast(ip);
        // ip lưu theo thứ tự byte mạng; đổi sang host order để mask cho đúng.
        const host_order = std.mem.bigToNative(u32, raw);
        const masked = host_order & bits;
        return @bitCast(std.mem.nativeToBig(u32, masked));
    }

    /// Số host trong dải, kể cả network và broadcast. /32 -> 1.
    /// /0 thì 2^32 host, không vừa u32 nên trả về maxInt.
    pub fn hostCount(self: Cidr) u32 {
        if (self.prefix == 0) return std.math.maxInt(u32);
        const host_bits: u5 = @intCast(32 - self.prefix);
        return @as(u32, 1) << host_bits;
    }

    pub fn contains(self: Cidr, ip: [4]u8) bool {
        return std.mem.eql(u8, &mask(ip, self.prefix), &self.network);
    }

    /// Host thứ i trong dải (i = 0 là network address).
    pub fn hostAt(self: Cidr, i: u32) [4]u8 {
        const raw: u32 = @bitCast(self.network);
        const host_order = std.mem.bigToNative(u32, raw);
        return @bitCast(std.mem.nativeToBig(u32, host_order + i));
    }
};

test "parseIpv4" {
    const t = std.testing;
    try t.expectEqual([4]u8{ 192, 168, 1, 10 }, try parseIpv4("192.168.1.10"));
    try t.expectEqual([4]u8{ 127, 0, 0, 1 }, try parseIpv4("127.0.0.1"));
    try t.expectError(error.InvalidIp, parseIpv4("256.1.1.1"));
    try t.expectError(error.InvalidIp, parseIpv4("192.168.1"));
    try t.expectError(error.InvalidIp, parseIpv4("192.168.1.1.1"));
    try t.expectError(error.InvalidIp, parseIpv4("abc.def.1.1"));
    try t.expectError(error.InvalidIp, parseIpv4(""));
}

test "classify" {
    const t = std.testing;
    try t.expectEqualStrings("loopback", classify(.{ 127, 0, 0, 1 }));
    try t.expectEqualStrings("private", classify(.{ 10, 0, 0, 5 }));
    try t.expectEqualStrings("private", classify(.{ 172, 16, 0, 1 }));
    try t.expectEqualStrings("private", classify(.{ 172, 31, 255, 255 }));
    try t.expectEqualStrings("private", classify(.{ 192, 168, 0, 1 }));
    try t.expectEqualStrings("public", classify(.{ 45, 33, 32, 156 }));
    try t.expectEqualStrings("link-local", classify(.{ 169, 254, 1, 2 }));
}

test "cidr" {
    const t = std.testing;
    const c = try Cidr.parse("192.168.1.0/24");
    try t.expectEqual(@as(u32, 256), c.hostCount());
    try t.expect(c.contains(.{ 192, 168, 1, 200 }));
    try t.expect(!c.contains(.{ 192, 168, 2, 1 }));
    try t.expectEqual([4]u8{ 192, 168, 1, 0 }, c.hostAt(0));
    try t.expectEqual([4]u8{ 192, 168, 1, 1 }, c.hostAt(1));
    try t.expectEqual([4]u8{ 192, 168, 1, 255 }, c.hostAt(255));
    const c32 = try Cidr.parse("10.0.0.5/32");
    try t.expectEqual(@as(u32, 1), c32.hostCount());
    try t.expectError(error.InvalidCidr, Cidr.parse("192.168.1.0"));
    try t.expectError(error.InvalidCidr, Cidr.parse("192.168.1.0/33"));
}
