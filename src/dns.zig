// dns.zig — Phân giải tên host sang IPv4 bằng libc getaddrinfo.
//
// Dùng libc ở đây vì Zig 0.17.1 chưa có API phân giải DNS thuần Zig ổn định
// cho library dùng trực tiếp; getaddrinfo tôn trọng /etc/resolv.conf và
// /etc/hosts của máy, nên chạy đúng cả trên Termux. Cần linkLibC (đã bật
// trong build.zig).
const std = @import("std");
const posix = std.posix;
const ip_mod = @import("ip.zig");

pub const DnsError = error{
    HostNotFound,
    TryAgain,
    NoAddress,
    SystemResources,
    Unexpected,
    OutOfMemory,
};

fn mapEai(rc: std.c.EAI) DnsError {
    return switch (rc) {
        .NONAME, .NODATA, .FAIL, .FAMILY, .SERVICE, .SOCKTYPE => error.HostNotFound,
        .AGAIN => error.TryAgain,
        .MEMORY => error.SystemResources,
        else => error.Unexpected,
    };
}

/// Phân giải `host` ("scanme.nmap.org", "localhost", "192.168.1.1") ra
/// danh sách IPv4. Trả về slice do người gọi sở hữu (free bằng allocator).
/// Trả về rỗng là không có địa chỉ IPv4 nào (không phải lỗi).
pub fn resolveIpv4(allocator: std.mem.Allocator, host: []const u8) DnsError![][4]u8 {
    // IP literal thì khỏi hỏi DNS.
    if (ip_mod.parseIpv4(host)) |ip| {
        const out = try allocator.alloc([4]u8, 1);
        out[0] = ip;
        return out;
    } else |_| {}

    // Zig 0.17 bỏ `Allocator.dupeZ`; tự cấp phát rồi thêm byte NUL.
    const host_z = try allocator.alloc(u8, host.len + 1);
    defer allocator.free(host_z);
    @memcpy(host_z[0..host.len], host);
    host_z[host.len] = 0;
    const host_ptr: [*:0]const u8 = @ptrCast(host_z.ptr);

    var hints: posix.addrinfo = std.mem.zeroes(posix.addrinfo);
    hints.family = posix.AF.INET;
    hints.socktype = posix.SOCK.STREAM;

    var res: ?*posix.addrinfo = null;
    const rc = std.c.getaddrinfo(host_ptr, null, &hints, &res);
    if (@intFromEnum(rc) != 0) return mapEai(rc);
    defer std.c.freeaddrinfo(res.?);

    var list: std.ArrayList([4]u8) = .empty;
    errdefer list.deinit(allocator);

    var cur: ?*posix.addrinfo = res;
    while (cur) |ai| {
        if (ai.family == posix.AF.INET and ai.addr != null) {
            const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(ai.addr));
            const raw: [4]u8 = @bitCast(sin.addr);
            try list.append(allocator, raw);
        }
        cur = ai.next;
    }

    return list.toOwnedSlice(allocator);
}

/// Phân giải và lấy địa chỉ đầu tiên. Tiện cho scanner chỉ cần một IP.
pub fn resolveFirstIpv4(allocator: std.mem.Allocator, host: []const u8) DnsError![4]u8 {
    const addrs = try resolveIpv4(allocator, host);
    defer allocator.free(addrs);
    if (addrs.len == 0) return error.NoAddress;
    return addrs[0];
}
