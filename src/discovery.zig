// discovery.zig — Host có sống không? Dùng TCP connect thay cho ICMP ping.
//
// ICMP ping cần raw socket (thường cần root, và nhiều host chặn ICMP).
// Cách thực tế hơn trên mạng nội bộ: thử nối TCP tới vài port hay mở
// (80, 443, 22...). Chỉ cần một port trả lời là biết host đang sống.
// Ngược lại: không port nào trả lời thì chưa chắc host chết — có thể nó
// chỉ chặn hết các port đó.
const std = @import("std");
const sys = @import("sys.zig");
const ip_mod = @import("ip.zig");

pub const DiscoveryOptions = struct {
    timeout_ms: i32 = 800,
    /// Thử các port này theo thứ tự, dừng khi gặp port mở đầu tiên.
    probe_ports: []const u16 = ip_mod.common_probe_ports,
};

/// Trả về port đầu tiên nối được, hoặc null nếu không nối được port nào.
pub fn firstOpenPort(ip: [4]u8, opts: DiscoveryOptions) ?u16 {
    for (opts.probe_ports) |port| {
        const fd = sys.connectTimeout(ip, port, opts.timeout_ms) catch continue;
        sys.closeFd(fd);
        return port;
    }
    return null;
}

pub fn isHostUp(ip: [4]u8, opts: DiscoveryOptions) bool {
    return firstOpenPort(ip, opts) != null;
}

/// Quét một dải CIDR, trả về danh sách host đang sống (slice do người gọi
/// sở hữu). Chỉ quét host, không quét port — nhanh và ít ồn hơn nhiều.
/// Cảnh báo: dải lớn (ví dụ /16 = 65536 host) sẽ rất lâu; hãy dùng /24
/// trở xuống, hoặc tăng timeout thấp + quét song song ở tầng trên.
pub fn sweepCidr(allocator: std.mem.Allocator, cidr: ip_mod.Cidr, opts: DiscoveryOptions) ![][4]u8 {
    var live: std.ArrayList([4]u8) = .empty;
    errdefer live.deinit(allocator);
    const count = cidr.hostCount();
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const host = cidr.hostAt(i);
        if (isHostUp(host, opts)) try live.append(allocator, host);
    }
    return live.toOwnedSlice(allocator);
}
