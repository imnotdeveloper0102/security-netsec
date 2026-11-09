// scanner.zig — TCP connect scan: cách quét port cơ bản nhất, không cần root.
//
// Nguyên lý: mở một kết nối TCP bình thường tới từng port. Kết nối được là
// port mở; bị từ chối (RST) là port đóng; hết timeout mà không trả lời là
// filtered (có thể bị tường lửa chặn). Đây là kiểu quét "lịch sự" nhất —
// giống hệt một client bình thường kết nối tới, không gửi gói tin lạ.
// Không phải SYN scan: SYN scan cần raw socket + quyền root, để bản sau.
const std = @import("std");
const sys = @import("sys.zig");
const ip_mod = @import("ip.zig");

pub const PortStatus = enum {
    open,
    closed,
    filtered,

    pub fn toString(self: PortStatus) []const u8 {
        return switch (self) {
            .open => "open",
            .closed => "closed",
            .filtered => "filtered",
        };
    }
};

pub const ScanOptions = struct {
    /// Timeout cho mỗi lần connect, mili-giây. 500ms là hợp lý cho LAN,
    /// còn quét Internet thì nên 1000-2000ms.
    timeout_ms: i32 = 1000,
};

pub const ScanResult = struct {
    ip: [4]u8,
    port: u16,
    status: PortStatus,
    /// Thời gian connect, mili-giây. Chỉ có khi port mở.
    rtt_ms: ?u64 = null,

    pub fn service(self: ScanResult) []const u8 {
        return ip_mod.serviceName(self.port);
    }
};

/// Mili-giây từ đồng hồ monotonic (không bị chỉnh giờ hệ thống làm lệch).
fn nowMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
}

/// Quét một port duy nhất.
pub fn scanPort(ip: [4]u8, port: u16, opts: ScanOptions) ScanResult {
    const start = nowMs();
    const fd = sys.connectTimeout(ip, port, opts.timeout_ms) catch |err| {
        return .{
            .ip = ip,
            .port = port,
            .status = switch (err) {
                error.ConnectionRefused => .closed,
                // Timeout / không tới được host / bị chặn: đều tính là filtered,
                // vì từ phía quét không phân biệt được tường lửa với host chết.
                else => .filtered,
            },
        };
    };
    defer sys.closeFd(fd);
    const rtt: u64 = nowMs() - start;
    return .{ .ip = ip, .port = port, .status = .open, .rtt_ms = rtt };
}

/// Quét tuần tự nhiều port. Đơn giản, dễ đoán, hợp để học và để test.
pub fn scanPorts(allocator: std.mem.Allocator, ip: [4]u8, ports: []const u16, opts: ScanOptions) ![]ScanResult {
    const out = try allocator.alloc(ScanResult, ports.len);
    for (ports, 0..) |port, i| {
        out[i] = scanPort(ip, port, opts);
    }
    return out;
}

/// Quét nhiều port cùng lúc bằng N luồng worker. Mỗi worker lấy port tiếp
/// theo từ bộ đếm nguyên tử, ghi kết quả đúng vị trí của port đó nên thứ tự
/// kết quả vẫn khớp thứ tự đầu vào.
pub fn scanPortsConcurrent(
    allocator: std.mem.Allocator,
    ip: [4]u8,
    ports: []const u16,
    opts: ScanOptions,
    worker_count: usize,
) ![]ScanResult {
    const out = try allocator.alloc(ScanResult, ports.len);
    if (ports.len == 0) return out;

    const workers = @min(worker_count, ports.len);
    const Ctx = struct {
        ip: [4]u8,
        ports: []const u16,
        out: []ScanResult,
        opts: ScanOptions,
        next: std.atomic.Value(usize),

        fn run(ctx: *@This()) void {
            while (true) {
                const i = ctx.next.fetchAdd(1, .monotonic);
                if (i >= ctx.ports.len) break;
                ctx.out[i] = scanPort(ctx.ip, ctx.ports[i], ctx.opts);
            }
        }
    };

    var ctx = Ctx{
        .ip = ip,
        .ports = ports,
        .out = out,
        .opts = opts,
        .next = std.atomic.Value(usize).init(0),
    };

    var threads = try allocator.alloc(std.Thread, workers);
    defer allocator.free(threads);
    var started: usize = 0;
    errdefer {
        for (threads[0..started]) |t| t.join();
        allocator.free(out);
    }
    for (threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
        started += 1;
    }
    for (threads) |t| t.join();
    return out;
}

/// "80,443,8000-8010" -> []u16. Hỗ trợ port đơn, danh sách, và dải a-b.
pub fn parsePortList(allocator: std.mem.Allocator, spec: []const u8) ![]u16 {
    var list: std.ArrayList(u16) = .empty;
    errdefer list.deinit(allocator);
    var it = std.mem.splitScalar(u8, spec, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, '-')) |dash| {
            const lo = std.fmt.parseInt(u32, trimmed[0..dash], 10) catch return error.InvalidPort;
            const hi = std.fmt.parseInt(u32, trimmed[dash + 1 ..], 10) catch return error.InvalidPort;
            if (!ip_mod.isValidPort(lo) or !ip_mod.isValidPort(hi) or lo > hi) return error.InvalidPort;
            var p = lo;
            while (p <= hi) : (p += 1) try list.append(allocator, @intCast(p));
        } else {
            const p = std.fmt.parseInt(u32, trimmed, 10) catch return error.InvalidPort;
            if (!ip_mod.isValidPort(p)) return error.InvalidPort;
            try list.append(allocator, @intCast(p));
        }
    }
    return list.toOwnedSlice(allocator);
}

test "parsePortList" {
    const t = std.testing;
    const alloc = t.allocator;
    const a = try parsePortList(alloc, "80,443");
    defer alloc.free(a);
    try t.expectEqualSlices(u16, &.{ 80, 443 }, a);
    const b = try parsePortList(alloc, "8000-8002");
    defer alloc.free(b);
    try t.expectEqualSlices(u16, &.{ 8000, 8001, 8002 }, b);
    const c = try parsePortList(alloc, "22, 80-81");
    defer alloc.free(c);
    try t.expectEqualSlices(u16, &.{ 22, 80, 81 }, c);
    try t.expectError(error.InvalidPort, parsePortList(alloc, "0"));
    try t.expectError(error.InvalidPort, parsePortList(alloc, "70000"));
    try t.expectError(error.InvalidPort, parsePortList(alloc, "90-80"));
}
