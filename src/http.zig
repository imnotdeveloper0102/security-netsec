// http.zig — Kiểm tra HTTP header, tập trung vào header bảo mật.
//
// Dùng khi đánh giá nhanh một web server: gửi HEAD, đọc status + header,
// rồi chỉ ra những header bảo mật còn thiếu (HSTS, CSP, X-Frame-Options...).
// Thiếu header không đồng nghĩa với "bị hack được", chỉ là một điểm cần xem.
const std = @import("std");
const sys = @import("sys.zig");

pub const HttpError = error{
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
    BadResponse,
    EndOfStream,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const HttpHeadResult = struct {
    status: u16,
    status_text: []const u8,
    headers: []Header,
    /// Toàn bộ phần header thô (để debug / in ra).
    raw: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *HttpHeadResult) void {
        for (self.headers) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.allocator.free(self.headers);
        self.allocator.free(self.raw);
        self.allocator.free(self.status_text);
    }

    pub fn getHeader(self: *const HttpHeadResult, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn server(self: *const HttpHeadResult) ?[]const u8 {
        return self.getHeader("server");
    }
};

pub const HttpOptions = struct {
    timeout_ms: i32 = 3000,
};

/// Gửi HEAD tới `host:port/path` và phân tích response header.
pub fn httpHead(allocator: std.mem.Allocator, ip: [4]u8, host: []const u8, port: u16, path: []const u8, opts: HttpOptions) HttpError!HttpHeadResult {
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

    const req = try std.fmt.allocPrint(allocator, "HEAD {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: security-netsec/0.1\r\nConnection: close\r\n\r\n", .{ path, host });
    defer allocator.free(req);

    sys.writeAll(fd, req) catch |err| switch (err) {
        error.Timeout => return error.Timeout,
        else => return error.Unexpected,
    };

    var raw: std.ArrayList(u8) = .empty;
    errdefer raw.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    while (raw.items.len < 65536) {
        const n = sys.readTimeout(fd, &chunk) catch |err| switch (err) {
            error.Timeout, error.EndOfStream, error.ConnectionReset => break,
            else => return error.Unexpected,
        };
        try raw.appendSlice(allocator, chunk[0..n]);
        if (std.mem.indexOf(u8, raw.items, "\r\n\r\n") != null) break;
    }
    if (raw.items.len == 0) return error.BadResponse;

    return parseHead(allocator, try raw.toOwnedSlice(allocator));
}

fn parseHead(allocator: std.mem.Allocator, raw: []u8) HttpError!HttpHeadResult {
    errdefer allocator.free(raw);
    const end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse raw.len;
    const head = raw[0..end];

    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return error.BadResponse;
    // "HTTP/1.1 200 OK"
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next(); // HTTP/1.1
    const code_str = parts.next() orelse return error.BadResponse;
    const status = std.fmt.parseInt(u16, code_str, 10) catch return error.BadResponse;
    const status_text = std.mem.trim(u8, parts.rest(), " ") ;
    const status_owned = try allocator.dupe(u8, status_text);

    var headers: std.ArrayList(Header) = .empty;
    errdefer {
        for (headers.items) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        headers.deinit(allocator);
        allocator.free(status_owned);
    }
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = try allocator.dupe(u8, std.mem.trim(u8, line[0..colon], " "));
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, std.mem.trim(u8, line[colon + 1 ..], " "));
        try headers.append(allocator, .{ .name = name, .value = value });
    }

    return .{
        .status = status,
        .status_text = status_owned,
        .headers = try headers.toOwnedSlice(allocator),
        .raw = raw,
        .allocator = allocator,
    };
}

/// Các header bảo mật nên có trên một web server hiện đại.
pub const security_headers: []const []const u8 = &.{
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
};

/// Trả về danh sách header bảo mật còn thiếu (slice do người gọi sở hữu).
pub fn missingSecurityHeaders(allocator: std.mem.Allocator, result: *const HttpHeadResult) ![][]const u8 {
    var missing: std.ArrayList([]const u8) = .empty;
    errdefer missing.deinit(allocator);
    for (security_headers) |name| {
        if (result.getHeader(name) == null) try missing.append(allocator, name);
    }
    return missing.toOwnedSlice(allocator);
}

test "parseHead" {
    const t = std.testing;
    const alloc = t.allocator;
    const raw_text = "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nX-Frame-Options: DENY\r\nContent-Type: text/html\r\n\r\n";
    var res = try parseHead(alloc, try alloc.dupe(u8, raw_text));
    defer res.deinit();
    try t.expectEqual(@as(u16, 200), res.status);
    try t.expectEqualStrings("nginx/1.25", res.server().?);
    try t.expectEqualStrings("DENY", res.getHeader("x-frame-options").?);
    const missing = try missingSecurityHeaders(alloc, &res);
    defer alloc.free(missing);
    // Thiếu HSTS, CSP, X-Content-Type-Options, Referrer-Policy.
    try t.expectEqual(@as(usize, 4), missing.len);
}
