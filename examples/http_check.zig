// netsec-http — Tool ví dụ: kiểm tra header bảo mật của một web server.
//
// Cách dùng:
//   netsec-http <host> [port] [path]
//   netsec-http example.com 80 /
//   netsec-http example.com 443 /
const std = @import("std");
const netsec = @import("netsec");

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const args = try init.args.toSlice(arena.allocator());
    if (args.len < 2) {
        std.debug.print("Dùng: {s} <host> [port] [path]\n", .{args[0]});
        return;
    }
    const host = args[1];
    const port: u16 = if (args.len > 2) std.fmt.parseInt(u16, args[2], 10) catch 80 else 80;
    const path = if (args.len > 3) args[3] else "/";

    const ip = netsec.dns.resolveFirstIpv4(alloc, host) catch |err| {
        std.debug.print("Không phân giải được {s}: {t}\n", .{ host, err });
        return;
    };

    var res = netsec.http.httpHead(alloc, ip, host, port, path, .{}) catch |err| {
        std.debug.print("Không lấy được header {s}:{d}: {t}\n", .{ host, port, err });
        return;
    };
    defer res.deinit();

    std.debug.print("{s}:{d}{s} -> {d} {s}\n", .{ host, port, path, res.status, res.status_text });
    if (res.server()) |srv| std.debug.print("Server: {s}\n", .{srv});
    for (res.headers) |h| {
        std.debug.print("  {s}: {s}\n", .{ h.name, h.value });
    }
    const missing = try netsec.http.missingSecurityHeaders(alloc, &res);
    defer alloc.free(missing);
    if (missing.len == 0) {
        std.debug.print("Đủ các header bảo mật đã kiểm tra.\n", .{});
    } else {
        std.debug.print("Thiếu header bảo mật:\n", .{});
        for (missing) |m| std.debug.print("  - {s}\n", .{m});
    }
}
