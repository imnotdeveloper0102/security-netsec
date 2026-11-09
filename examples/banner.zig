// netsec-banner — Tool ví dụ: lấy banner của một dịch vụ.
//
// Cách dùng:
//   netsec-banner <host> <port>
//   netsec-banner scanme.nmap.org 22
const std = @import("std");
const netsec = @import("netsec");

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const args = try init.args.toSlice(arena.allocator());
    if (args.len < 3) {
        std.debug.print("Dùng: {s} <host> <port>\n", .{args[0]});
        return;
    }
    const host = args[1];
    const port = std.fmt.parseInt(u16, args[2], 10) catch {
        std.debug.print("Port sai: {s}\n", .{args[2]});
        return;
    };

    const ip = netsec.dns.resolveFirstIpv4(alloc, host) catch |err| {
        std.debug.print("Không phân giải được {s}: {t}\n", .{ host, err });
        return;
    };

    const banner = netsec.banner.grabBanner(alloc, ip, port, .{}) catch |err| {
        std.debug.print("Không lấy được banner {s}:{d}: {t}\n", .{ host, port, err });
        return;
    };
    defer alloc.free(banner);

    std.debug.print("Banner {s}:{d}:\n{s}\n", .{ host, port, banner });
    std.debug.print("Đoán dịch vụ: {s}\n", .{netsec.banner.guessService(port, banner)});
}
