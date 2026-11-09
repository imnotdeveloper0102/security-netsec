// netsec-scan — Tool ví dụ dùng thư viện netsec để quét port.
//
// Cách dùng:
//   netsec-scan <host> [port-spec] [timeout_ms]
//   netsec-scan scanme.nmap.org 22,80,443
//   netsec-scan 192.168.1.1 1-1000 500
//
// Chỉ quét host của mình, mạng của mình, hoặc host công khai cho phép quét
// như scanme.nmap.org.
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
        std.debug.print("Dùng: {s} <host> [port-spec] [timeout_ms]\n", .{args[0]});
        std.debug.print("Ví dụ: {s} scanme.nmap.org 22,80,443\n", .{args[0]});
        return;
    }
    const host = args[1];
    const spec = if (args.len > 2) args[2] else "22,80,443,8080";
    const timeout_ms: i32 = if (args.len > 3) std.fmt.parseInt(i32, args[3], 10) catch 1000 else 1000;

    const ip = netsec.dns.resolveFirstIpv4(alloc, host) catch |err| {
        std.debug.print("Không phân giải được {s}: {t}\n", .{ host, err });
        return;
    };
    var ip_buf: [16]u8 = undefined;
    const ip_text = netsec.ip.formatIpv4(ip, &ip_buf);
    std.debug.print("Quét {s} ({s}, {s}) — port: {s}, timeout {d}ms\n", .{
        host, ip_text, netsec.ip.classify(ip), spec, timeout_ms,
    });

    const ports = netsec.scanner.parsePortList(alloc, spec) catch |err| {
        std.debug.print("Port spec sai: {t}\n", .{err});
        return;
    };
    defer alloc.free(ports);

    const results = try netsec.scanner.scanPortsConcurrent(alloc, ip, ports, .{ .timeout_ms = timeout_ms }, 32);
    defer alloc.free(results);

    var open_count: usize = 0;
    for (results) |r| {
        if (r.status == .open) {
            open_count += 1;
            std.debug.print("  {d}/tcp  {s}  {s}  ({d}ms)\n", .{ r.port, r.status.toString(), r.service(), r.rtt_ms orelse 0 });
        } else {
            std.debug.print("  {d}/tcp  {s}  {s}\n", .{ r.port, r.status.toString(), r.service() });
        }
    }
    std.debug.print("Xong: {d}/{d} port mở.\n", .{ open_count, results.len });
}
