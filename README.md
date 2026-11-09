# security-netsec — Thư viện an ninh mạng bằng Zig

Thư viện Zig để học và kiểm tra mạng (tên module khi import trong code vẫn là `netsec`): quét port, lấy banner, phân giải DNS,
kiểm tra header HTTP, xem host có sống không. Viết cho Zig **0.17.1**.

## Cài Zig

Máy này đã có Zig 0.17.1 ở `~/workspace/tools/zig-x86_64-linux-0.17.1/zig`.
Trên máy khác, tải bản mới nhất ở https://ziglang.org/download/ rồi giải nén,
sau đó cho `zig` vào PATH.

```sh
export PATH=~/workspace/tools/zig-x86_64-linux-0.17.1:$PATH
zig version   # 0.17.1
```

## Build và test

```sh
cd ~/workspace/security-netsec
zig build test     # chạy unit test
zig build          # build thư viện + 3 tool ví dụ vào zig-out/bin/
```

## Dùng thư viện trong code Zig khác

```zig
const netsec = @import("netsec");

// Phân giải host
const ip = try netsec.dns.resolveFirstIpv4(alloc, "scanme.nmap.org");

// Quét port (song song 32 luồng)
const results = try netsec.scanner.scanPortsConcurrent(
    alloc, ip, &.{ 22, 80, 443 }, .{ .timeout_ms = 1000 }, 32,
);
for (results) |r| std.debug.print("{d} {s}\n", .{ r.port, r.status.toString() });

// Lấy banner
const banner = try netsec.banner.grabBanner(alloc, ip, 22, .{});

// Kiểm tra header bảo mật
var head = try netsec.http.httpHead(alloc, ip, "example.com", 80, "/", .{});
defer head.deinit();
const missing = try netsec.http.missingSecurityHeaders(alloc, &head);

// Host có sống không / quét host trong dải
const up = netsec.discovery.isHostUp(ip, .{});
const cidr = try netsec.ip.Cidr.parse("192.168.1.0/24");
const live = try netsec.discovery.sweepCidr(alloc, cidr, .{});
```

## 3 tool ví dụ

```sh
zig-out/bin/netsec-scan scanme.nmap.org 22,80,443
zig-out/bin/netsec-scan 192.168.1.1 1-1000 500
zig-out/bin/netsec-banner scanme.nmap.org 22
zig-out/bin/netsec-http example.com 80 /
```

## Cấu trúc

| File | Làm gì |
| --- | --- |
| `src/ip.zig` | IPv4, CIDR, phân loại IP, tên dịch vụ theo port |
| `src/dns.zig` | Phân giải tên host sang IPv4 (libc `getaddrinfo`) |
| `src/scanner.zig` | TCP connect scan, tuần tự + song song, parse `80,443,8000-8010` |
| `src/banner.zig` | Lấy banner, đoán dịch vụ từ banner |
| `src/http.zig` | HEAD request, kiểm tra header bảo mật còn thiếu |
| `src/discovery.zig` | Host sống không (TCP probe), quét host trong CIDR |
| `src/sys.zig` | Socket POSIX + timeout (nội bộ) |

## Vì sao lõi mạng gọi syscall POSIX trực tiếp?

Trong Zig 0.17.1, `std.Io.net` connect với timeout sẽ panic
(`TODO implement netConnectIpPosix with timeout` trong
`lib/std/Io/Threaded.zig`). Một thư viện quét port mà không đặt được timeout
thì không dùng được, nên lõi ở `src/sys.zig` gọi thẳng
`socket` / `connect` / `poll` / `getsockopt`, giống cách tool C vẫn làm:
connect non-blocking, `poll` chờ tối đa `timeout_ms`, rồi đọc `SO_ERROR`
để biết connect thành công hay thất bại. Khi Zig sửa xong phần timeout
trong `std.Io`, có thể đổi lại sau.

## Giới hạn đã biết (nói thẳng, không giấu)

- **Chỉ IPv4.** IPv6 chưa làm.
- **Chỉ TCP connect scan.** Không có SYN scan (cần raw socket + root),
  không có quét UDP, không ping ICMP.
- **Chưa có TLS.** `netsec-http` chỉ nói chuyện HTTP thường; site HTTPS
  (port 443) sẽ không trả header qua kết nối HTTP thường.
- **Banner do server tự khai**, có thể bị giả hoặc tắt. Tên dịch vụ theo
  port chỉ để hiển thị.
- Quét dải CIDR lớn (`/16`) sẽ rất lâu nếu quét tuần tự — bản sau sẽ
  quét song song.

## Quy tắc dùng

Chỉ quét **mạng của mình, thiết bị của mình, hoặc host công khai cho phép
quét** như `scanme.nmap.org`. Quét mạng người khác khi chưa được phép có
thể bị coi là dò quét trái phép và bị chặn / báo abuse.
