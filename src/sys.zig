// sys.zig — Lớp socket thô dùng syscall POSIX trực tiếp.
//
// Vì sao không dùng std.Io.net của Zig 0.17.1?
// Trong bản 0.17.1, `IpAddress.connect` với timeout khác `.none` sẽ panic
// ("TODO implement netConnectIpPosix with timeout" trong lib/std/Io/Threaded.zig).
// Một thư viện quét port mà không đặt được timeout thì không dùng được, nên
// lõi mạng ở đây gọi thẳng syscall socket/connect/poll/getsockopt — cách mà
// các tool quét port viết bằng C vẫn làm. Code dài hơn một chút nhưng hành vi
// rõ ràng, timeout thật, và chạy được trên Linux / Termux / Android.
//
// Chỉ hỗ trợ IPv4 ở lõi socket. IPv6 để cho bản sau.
const std = @import("std");
const posix = std.posix;

pub const ConnectError = error{
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
};

pub const ReadError = error{
    Timeout,
    ConnectionReset,
    Unexpected,
    EndOfStream,
};

fn mapConnectErrno(e: posix.E) ConnectError {
    return switch (e) {
        .CONNREFUSED => error.ConnectionRefused,
        .HOSTUNREACH => error.HostUnreachable,
        .NETUNREACH => error.NetworkUnreachable,
        .NETDOWN => error.NetworkDown,
        .ADDRNOTAVAIL => error.AddressUnavailable,
        .ACCES, .PERM => error.AccessDenied,
        .TIMEDOUT => error.Timeout,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        else => error.Unexpected,
    };
}

/// Mở socket TCP tới `ip:port`, chờ tối đa `timeout_ms` mili-giây.
/// Trả về fd đang ở chế độ blocking, đã đặt SO_RCVTIMEO / SO_SNDTIMEO
/// bằng `timeout_ms` để các lần read/write sau cũng không treo.
/// Người gọi phải `closeFd(fd)` khi xong.
pub fn connectTimeout(ip: [4]u8, port: u16, timeout_ms: i32) ConnectError!posix.socket_t {
    const fd = openSocket() catch |err| return err;
    errdefer closeFd(fd);

    var addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(ip),
    };
    const addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    // Connect non-blocking rồi poll, để timeout là thật.
    const rc = posix.system.connect(fd, @ptrCast(&addr), addr_len);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .INTR => {
            // Thử lại một lần cho chắc; hiếm khi gặp.
            const rc2 = posix.system.connect(fd, @ptrCast(&addr), addr_len);
            switch (posix.errno(rc2)) {
                .SUCCESS => {},
                .AGAIN, .INPROGRESS => try waitWritable(fd, timeout_ms),
                else => |e| return mapConnectErrno(e),
            }
        },
        .AGAIN, .INPROGRESS => try waitWritable(fd, timeout_ms),
        else => |e| return mapConnectErrno(e),
    }

    // Kiểm tra SO_ERROR: poll báo writable cả khi connect thất bại.
    var so_error: i32 = 0;
    var optlen: posix.socklen_t = @sizeOf(i32);
    const grc = posix.system.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&so_error), &optlen);
    if (posix.errno(grc) != .SUCCESS) return error.Unexpected;
    if (so_error != 0) {
        return mapConnectErrno(@enumFromInt(so_error));
    }

    // Về lại blocking + đặt timeout cho read/write.
    setBlocking(fd);
    setSocketTimeouts(fd, timeout_ms);

    return fd;
}

fn openSocket() ConnectError!posix.socket_t {
    const flags: u32 = posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
    const rc = posix.system.socket(posix.AF.INET, flags, 0);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }
}

fn waitWritable(fd: posix.socket_t, timeout_ms: i32) ConnectError!void {
    var pfd = [_]posix.pollfd{.{
        .fd = fd,
        .events = posix.POLL.OUT,
        .revents = 0,
    }};
    const n = posix.poll(&pfd, timeout_ms) catch return error.Unexpected;
    if (n == 0) return error.Timeout;
    if (pfd[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) {
        // Lỗi thật nằm trong SO_ERROR, để bước sau đọc ra.
        return;
    }
}

fn setBlocking(fd: posix.socket_t) void {
    // Zig 0.17 bỏ `posix.fcntl`; gọi thẳng syscall fcntl.
    const rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(rc) != .SUCCESS) return;
    // Zig 0.17 đổi O thành packed struct với field bool, nên phải bitCast
    // qua lại giữa số nguyên cờ và struct để tắt NONBLOCK.
    const flags: i32 = @intCast(rc);
    var o_flags: posix.O = @bitCast(@as(u32, @bitCast(flags)));
    o_flags.NONBLOCK = false;
    const cleared: u32 = @bitCast(o_flags);
    _ = posix.system.fcntl(fd, posix.F.SETFL, cleared);
}

fn setSocketTimeouts(fd: posix.socket_t, timeout_ms: i32) void {
    const tv = posix.timeval{
        .sec = @divTrunc(timeout_ms, 1000),
        .usec = @mod(timeout_ms, 1000) * 1000,
    };
    const bytes = std.mem.asBytes(&tv);
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, bytes) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, bytes) catch {};
}

pub fn closeFd(fd: posix.socket_t) void {
    // Zig 0.17 bỏ `posix.close`; gọi thẳng syscall close, bỏ qua lỗi
    // (kể cả EINTR — fd vẫn được đóng, xem zig issue #2425).
    _ = posix.system.close(fd);
}

/// Ghi một lần qua syscall write. Trả về số byte đã ghi.
fn writeOnce(fd: posix.socket_t, data: []const u8) ReadError!usize {
    while (true) {
        const rc = posix.system.write(fd, data.ptr, data.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.Timeout,
            .PIPE => return error.ConnectionReset,
            .CONNRESET => return error.ConnectionReset,
            else => return error.Unexpected,
        }
    }
}

/// Đọc tối đa `buf.len` byte. Hết timeout -> error.Timeout.
/// Đọc được 0 byte (peer đóng) -> error.EndOfStream.
pub fn readTimeout(fd: posix.socket_t, buf: []u8) ReadError!usize {
    const n = posix.read(fd, buf) catch |err| switch (err) {
        error.WouldBlock => return error.Timeout,
        error.ConnectionResetByPeer => return error.ConnectionReset,
        else => return error.Unexpected,
    };
    if (n == 0) return error.EndOfStream;
    return n;
}

/// Ghi hết `data`, hoặc lỗi khi timeout / đứt kết nối.
pub fn writeAll(fd: posix.socket_t, data: []const u8) ReadError!void {
    var off: usize = 0;
    while (off < data.len) {
        const n = try writeOnce(fd, data[off..]);
        if (n == 0) return error.ConnectionReset;
        off += n;
    }
}
