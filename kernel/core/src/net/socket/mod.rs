// SPDX-License-Identifier: MPL-2.0

use core::fmt::Display;

use options::SocketOption;
use util::{
    MessageHeader, RecvFlags, RecvOutput, SendFlags, SockShutdownCmd, SocketAddr, audit_connect,
    check_connect,
};

use crate::{
    fs::{
        file::{
            AccessMode, CreationFlags, FileCommon, FileLike, SettableStatusFlags, StatusFlags,
            file_table::FdFlags,
        },
        pseudofs::SockFs,
    },
    net::socket::util::ioctl::socket_ioctl,
    prelude::*,
    util::{MultiRead, MultiWrite, ioctl::RawIoctl},
};

pub(crate) mod ip;
pub(crate) mod netlink;
pub(crate) mod options;
pub(crate) mod unix;
pub(crate) mod util;
pub(crate) mod vsock;

mod private {
    use core::time::Duration;

    use super::util::RecvFlags;
    use crate::{
        events::IoEvents,
        prelude::*,
        process::signal::Pollable,
        util::{MultiWrite, ioctl::RawIoctl},
    };

    /// Common methods for sockets, but private to the network module.
    ///
    /// These are implementation details of sockets, so shouldn't be accessed outside the network
    /// module. Therefore, the whole trait is sealed.
    pub(crate) trait SocketPrivate: Pollable {
        /// Returns whether the socket is in non-blocking mode.
        fn is_nonblocking(&self) -> bool;

        /// Blocks until some events occur to complete I/O operations.
        ///
        /// If the socket is in non-blocking mode and the I/O operations cannot be completed
        /// immediately, this method will fail with [`EAGAIN`] instead of blocking.
        ///
        /// [`EAGAIN`]: crate::error::Errno::EAGAIN
        #[track_caller]
        fn block_on<F, R>(
            &self,
            events: IoEvents,
            timeout: Option<Duration>,
            try_op: F,
        ) -> Result<R>
        where
            Self: Sized,
            F: FnMut() -> Result<R>,
        {
            self.block_on_unless(false, events, timeout, try_op)
        }

        /// Blocks until some events occur to complete I/O operations, unless `is_dont_wait` is
        /// true.
        ///
        /// This method behaves like [`Self::block_on`], except that it also fails with
        /// [`EAGAIN`] instead of blocking if `is_dont_wait` is true. This is used to support
        /// `MSG_DONTWAIT` in send and receive operations.
        ///
        /// [`EAGAIN`]: crate::error::Errno::EAGAIN
        #[track_caller]
        fn block_on_unless<F, R>(
            &self,
            is_dont_wait: bool,
            events: IoEvents,
            timeout: Option<Duration>,
            mut try_op: F,
        ) -> Result<R>
        where
            Self: Sized,
            F: FnMut() -> Result<R>,
        {
            if is_dont_wait || self.is_nonblocking() {
                try_op()
            } else {
                self.wait_events(events, timeout.as_ref(), try_op)
                    .map_err(|err| match err.error() {
                        Errno::ETIME => {
                            Error::with_message(Errno::EAGAIN, "the socket timeout expired")
                        }
                        _ => err,
                    })
            }
        }

        /// Receives data from a stream socket, honoring `MSG_DONTWAIT` and `MSG_WAITALL`.
        ///
        /// `try_recv` receives some data without blocking. It returns the number of bytes
        /// received (zero means the end of the stream) and an extra output. If `should_stop`
        /// returns true for the extra output, no more data will be received.
        ///
        /// With `MSG_WAITALL`, this method keeps receiving until `writer` is full. Like Linux, it
        /// returns the data received so far instead of waiting for more if the socket is
        /// non-blocking, the end of the stream is reached, an error occurs, or a signal or the
        /// receive timeout interrupts the waiting. The extra output of the last receive is
        /// returned.
        ///
        /// Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/net/ipv4/tcp.c#L2711-L2749>
        #[track_caller]
        fn recv_stream<T>(
            &self,
            writer: &mut dyn MultiWrite,
            flags: RecvFlags,
            timeout: Option<Duration>,
            mut try_recv: impl FnMut(&mut dyn MultiWrite) -> Result<(usize, T)>,
            should_stop: impl Fn(&T) -> bool,
        ) -> Result<(usize, T)>
        where
            Self: Sized,
        {
            // TODO: Support `MSG_WAITALL` with `MSG_PEEK` and `MSG_TRUNC` as Linux does.
            let is_wait_all = flags.contains(RecvFlags::MSG_WAITALL)
                && !flags.intersects(RecvFlags::MSG_PEEK | RecvFlags::MSG_TRUNC);

            let mut received_len = 0;
            let mut last_output = None;
            let result = self.block_on_unless(
                flags.contains(RecvFlags::MSG_DONTWAIT),
                IoEvents::IN,
                timeout,
                || {
                    let (len, output) = match try_recv(writer) {
                        Ok(res) => res,
                        // Return the data received before the error.
                        //
                        // TODO: Linux keeps the error (e.g., `ECONNRESET`) for the next call,
                        // but some errors here have already been consumed by `try_recv`.
                        Err(err) if received_len > 0 && err.error() != Errno::EAGAIN => {
                            return Ok(());
                        }
                        Err(err) => return Err(err),
                    };

                    received_len += len;
                    let is_done =
                        !is_wait_all || len == 0 || should_stop(&output) || writer.is_empty();
                    last_output = Some(output);

                    if is_done {
                        Ok(())
                    } else {
                        Err(Error::with_message(Errno::EAGAIN, "waiting for more data"))
                    }
                },
            );

            match (result, last_output) {
                (Ok(()), Some(output)) => Ok((received_len, output)),
                // Return the data received before the waiting is interrupted.
                (Err(_), Some(output)) if received_len > 0 => Ok((received_len, output)),
                (Err(err), _) => Err(err),
                (Ok(()), None) => unreachable!("`try_recv` has succeeded at least once"),
            }
        }

        /// Handles commands specific to its protocol or socket type.
        fn protocol_ioctl(&self, _raw_ioctl: RawIoctl) -> Result<i32> {
            return_errno_with_message!(Errno::ENOTTY, "the socket ioctl command is unknown");
        }
    }
}

/// Operations defined on a socket.
pub(crate) trait Socket: private::SocketPrivate + Send + Sync {
    /// Assigns the specified address to the socket.
    fn bind(&self, _socket_addr: SocketAddr) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "bind() is not supported");
    }

    /// Builds a connection for the given address
    fn connect(&self, _socket_addr: SocketAddr) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "connect() is not supported");
    }

    /// Listens for connections on the socket.
    fn listen(&self, _backlog: usize) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "listen() is not supported");
    }

    /// Accepts a connection on the socket.
    fn accept(&self, _is_nonblocking: bool) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "accept() is not supported");
    }

    /// Shuts down part of a full-duplex connection.
    fn shutdown(&self, _cmd: SockShutdownCmd) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "shutdown() is not supported");
    }

    /// Gets the address of this socket.
    fn addr(&self) -> Result<SocketAddr> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "getsockname() is not supported");
    }

    /// Gets the address of the peer socket.
    fn peer_addr(&self) -> Result<SocketAddr> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "getpeername() is not supported");
    }

    /// Gets options on the socket.
    ///
    /// If the method succeeds, the result will be stored in the `option` parameter.
    fn get_option(&self, _option: &mut dyn SocketOption) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "getsockopt() is not supported");
    }

    /// Sets options on the socket.
    fn set_option(&self, _option: &dyn SocketOption) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "setsockopt() is not supported");
    }

    /// Sends a message on the socket.
    fn sendmsg(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendFlags,
    ) -> Result<usize>;

    /// Receives a message from the socket.
    ///
    /// If successful, the `writer` buffer will be filled with the received content.
    /// This method returns the length, flags, and header of the received message.
    fn recvmsg(
        &self,
        writer: &mut dyn MultiWrite,
        flags: RecvFlags,
    ) -> Result<(RecvOutput, MessageHeader)>;

    /// Returns the common state for this socket.
    fn common(&self) -> &FileCommon;
}

/// Receives one message from a socket into all the buffers, like `read(2)` and `readv(2)`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/socket.c#L1201-L1220>
pub(crate) fn read_socket(socket: &dyn Socket, writer: &mut dyn MultiWrite) -> Result<usize> {
    if writer.is_empty() {
        // Linux always returns `Ok(0)` in this case, so we follow it.
        return Ok(0);
    }

    // TODO: Set correct flags
    socket
        .recvmsg(writer, RecvFlags::empty())
        .map(|(output, _)| output.len())
}

/// Sends all the buffers to a socket as one message, like `write(2)` and `writev(2)`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/net/socket.c#L1222-L1243>
pub(crate) fn write_socket(socket: &dyn Socket, reader: &mut dyn MultiRead) -> Result<usize> {
    let audit_target = check_connect(socket, None)?;
    // TODO: Set correct flags
    let sent_bytes = socket.sendmsg(
        reader,
        MessageHeader::new(None, Vec::new()),
        SendFlags::empty(),
    )?;
    audit_connect(audit_target);
    Ok(sent_bytes)
}

impl<T: Socket + 'static> FileLike for T {
    fn read(&self, writer: &mut VmWriter) -> Result<usize> {
        read_socket(self, writer)
    }

    fn write(&self, reader: &mut VmReader) -> Result<usize> {
        write_socket(self, reader)
    }

    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        socket_ioctl(self, raw_ioctl)
    }

    fn settable_status_flags(&self) -> SettableStatusFlags {
        SettableStatusFlags::minimal().with_o_async()
    }

    fn as_socket(&self) -> Option<&dyn Socket> {
        Some(self)
    }

    fn common(&self) -> &FileCommon {
        Socket::common(self)
    }

    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display> {
        struct FdInfo {
            flags: u32,
            ino: u64,
        }

        impl Display for FdInfo {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                writeln!(f, "pos:\t{}", 0)?;
                writeln!(f, "flags:\t0{:o}", self.flags)?;
                writeln!(f, "mnt_id:\t{}", SockFs::mount_node().id())?;
                writeln!(f, "ino:\t{}", self.ino)
            }
        }

        let mut flags = self.common().status_flags().bits() | self.common().access_mode() as u32;
        if fd_flags.contains(FdFlags::CLOEXEC) {
            flags |= CreationFlags::O_CLOEXEC.bits();
        }

        Box::new(FdInfo {
            flags,
            ino: self.common().path().inode().ino(),
        })
    }
}

/// Create the `FileCommon` for the socket files.
fn new_socket_common(is_nonblocking: bool) -> FileCommon {
    let status_flags = if is_nonblocking {
        StatusFlags::O_NONBLOCK
    } else {
        StatusFlags::empty()
    };
    // Reference: <https://elixir.bootlin.com/linux/v7.0/source/net/socket.c#L483>.
    FileCommon::new(SockFs::new_path(), AccessMode::O_RDWR, status_flags)
}
