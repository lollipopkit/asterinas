// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs,
    fs::file::{
        FileLike, RwfFlags, StatusFlags,
        file_table::{RawFileDesc, get_file_fast},
    },
    net::socket::write_socket,
    prelude::*,
    util::{MultiRead, VmReaderArray},
};

pub(super) fn sys_writev(
    raw_fd: RawFileDesc,
    io_vec_ptr: Vaddr,
    io_vec_count: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let res = do_sys_writev(raw_fd, io_vec_ptr, io_vec_count, 0, ctx)?;
    Ok(SyscallReturn::Return(res as _))
}

pub(super) fn sys_pwritev(
    raw_fd: RawFileDesc,
    io_vec_ptr: Vaddr,
    io_vec_count: usize,
    offset_low: u64,
    _offset_high: u64,
    ctx: &Context,
) -> Result<SyscallReturn> {
    // On 64-bit platforms, Linux assumes the `offset_low` contains the full
    // 64-bit offset.
    // Reference: <https://elixir.bootlin.com/linux/v6.16.9/source/fs/read_write.c#L1114-L1118>.
    let offset = offset_low.cast_signed();
    let res = do_sys_pwritev(raw_fd, io_vec_ptr, io_vec_count, offset, 0, ctx)?;
    Ok(SyscallReturn::Return(res as _))
}

pub(super) fn sys_pwritev2(
    raw_fd: RawFileDesc,
    io_vec_ptr: Vaddr,
    io_vec_count: usize,
    offset_low: u64,
    _offset_high: u64,
    flags: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    // On 64-bit platforms, Linux assumes the `offset_low` contains the full
    // 64-bit offset.
    // Reference: <https://elixir.bootlin.com/linux/v6.16.9/source/fs/read_write.c#L1114-L1118>.
    let offset = offset_low.cast_signed();
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/read_write.c#L1203-L1213>
    let res = if offset == -1 {
        do_sys_writev(raw_fd, io_vec_ptr, io_vec_count, flags, ctx)?
    } else {
        do_sys_pwritev(raw_fd, io_vec_ptr, io_vec_count, offset, flags, ctx)?
    };
    Ok(SyscallReturn::Return(res as _))
}

fn do_sys_pwritev(
    raw_fd: RawFileDesc,
    io_vec_ptr: Vaddr,
    io_vec_count: usize,
    offset: i64,
    raw_flags: u32,
    ctx: &Context,
) -> Result<usize> {
    debug!(
        "raw_fd = {}, io_vec_ptr = 0x{:x}, io_vec_counter = 0x{:x}, offset = 0x{:x}, flags = 0x{:x}",
        raw_fd, io_vec_ptr, io_vec_count, offset, raw_flags
    );

    if offset < 0 {
        return_errno_with_message!(Errno::EINVAL, "offset cannot be negative");
    }

    let mut file_table = ctx.thread_local.borrow_file_table_mut();
    let file = get_file_fast!(&mut file_table, raw_fd.try_into()?);

    let user_space = ctx.user_space();
    let mut reader_array = VmReaderArray::from_user_io_vecs(&user_space, io_vec_ptr, io_vec_count)?;

    // Probe with a zero-length write so that unsupported files (e.g., pipes)
    // still return the correct errno even when all buffers are empty, or before
    // the flags are checked.
    if reader_array.readers_mut().is_empty() || raw_flags != 0 {
        let empty = [0u8; 0];
        let mut reader = VmReader::from(empty.as_slice()).to_fallible();
        file.write_at(offset as usize, &mut reader)?;
        if reader_array.readers_mut().is_empty() {
            return Ok(0);
        }
    }
    let flags = RwfFlags::from_raw_checked(raw_flags, &**file)?;

    let mut total_len: usize = 0;
    let mut cur_offset = offset as usize;

    for reader in reader_array.readers_mut() {
        debug_assert!(reader.has_remain());

        // TODO: According to the man page
        // at <https://man7.org/linux/man-pages/man2/readv.2.html>,
        // writev must be atomic,
        // but the current implementation does not ensure atomicity.
        // A suitable fix would be to add a `writev` method for the `FileLike` trait,
        // allowing each subsystem to implement atomicity.
        match file.write_at_with_flags(cur_offset, reader, flags) {
            Ok(write_len) => {
                total_len += write_len;
                cur_offset += write_len;
            }
            Err(_) if total_len > 0 => break,
            Err(err) => return Err(err),
        }
        if reader.has_remain() {
            // Partial write, maybe errors in the middle
            break;
        }
    }
    if total_len > 0 {
        fs::vfs::notify::on_modify(&file);
    }

    Ok(total_len)
}

fn do_sys_writev(
    raw_fd: RawFileDesc,
    io_vec_ptr: Vaddr,
    io_vec_count: usize,
    raw_flags: u32,
    ctx: &Context,
) -> Result<usize> {
    debug!(
        "raw_fd = {}, io_vec_ptr = 0x{:x}, io_vec_counter = 0x{:x}, flags = 0x{:x}",
        raw_fd, io_vec_ptr, io_vec_count, raw_flags
    );

    let mut file_table = ctx.thread_local.borrow_file_table_mut();
    let file = get_file_fast!(&mut file_table, raw_fd.try_into()?);
    check_writable(&**file)?;

    let mut total_len = 0;

    let user_space = ctx.user_space();
    let mut reader_array = VmReaderArray::from_user_io_vecs(&user_space, io_vec_ptr, io_vec_count)?;

    // Like Linux, nothing is written if there are no data, and the flags are not checked.
    // Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/fs/read_write.c#L1038-L1050>
    if reader_array.sum_lens() == 0 {
        return Ok(0);
    }
    let flags = RwfFlags::from_raw_checked(raw_flags, &**file)?;

    // Like Linux, a socket sends all the buffers as one message.
    if let Some(socket) = file.as_socket() {
        let sent_len =
            write_socket(socket, &mut reader_array, flags).map_err(|err| match err.error() {
                Errno::EINTR => Error::new(Errno::ERESTARTSYS),
                _ => err,
            })?;
        if sent_len > 0 {
            fs::vfs::notify::on_modify(&file);
        }
        return Ok(sent_len);
    }

    for reader in reader_array.readers_mut() {
        debug_assert!(reader.has_remain());

        // TODO: According to the man page
        // at <https://man7.org/linux/man-pages/man2/readv.2.html>,
        // writev must be atomic,
        // but the current implementation does not ensure atomicity.
        // A suitable fix would be to add a `writev` method for the `FileLike` trait,
        // allowing each subsystem to implement atomicity.
        match file.write_with_flags(reader, flags) {
            Ok(write_len) => total_len += write_len,
            Err(_) if total_len > 0 => break,
            Err(err) => return Err(err),
        }
        if reader.has_remain() {
            // Partial write, maybe errors in the middle
            break;
        }
    }
    if total_len > 0 {
        fs::vfs::notify::on_modify(&file);
    }

    Ok(total_len)
}

/// Checks whether the file is opened for writing, which is checked before the data and the flags.
fn check_writable(file: &dyn FileLike) -> Result<()> {
    if file.status_flags().contains(StatusFlags::O_PATH) || !file.access_mode().is_writable() {
        return_errno_with_message!(Errno::EBADF, "the file is not opened for writing");
    }
    Ok(())
}
