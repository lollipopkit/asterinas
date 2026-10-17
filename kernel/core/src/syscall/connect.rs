// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs::file::file_table::{RawFileDesc, get_file_fast},
    net::socket::util::{SocketAddr, audit_connect, check_connect},
    prelude::*,
    util::net::read_socket_addr_from_user,
};

pub(super) fn sys_connect(
    sockfd: RawFileDesc,
    sockaddr_ptr: Vaddr,
    addr_len: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let socket_addr = read_socket_addr_from_user(sockaddr_ptr, addr_len as _)?;
    debug!("fd = {sockfd}, socket_addr = {socket_addr:?}");

    let mut file_table = ctx.thread_local.borrow_file_table_mut();
    let file = get_file_fast!(&mut file_table, sockfd.try_into()?);
    let socket = file.as_socket_or_err()?;

    check_connect(socket, Some(&socket_addr))?;
    let audit_target = SocketAddr::audit_target_if_audited(Some(&socket_addr));
    let res = socket.connect(socket_addr);
    // A non-blocking connection is in progress towards the destination.
    if res
        .as_ref()
        .err()
        .is_none_or(|err| err.error() == Errno::EINPROGRESS)
    {
        audit_connect(audit_target);
    }
    res.map_err(|err| match err.error() {
        // FIXME: `connect` should not be restarted if a timeout has been set on the socket using `setsockopt`.
        Errno::EINTR => Error::new(Errno::ERESTARTSYS),
        _ => err,
    })?;

    Ok(SyscallReturn::Return(0))
}
