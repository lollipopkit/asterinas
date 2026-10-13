// SPDX-License-Identifier: MPL-2.0

use int_to_c_enum::TryFromInt;

use super::{RawSocketOption, SocketOption, impl_raw_socket_option};
use crate::{net::socket::ip::options::V6Only, prelude::*};

/// Socket options for IPv6 sockets.
///
/// Only the supported options are listed here. The raw definitions can be found at:
/// <https://elixir.bootlin.com/linux/v6.16.5/source/include/uapi/linux/in6.h#L170>.
#[repr(i32)]
#[derive(Clone, Copy, Debug, TryFromInt)]
pub(crate) enum CIpv6OptionName {
    V6ONLY = 26,
}

pub(crate) fn new_ipv6_option(name: i32) -> Result<Box<dyn RawSocketOption>> {
    let name = CIpv6OptionName::try_from(name).map_err(|_| Errno::ENOPROTOOPT)?;
    match name {
        CIpv6OptionName::V6ONLY => Ok(Box::new(V6Only::new())),
    }
}

impl_raw_socket_option!(V6Only);
