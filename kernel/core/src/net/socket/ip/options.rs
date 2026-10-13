// SPDX-License-Identifier: MPL-2.0

use core::num::NonZeroU8;

use aster_bigtcp::socket::NeedIfacePoll;

use crate::{
    net::socket::options::{
        SocketOption,
        macros::{impl_socket_options, sock_option_mut, sock_option_ref},
    },
    prelude::*,
};

/// IP-level socket options.
#[derive(Clone, Copy, CopyGetters, Debug, Setters)]
#[get_copy = "pub"]
#[set = "pub"]
pub(super) struct IpOptionSet {
    tos: u8,
    ttl: IpTtl,
    hdrincl: bool,
    recverr: bool,
}

const DEFAULT_TTL: u8 = 64;
pub(super) const INET_ECN_MASK: u8 = 3;

impl IpOptionSet {
    pub(super) const fn new_tcp() -> Self {
        Self {
            tos: 0,
            ttl: IpTtl(None),
            hdrincl: false,
            recverr: false,
        }
    }

    pub(super) const fn new_udp() -> Self {
        Self {
            tos: 0,
            ttl: IpTtl(None),
            hdrincl: false,
            recverr: false,
        }
    }

    pub(super) fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            ip_tos @ Tos => {
                let tos = self.tos();
                ip_tos.set(tos as _);
            }
            ip_ttl @ Ttl => {
                let ttl = self.ttl();
                ip_ttl.set(ttl);
            }
            ip_hdrincl @ Hdrincl => {
                let hdrincl = self.hdrincl();
                ip_hdrincl.set(hdrincl);
            }
            ip_recverr @ Recverr => {
                let recverr = self.recverr();
                ip_recverr.set(recverr);
            }
            _ => return_errno_with_message!(Errno::ENOPROTOOPT, "the socket option is unknown"),
        });

        Ok(())
    }

    pub(super) fn set_option(
        &mut self,
        option: &dyn SocketOption,
        socket: &dyn SetIpLevelOption,
    ) -> Result<NeedIfacePoll> {
        sock_option_ref!(match option {
            ip_tos @ Tos => {
                let old_value = self.tos();
                let mut val = *ip_tos.get().unwrap() as u8;
                val &= !INET_ECN_MASK;
                val |= old_value & INET_ECN_MASK;
                self.set_tos(val);
            }
            ip_ttl @ Ttl => {
                let ttl = ip_ttl.get().unwrap();
                self.set_ttl(*ttl);
            }
            ip_hdrincl @ Hdrincl => {
                let hdrincl = ip_hdrincl.get().unwrap();
                socket.set_hdrincl(*hdrincl)?;
                self.set_hdrincl(*hdrincl);
            }
            ip_recverr @ Recverr => {
                let recverr = ip_recverr.get().unwrap();
                self.set_recverr(*recverr);
            }
            _ => return_errno_with_message!(
                Errno::ENOPROTOOPT,
                "the socket option to be set is unknown"
            ),
        });

        Ok(NeedIfacePoll::FALSE)
    }
}

impl_socket_options!(
    pub(crate) struct Tos(i32);
    pub(crate) struct Ttl(IpTtl);
    pub(crate) struct Hdrincl(bool);
    pub(crate) struct Recverr(bool);
    pub(crate) struct V6Only(bool);
);

#[derive(Clone, Copy, Debug)]
pub(crate) struct IpTtl(Option<NonZeroU8>);

impl IpTtl {
    pub(crate) const fn new(val: Option<NonZeroU8>) -> Self {
        Self(val)
    }

    pub(crate) const fn get(&self) -> u8 {
        if let Some(val) = self.0 {
            val.get()
        } else {
            DEFAULT_TTL
        }
    }
}

pub(super) trait SetIpLevelOption {
    fn set_hdrincl(&self, _hdrincl: bool) -> Result<()>;
}

/// IPv6-level socket options.
#[derive(Clone, Copy, CopyGetters, Debug, Setters)]
#[get_copy = "pub"]
#[set = "pub"]
pub(super) struct Ipv6OptionSet {
    v6only: bool,
}

impl Ipv6OptionSet {
    pub(super) const fn new() -> Self {
        // Linux uses `net.ipv6.bindv6only` as the default value, which defaults to 0.
        Self { v6only: false }
    }

    pub(super) fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            ipv6_v6only @ V6Only => {
                ipv6_v6only.set(self.v6only());
            }
            _ => return_errno_with_message!(Errno::ENOPROTOOPT, "the socket option is unknown"),
        });

        Ok(())
    }

    pub(super) fn set_option(
        &mut self,
        option: &dyn SocketOption,
        socket: &dyn SetIpv6LevelOption,
    ) -> Result<()> {
        sock_option_ref!(match option {
            ipv6_v6only @ V6Only => {
                // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/net/ipv6/ipv6_sockglue.c#L536>.
                if socket.is_bound() {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "IPV6_V6ONLY cannot be changed after the socket is bound"
                    );
                }
                self.set_v6only(*ipv6_v6only.get().unwrap());
            }
            _ => return_errno_with_message!(
                Errno::ENOPROTOOPT,
                "the socket option to be set is unknown"
            ),
        });

        Ok(())
    }
}

pub(super) trait SetIpv6LevelOption {
    /// Returns whether the socket is bound to a local port.
    fn is_bound(&self) -> bool;
}
