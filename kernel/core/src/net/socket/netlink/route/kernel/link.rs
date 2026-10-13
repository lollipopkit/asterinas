// SPDX-License-Identifier: MPL-2.0

//! Handle link-related requests.

use core::num::NonZero;

use aster_bigtcp::{
    iface::{InterfaceFlags, InterfaceType},
    wire::EthernetAddress,
};

use super::util::finish_response;
use crate::{
    net::{
        iface::{DEFAULT_TX_QUEUE_LEN, Iface, iter_all_ifaces},
        socket::netlink::{
            message::{
                CMsgSegHdr, CSegmentType, ErrorSegment, GetRequestFlags, NewRequestFlags,
                SegHdrCommonFlags,
            },
            route::message::{LinkAttr, LinkSegment, LinkSegmentBody, RtnlSegment},
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

/// The unspecified link-layer address.
const UNSPECIFIED_LINK_ADDR: EthernetAddress = EthernetAddress([0; 6]);

pub(super) fn do_get_link(request_segment: &LinkSegment) -> Result<Vec<RtnlSegment>> {
    let filter_by = FilterBy::from_request(request_segment)?;

    let mut response_segments: Vec<RtnlSegment> = iter_all_ifaces()
        // Filter to include only requested links.
        .filter(|iface| match &filter_by {
            FilterBy::Index(index) => *index == iface.index(),
            FilterBy::Name(name) => *name == iface.name().as_cstr(),
            FilterBy::Dump => true,
        })
        .map(|iface| iface_to_new_link(request_segment.header(), iface))
        .map(RtnlSegment::NewLink)
        .collect();

    let dump_all = matches!(filter_by, FilterBy::Dump);

    if !dump_all && response_segments.is_empty() {
        return_errno_with_message!(Errno::ENODEV, "no link found");
    }

    finish_response(request_segment.header(), dump_all, &mut response_segments);

    Ok(response_segments)
}

/// Handles `RTM_NEWLINK`, which creates a link or modifies an existing link.
///
/// Neither creating links nor modifying link attributes is supported yet. However, a request that
/// does not change anything (e.g., `ip link set lo up` when `lo` is already up) succeeds.
pub(super) fn do_new_link(request_segment: &LinkSegment) -> Result<Vec<RtnlSegment>> {
    let header = request_segment.header();
    let body = request_segment.body();
    let flags = NewRequestFlags::from_bits_truncate(header.flags);

    let required_name = request_segment.attrs().iter().find_map(|attr| {
        if let LinkAttr::Name(name) = attr {
            Some(name.as_cstr())
        } else {
            None
        }
    });
    // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/net/core/rtnetlink.c#L3909-L3926>.
    let iface = if let Some(index) = body.index {
        iter_all_ifaces().find(|iface| iface.index() == index.get())
    } else if let Some(name) = required_name {
        iter_all_ifaces().find(|iface| iface.name().as_cstr() == name)
    } else {
        None
    };

    let Some(iface) = iface else {
        if flags.contains(NewRequestFlags::CREATE) {
            return_errno_with_message!(Errno::EOPNOTSUPP, "creating links is not supported");
        }
        return_errno_with_message!(Errno::ENODEV, "no link found");
    };

    // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/net/core/rtnetlink.c#L3709>.
    if flags.contains(NewRequestFlags::EXCL) {
        return_errno_with_message!(Errno::EEXIST, "the link already exists");
    }

    if request_segment
        .attrs()
        .iter()
        .any(|attr| !matches!(attr, LinkAttr::Name(_)))
    {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "modifying link attributes is not supported"
        );
    }

    // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/net/core/rtnetlink.c#L3140-L3142>.
    // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/net/core/rtnetlink.c#L1092-L1103>.
    let old_flags = iface.flags();
    let new_flags = if body.change.is_empty() {
        if body.flags.is_empty() {
            old_flags
        } else {
            body.flags
        }
    } else {
        (body.flags & body.change) | (old_flags - body.change)
    };
    if (new_flags ^ old_flags).intersects(USER_CHANGEABLE_FLAGS) {
        return_errno_with_message!(Errno::EOPNOTSUPP, "changing link flags is not supported");
    }

    let mut response_segments = Vec::new();
    if SegHdrCommonFlags::from_bits_truncate(header.flags).contains(SegHdrCommonFlags::ACK) {
        let ack_segment = ErrorSegment::new_from_request(header, None);
        response_segments.push(RtnlSegment::Error(ack_segment));
    }
    Ok(response_segments)
}

/// The link flags that can be changed by user space.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/net/core/dev.c#L9444-L9447>.
const USER_CHANGEABLE_FLAGS: InterfaceFlags = InterfaceFlags::UP
    .union(InterfaceFlags::DEBUG)
    .union(InterfaceFlags::NOTRAILERS)
    .union(InterfaceFlags::NOARP)
    .union(InterfaceFlags::DYNAMIC)
    .union(InterfaceFlags::MULTICAST)
    .union(InterfaceFlags::PORTSEL)
    .union(InterfaceFlags::AUTOMEDIA)
    .union(InterfaceFlags::PROMISC)
    .union(InterfaceFlags::ALLMULTI);

enum FilterBy<'a> {
    Index(u32),
    Name(&'a CStr),
    Dump,
}

impl<'a> FilterBy<'a> {
    fn from_request(request_segment: &'a LinkSegment) -> Result<Self> {
        let dump_all = {
            let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
            flags.contains(GetRequestFlags::DUMP)
        };
        if dump_all {
            validate_dumplink_request(request_segment.body())?;
            return Ok(Self::Dump);
        }

        validate_getlink_request(request_segment.body())?;

        // `index` takes precedence over `required_name`.

        if let Some(required_index) = request_segment.body().index {
            return Ok(Self::Index(required_index.get()));
        }

        let required_name = request_segment.attrs().iter().find_map(|attr| {
            if let LinkAttr::Name(name) = attr {
                Some(name.as_cstr())
            } else {
                None
            }
        });
        if let Some(required_name) = required_name {
            return Ok(Self::Name(required_name));
        }

        return_errno_with_message!(
            Errno::EINVAL,
            "either interface name or index should be specified for non-dump mode"
        );
    }
}

// The below functions starting with `validate_` should only be enabled in strict mode.
// Reference: <https://docs.kernel.org/userspace-api/netlink/intro.html#strict-checking>.

fn validate_getlink_request(body: &LinkSegmentBody) -> Result<()> {
    // FIXME: The Linux implementation also checks the `padding` and `change` fields,
    // but these fields are lost during the conversion of a `CIfInfoMsg` to `LinkSegmentBody`.
    // We should consider including the `change` field in `LinkSegmentBody`.
    // Reference: <https://elixir.bootlin.com/linux/v6.13/source/net/core/rtnetlink.c#L4043>.
    if !body.flags.is_empty() || body.type_ != InterfaceType::NETROM {
        return_errno_with_message!(Errno::EINVAL, "the flags or the type is not valid");
    }

    Ok(())
}

fn validate_dumplink_request(body: &LinkSegmentBody) -> Result<()> {
    // FIXME: The Linux implementation also checks the `padding` and `change` fields.
    // Reference: <https://elixir.bootlin.com/linux/v6.13/source/net/core/rtnetlink.c#L2378>.
    if !body.flags.is_empty() || body.type_ != InterfaceType::NETROM {
        return_errno_with_message!(Errno::EINVAL, "the flags or the type is not valid");
    }

    // The check is from <https://elixir.bootlin.com/linux/v6.13/source/net/core/rtnetlink.c#L2383>.
    if body.index.is_some() {
        return_errno_with_message!(
            Errno::EINVAL,
            "filtering by interface index is not valid for link dumps"
        );
    }

    Ok(())
}

fn iface_to_new_link(request_header: &CMsgSegHdr, iface: &Arc<Iface>) -> LinkSegment {
    let header = CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWLINK as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    };

    let link_message = LinkSegmentBody {
        family: CSocketAddrFamily::AF_UNSPEC,
        type_: iface.type_(),
        index: NonZero::new(iface.index()),
        flags: iface.flags(),
        change: InterfaceFlags::empty(),
    };

    // Linux may report dozens of attributes in a fixed order.
    // See the reference below for the complete attribute list and ordering.
    // TODO: Asterinas currently reports only a subset of these attributes.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/core/rtnetlink.c#L2050>.
    let mut attrs = Vec::with_capacity(5);
    attrs.extend([
        LinkAttr::Name(*iface.name()),
        LinkAttr::TxqLen(DEFAULT_TX_QUEUE_LEN),
        LinkAttr::Mtu(iface.mtu() as u32),
    ]);

    let (link_addr, link_broadcast_addr) = match iface.ethernet_addr() {
        Some(ethernet_addr) => (ethernet_addr, EthernetAddress::BROADCAST),
        None => (UNSPECIFIED_LINK_ADDR, UNSPECIFIED_LINK_ADDR),
    };
    attrs.extend([
        LinkAttr::Address(link_addr),
        LinkAttr::Broadcast(link_broadcast_addr),
    ]);

    LinkSegment::new(header, link_message, attrs)
}
