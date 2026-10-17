#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

./tcp_server &
sleep 0.2
./tcp_client

./udp_server &
sleep 0.2
./udp_client

./unix_server &
sleep 0.2
./unix_client

./af_unspec
./broadcast_complex
./listen_backlog
./msg_dontwait
./msg_peek
./msg_waitall
./msg_trunc
./privileged_ports
./send_buf_full
./sendmmsg
./socketpair
./socket_ioctl
./sockoption
./sockoption_short
./sockoption_unix
./tcp_accept_reset
./tcp_err
./tcp_poll
./tcp_reuseaddr
./tcp_wildcard
./tcp_wrapped_buffer_io
./udp_broadcast
./udp_connected
./udp_err
./udp_wildcard
./user_buffer_fault
./unix_datagram_err
./unix_seqpacket_err
./unix_stream_err

./netlink_route
./rtnl_err
./uevent_err
