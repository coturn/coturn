/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Link-only stubs for tests/test_dtls_listener_uaf.c, which compiles the real
 * src/apps/relay/dtls_listener.c. The test drives the static new-socket path in
 * handle_udp_packet(); everything else that file references is satisfied here
 * so the binary links without the rest of the relay.
 *
 * None of these are called on that path. They abort if a later change routes
 * the test into one of them. This file stays free of relay headers so the
 * stubs do not have to copy the real prototypes.
 */

#include <stdio.h>
#include <stdlib.h>

#define LINK_STUB(name)                                                                                                \
  void name(void);                                                                                                     \
  void name(void) {                                                                                                    \
    fprintf(stderr, "unexpected call to link stub %s\n", #name);                                                       \
    abort();                                                                                                           \
  }

LINK_STUB(allocate_super_memory_engine_func)
LINK_STUB(close_ioa_socket)
LINK_STUB(create_ioa_socket_from_ssl)
LINK_STUB(get_default_realm_options)
LINK_STUB(get_realm_options_by_origin)
LINK_STUB(get_remote_addr_from_ioa_socket)
LINK_STUB(get_version)
LINK_STUB(ioa_engine_record_packets)
LINK_STUB(ioa_engine_record_udp_recvmmsg_batch)
LINK_STUB(ioa_engine_record_udp_recvmmsg_no_buffer)
LINK_STUB(ioa_engine_record_udp_recvmmsg_unavailable)
LINK_STUB(ioa_engine_record_udp_recvmmsg_wouldblock)
LINK_STUB(ioa_init_recvmmsg_hdr)
LINK_STUB(ioa_network_buffer_allocate)
LINK_STUB(ioa_network_buffer_data)
LINK_STUB(ioa_network_buffer_delete)
LINK_STUB(ioa_network_buffer_get_capacity_udp)
LINK_STUB(ioa_network_buffer_get_size)
LINK_STUB(ioa_network_buffer_reset)
LINK_STUB(ioa_network_buffer_set_size)
LINK_STUB(ioa_parse_udp_recvmsg_cmsg)
LINK_STUB(ioa_socket_check_bandwidth)
LINK_STUB(ioa_socket_tobeclosed)
LINK_STUB(is_connreset)
LINK_STUB(set_raw_socket_tos_options)
LINK_STUB(set_raw_socket_ttl_options)
LINK_STUB(set_socket_options)
LINK_STUB(shutdown_client_connection)
LINK_STUB(ssl_read)
LINK_STUB(stun_report_binding)
LINK_STUB(turn_dtls_half_open_dec)
LINK_STUB(turn_dtls_half_open_try_inc)
LINK_STUB(turn_reset_socket_ttl_tos)
LINK_STUB(turn_server_stateless_nonce_enabled)
LINK_STUB(turn_server_stateless_nonce_lifetime)
LINK_STUB(turn_server_unauthenticated_reply_suppressed)
LINK_STUB(turn_session_refresh_to_be_allocated_timeout)
LINK_STUB(udp_recvfrom)
LINK_STUB(udp_send)
LINK_STUB(udp_sendmmsg_batch_begin)
LINK_STUB(udp_sendmmsg_batch_end)
LINK_STUB(ur_addr_map_del)
LINK_STUB(ur_addr_map_init)
LINK_STUB(would_block)
