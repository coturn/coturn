/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Link-only stubs for tests/test_turn_server_send.c, which compiles the real
 * src/server/ns_turn_server.c. ns_turn_server.c is written against the
 * abstract ioa_* interface in include/turn/ns_turn_ioalib.h, which the relay
 * (src/apps/relay) implements; this file plus the functional stubs in the test
 * translation unit stand in for that implementation, so the server core can be
 * exercised without a socket, an event loop, or a database.
 *
 * Everything here is on a code path the tests never take. The stubs are
 * deliberately declared without the relay headers, and thus without the real
 * prototypes: only the symbol name matters to the linker, and replicating the
 * full signatures would add no behavioral value. Each one abort()s loudly, so
 * a future change that routes a tested path into one of these fails the test
 * run instead of silently doing nothing.
 *
 * The stubs a tested path *does* reach live in test_turn_server_send.c, where
 * the real headers are in scope and the signatures must match.
 */

#include <stdio.h>
#include <stdlib.h>

#define LINK_STUB(name)                                                                                                \
  void name(void);                                                                                                     \
  void name(void) {                                                                                                    \
    fprintf(stderr, "unexpected call to link stub %s\n", #name);                                                       \
    abort();                                                                                                           \
  }

/* Socket lifecycle and attributes. */
LINK_STUB(close_ioa_socket_after_processing_if_necessary)
LINK_STUB(detach_ioa_socket)
LINK_STUB(get_ioa_socket_app_type)
LINK_STUB(get_ioa_socket_cipher)
LINK_STUB(get_ioa_socket_from_reservation)
LINK_STUB(get_ioa_socket_session)
LINK_STUB(get_ioa_socket_ssl_method)
LINK_STUB(get_ioa_socket_tls_cipher)
LINK_STUB(get_ioa_socket_tls_method)
LINK_STUB(get_local_addr_from_ioa_socket)
LINK_STUB(get_local_mtu_ioa_socket)
LINK_STUB(get_remote_addr_from_ioa_socket)
LINK_STUB(ioa_socket_tobeclosed)
LINK_STUB(register_callback_on_ioa_socket)
LINK_STUB(set_ioa_socket_app_type)
LINK_STUB(set_ioa_socket_buf_size)
LINK_STUB(set_ioa_socket_session)
LINK_STUB(set_ioa_socket_sub_session)
LINK_STUB(set_ioa_socket_tobeclosed)

/* Relay allocation and RFC 6062 TCP relays. */
LINK_STUB(create_relay_ioa_sockets)
LINK_STUB(ioa_create_connecting_tcp_relay_socket)
LINK_STUB(set_do_not_use_df)

/* Timers. */
LINK_STUB(delete_ioa_timer)
LINK_STUB(set_ioa_timer)

/* Realms, access lists, reporting. */
LINK_STUB(get_default_realm_options)
LINK_STUB(get_realm_options_by_name)
LINK_STUB(get_realm_options_by_origin)
LINK_STUB(ioa_get_blacklist)
LINK_STUB(ioa_get_whitelist)
LINK_STUB(ioa_lock_blacklist)
LINK_STUB(ioa_lock_whitelist)
LINK_STUB(ioa_unlock_blacklist)
LINK_STUB(ioa_unlock_whitelist)
LINK_STUB(stun_report_binding)
LINK_STUB(turn_report_allocation_set)

/* HTTP(S) side doors on the client listener. */
LINK_STUB(handle_http_echo)
LINK_STUB(try_acme_redirect)

/* --multiplex-peer shared relay sockets. */
LINK_STUB(mp_deregister_permission_peers)
LINK_STUB(mp_deregister_session_peers)
LINK_STUB(mp_register_peer)
