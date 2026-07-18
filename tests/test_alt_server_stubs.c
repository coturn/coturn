/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Link-only stubs for tests/test_alt_server_list.c, which compiles the real
 * src/apps/relay/netengine.c. The tests exercise only the alternate-server
 * list helpers (add_alt_server / del_alt_server); everything else netengine.c
 * references — listener/engine construction, the turnserver core, userdb,
 * admin server, prometheus — is satisfied here so the binary links without
 * dragging in the whole relay.
 *
 * None of these are ever called by the tested code paths, so they are defined
 * without the relay headers (and thus without the real prototypes) and abort()
 * loudly if a future netengine.c change routes the tested paths into one of
 * them. Keep this file free of relay includes: pulling in the headers would
 * force every stub to replicate the full (very wide) real signatures for no
 * behavioral gain.
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
LINK_STUB(allocate_super_memory_region_func)
LINK_STUB(auth_ping)
LINK_STUB(check_new_allocation_quota)
LINK_STUB(close_ioa_socket)
LINK_STUB(create_dtls_listener_server)
LINK_STUB(create_ioa_engine)
LINK_STUB(create_tls_listener_server)
LINK_STUB(get_secrets_list_size)
LINK_STUB(get_user_key)
LINK_STUB(init_multiplex_peer) /* referenced from a __linux__-only block */
LINK_STUB(init_turn_server)
LINK_STUB(ioa_engine_set_rtcp_map)
LINK_STUB(ioa_network_buffer_allocate)
LINK_STUB(ioa_network_buffer_data)
LINK_STUB(ioa_network_buffer_delete)
LINK_STUB(ioa_network_buffer_get_size)
LINK_STUB(ioa_network_buffer_header_init)
LINK_STUB(ioa_network_buffer_set_size)
LINK_STUB(new_super_memory_region)
LINK_STUB(open_client_connection_session)
LINK_STUB(prom_inc_unauthenticated_401_dropped_response)
LINK_STUB(prom_inc_unauthenticated_401_request)
LINK_STUB(prom_inc_unauthenticated_401_response)
LINK_STUB(release_allocation_quota)
LINK_STUB(reread_realms)
LINK_STUB(rtcp_map_create)
LINK_STUB(send_https_socket)
LINK_STUB(send_turn_session_info)
LINK_STUB(set_rfc5780)
LINK_STUB(set_unauthenticated_401_metric_cbs)
LINK_STUB(setup_admin_thread)
LINK_STUB(start_user_check)
LINK_STUB(turn_cancel_session)
LINK_STUB(turnipports_add_ip)
LINK_STUB(turnipports_create)
LINK_STUB(turnserver_accept_tcp_client_data_connection)
LINK_STUB(udp_send_message)
LINK_STUB(update_white_and_black_lists)

/* Data symbols netengine.c references (mainrelay.c / turn_admin_server.c
 * normally define them). Only their addresses are taken by code the tests
 * never run, so an over-sized zeroed blob stands in for struct admin_server. */
unsigned char adminserver[8192];
size_t global_allocation_count;
