/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Link-only stubs for tests/test_detach_socket_ttl.c, which compiles the real
 * src/apps/relay/ns_ioalib_engine_impl.c to reach detach_ioa_socket(). Keep this
 * file free of relay includes so stubs need not match the real prototypes;
 * none of these are called by the tested paths.
 */

#include <stdio.h>
#include <stdlib.h>

#define LINK_STUB(name)                                                                                                \
  void name(void);                                                                                                     \
  void name(void) {                                                                                                    \
    fprintf(stderr, "unexpected call to link stub %s\n", #name);                                                       \
    abort();                                                                                                           \
  }

LINK_STUB(allocation_get_permission)
LINK_STUB(decrement_global_allocation_count)
LINK_STUB(delete_tcp_connection)
LINK_STUB(get_a_local_relay)
LINK_STUB(get_allocation_ss)
LINK_STUB(get_dbdriver)
LINK_STUB(get_redis_async_connection)
LINK_STUB(get_turn_server_time)
LINK_STUB(increment_global_allocation_count)
LINK_STUB(is_allocation_valid)
LINK_STUB(mp_peer_table_deregister)
LINK_STUB(mp_peer_table_deregister_ip)
LINK_STUB(mp_peer_table_deregister_session)
LINK_STUB(mp_peer_table_init)
LINK_STUB(mp_peer_table_lookup)
LINK_STUB(mp_peer_table_register)
LINK_STUB(prom_dec_allocation)
LINK_STUB(prom_flush_401_counters)
LINK_STUB(prom_flush_udp_counters)
LINK_STUB(prom_inc_allocation)
LINK_STUB(prom_inc_stun_binding_error)
LINK_STUB(prom_inc_stun_binding_request)
LINK_STUB(prom_inc_stun_binding_response)
LINK_STUB(prom_set_finished_traffic)
LINK_STUB(report_turn_session_info)
LINK_STUB(rtcp_map_get)
LINK_STUB(rtcp_map_put)
LINK_STUB(send_message_to_redis)
LINK_STUB(shutdown_client_connection)
LINK_STUB(turn_peer_input_handler)
LINK_STUB(turn_server_get_engine)
LINK_STUB(turnipports_allocate)
LINK_STUB(turnipports_allocate_even)
LINK_STUB(turnipports_release)
LINK_STUB(ur_addr_map_del)
LINK_STUB(ur_addr_map_put)

/* Oversized stand-in for turn_params_t; the tested paths never read its fields. */
unsigned char turn_params[16384];
