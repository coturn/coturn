/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "ns_turn_server.h"

#include "ns_turn_utils.h"
#include "ns_turn_allocation.h"
#include "ns_turn_msg_addr.h"
#include "ns_turn_ioalib.h"

///////////////////////////////////////////

#define FUNCSTART if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:start\n",__FUNCTION__,__LINE__)
#define FUNCEND if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:end\n",__FUNCTION__,__LINE__)

////////////////////////////////////////////////

static inline int get_family(int stun_family) {
	switch(stun_family) {
	case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
		return AF_INET;
	case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
		return AF_INET6;
	case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT:
		return AF_INET;
	default:
		return AF_INET;
	};
}

////////////////////////////////////////////////

#define MAX_NUMBER_OF_UNKNOWN_ATTRS (128)

int TURN_MAX_ALLOCATE_TIMEOUT = 60;
int TURN_MAX_ALLOCATE_TIMEOUT_STUN_ONLY = 3;

static inline void log_method(ts_ur_super_session* ss, const char *method, int err_code, const u08bits *reason)
{
  if(ss) {
	  if(!method) method = "unknown";
	  if(!err_code) {
		  if(ss->origin[0]) {
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					"session %018llu: origin <%s> realm <%s> user <%s>: incoming packet %s processed, success\n",
					(unsigned long long)(ss->id), (const char*)(ss->origin),(const char*)(ss->realm_options.name),(const char*)(ss->username),method);
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"session %018llu: realm <%s> user <%s>: incoming packet %s processed, success\n",
				(unsigned long long)(ss->id), (const char*)(ss->realm_options.name),(const char*)(ss->username),method);
		}
	  } else {
		  if(!reason) reason=get_default_reason(err_code);
		  if(ss->origin[0]) {
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					  "session %018llu: origin <%s> realm <%s> user <%s>: incoming packet %s processed, error %d: %s\n",
					  (unsigned long long)(ss->id), (const char*)(ss->origin),(const char*)(ss->realm_options.name),(const char*)(ss->username), method, err_code, reason);
		  } else {
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					  "session %018llu: realm <%s> user <%s>: incoming packet %s processed, error %d: %s\n",
					  (unsigned long long)(ss->id), (const char*)(ss->realm_options.name),(const char*)(ss->username), method, err_code, reason);
		  }
	  }
  }
}

///////////////////////////////////////////

static int attach_socket_to_session(turn_turnserver* server, ioa_socket_handle s, ts_ur_super_session* ss);

static int check_stun_auth(turn_turnserver *server,
			ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
			int *err_code, 	const u08bits **reason,
			ioa_net_data *in_buffer, ioa_network_buffer_handle nbh,
			u16bits method, int *message_integrity,
			int *postpone_reply,
			int can_resume);

static int create_relay_connection(turn_turnserver* server,
		ts_ur_super_session *ss, u32bits lifetime,
		int address_family, u08bits transport,
		int even_port, u64bits in_reservation_token, u64bits *out_reservation_token,
		int *err_code, const u08bits **reason, accept_cb acb);

static int refresh_relay_connection(turn_turnserver* server,
		ts_ur_super_session *ss, u32bits lifetime, int even_port,
		u64bits in_reservation_token, u64bits *out_reservation_token,
		int *err_code, int family);

static int write_client_connection(turn_turnserver *server, ts_ur_super_session* ss, ioa_network_buffer_handle nbh, int ttl, int tos);

static void tcp_peer_accept_connection(ioa_socket_handle s, void *arg);

static int read_client_connection(turn_turnserver *server,
				  ts_ur_super_session *ss, ioa_net_data *in_buffer,
				  int can_resume, int count_usage);

static int need_stun_authentication(turn_turnserver *server, ts_ur_super_session *ss);

/////////////////// timer //////////////////////////

static void timer_timeout_handler(ioa_engine_handle e, void *arg)
{
	UNUSED_ARG(e);
	if(arg) {
		turn_turnserver *server=(turn_turnserver*)arg;
		server->ctime = turn_time();
	}
}

turn_time_t get_turn_server_time(turn_turnserver *server)
{
	if(server) {
		return server->ctime;
	}
	return turn_time();
}

/////////////////// quota //////////////////////

static int inc_quota(ts_ur_super_session* ss, u08bits *username)
{
	if(ss && !(ss->quota_used) && ss->server && ((turn_turnserver*)ss->server)->chquotacb && username) {

		if(((turn_turnserver*)ss->server)->ct == TURN_CREDENTIALS_LONG_TERM) {
			if(!(ss->origin_set)) {
				return -1;
			}
		}

		if((((turn_turnserver*)ss->server)->chquotacb)(username, ss->oauth, (u08bits*)ss->realm_options.name)<0) {

			return -1;

		} else {

			STRCPY(ss->username,username);

			ss->quota_used = 1;
		}
	}

	return 0;
}

static void dec_quota(ts_ur_super_session* ss)
{
	if(ss && ss->quota_used && ss->server && ((turn_turnserver*)ss->server)->raqcb) {

		ss->quota_used = 0;

		(((turn_turnserver*)ss->server)->raqcb)(ss->username, ss->oauth, (u08bits*)ss->realm_options.name);
	}
}

static void dec_bps(ts_ur_super_session* ss)
{
	if(ss && ss->server) {

		if(ss->bps) {
			if(((turn_turnserver*)ss->server)->allocate_bps_func) {
				((turn_turnserver*)ss->server)->allocate_bps_func(ss->bps,0);
			}
			ss->bps = 0;
		}
	}
}

/////////////////// server lists ///////////////////

void init_turn_server_addrs_list(turn_server_addrs_list_t *l)
{
	if(l) {
		l->addrs = NULL;
		l->size = 0;
		turn_mutex_init(&(l->m));
	}
}

/////////////////// RFC 5780 ///////////////////////

void set_rfc5780(turn_turnserver *server, get_alt_addr_cb cb, send_message_cb smcb)
{
	if(server) {
		if(!cb || !smcb) {
			server->rfc5780 = 0;
			server->alt_addr_cb = NULL;
			server->sm_cb = NULL;
		} else {
			server->rfc5780 = 1;
			server->alt_addr_cb = cb;
			server->sm_cb = smcb;
		}
	}
}

static int is_rfc5780(turn_turnserver *server)
{
	if(!server)
		return 0;

	return ((server->rfc5780) && (server->alt_addr_cb));
}

static int get_other_address(turn_turnserver *server, ts_ur_super_session *ss, ioa_addr *alt_addr)
{
	if(is_rfc5780(server) && ss && ss->client_socket) {
		int ret = server->alt_addr_cb(get_local_addr_from_ioa_socket(ss->client_socket), alt_addr);
		return ret;
	}

	return -1;
}

static int send_turn_message_to(turn_turnserver *server, ioa_network_buffer_handle nbh, ioa_addr *response_origin, ioa_addr *response_destination)
{
	if(is_rfc5780(server) && nbh && response_origin && response_destination) {
		return server->sm_cb(server->e, nbh, response_origin, response_destination);
	}

	return -1;
}

/////////////////// Peer addr check /////////////////////////////

static int good_peer_addr(turn_turnserver *server, const char* realm, ioa_addr *peer_addr)
{
#define CHECK_REALM(r) if((r)[0] && realm && realm[0] && strcmp((r),realm)) continue

	if(server && peer_addr) {
		if(*(server->no_multicast_peers) && ioa_addr_is_multicast(peer_addr))
			return 0;
		if(*(server->no_loopback_peers) && ioa_addr_is_loopback(peer_addr))
			return 0;

		{
			int i;

			if(server->ip_whitelist) {
				// White listing of addr ranges
				for (i = server->ip_whitelist->ranges_number - 1; i >= 0; --i) {
					CHECK_REALM(server->ip_whitelist->rs[i].realm);
					if (ioa_addr_in_range(&(server->ip_whitelist->rs[i].enc), peer_addr))
						return 1;
				}
			}

			{
				ioa_lock_whitelist(server->e);

				const ip_range_list_t* wl = ioa_get_whitelist(server->e);
				if(wl) {
					// White listing of addr ranges
					for (i = wl->ranges_number - 1; i >= 0; --i) {
						CHECK_REALM(wl->rs[i].realm);
						if (ioa_addr_in_range(&(wl->rs[i].enc), peer_addr)) {
							ioa_unlock_whitelist(server->e);
							return 1;
						}
					}
				}

				ioa_unlock_whitelist(server->e);
			}

			if(server->ip_blacklist) {
				// Black listing of addr ranges
				for (i = server->ip_blacklist->ranges_number - 1; i >= 0; --i) {
					CHECK_REALM(server->ip_blacklist->rs[i].realm);
					if (ioa_addr_in_range(&(server->ip_blacklist->rs[i].enc), peer_addr)) {
						char saddr[129];
						addr_to_string_no_port(peer_addr,(u08bits*)saddr);
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "A peer IP %s denied in the range: %s\n",saddr,server->ip_blacklist->rs[i].str);
						return 0;
					}
				}
			}

			{
				ioa_lock_blacklist(server->e);

				const ip_range_list_t* bl = ioa_get_blacklist(server->e);
				if(bl) {
					// Black listing of addr ranges
					for (i = bl->ranges_number - 1; i >= 0; --i) {
						CHECK_REALM(bl->rs[i].realm);
						if (ioa_addr_in_range(&(bl->rs[i].enc), peer_addr)) {
							ioa_unlock_blacklist(server->e);
							char saddr[129];
							addr_to_string_no_port(peer_addr,(u08bits*)saddr);
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "A peer IP %s denied in the range: %s\n",saddr,bl->rs[i].str);
							return 0;
						}
					}
				}

				ioa_unlock_blacklist(server->e);
			}
		}
	}

#undef CHECK_REALM

	return 1;
}

/////////////////// Allocation //////////////////////////////////

allocation* get_allocation_ss(ts_ur_super_session *ss) {
	return &(ss->alloc);
}

static inline relay_endpoint_session *get_relay_session_ss(ts_ur_super_session *ss, int family)
{
	return get_relay_session(&(ss->alloc),family);
}

static inline ioa_socket_handle get_relay_socket_ss(ts_ur_super_session *ss, int family)
{
	return get_relay_socket(&(ss->alloc),family);
}

/////////// Session info ///////

void turn_session_info_init(struct turn_session_info* tsi) {
	if(tsi) {
		ns_bzero(tsi,sizeof(struct turn_session_info));
	}
}

void turn_session_info_clean(struct turn_session_info* tsi) {
	if(tsi) {
		if(tsi->extra_peers_data) {
			turn_free(tsi->extra_peers_data, sizeof(addr_data)*(tsi->extra_peers_size));
		}
		turn_session_info_init(tsi);
	}
}

void turn_session_info_add_peer(struct turn_session_info* tsi, ioa_addr *peer)
{
	if(tsi && peer) {
		{
			size_t i;
			for(i=0;i<tsi->main_peers_size;++i) {
				if(addr_eq(peer, &(tsi->main_peers_data[i].addr))) {
					return;
				}
			}

			if(tsi->main_peers_size < TURN_MAIN_PEERS_ARRAY_SIZE) {
				addr_cpy(&(tsi->main_peers_data[tsi->main_peers_size].addr),peer);
				addr_to_string(&(tsi->main_peers_data[tsi->main_peers_size].addr),
					(u08bits*)tsi->main_peers_data[tsi->main_peers_size].saddr);
				tsi->main_peers_size += 1;
				return;
			}
		}

		if(tsi->extra_peers_data) {
			size_t sz;
			for(sz=0;sz<tsi->extra_peers_size;++sz) {
				if(addr_eq(peer, &(tsi->extra_peers_data[sz].addr))) {
					return;
				}
			}
		}
		tsi->extra_peers_data = (addr_data*)turn_realloc(tsi->extra_peers_data,tsi->extra_peers_size*sizeof(addr_data),(tsi->extra_peers_size+1)*sizeof(addr_data));
		addr_cpy(&(tsi->extra_peers_data[tsi->extra_peers_size].addr),peer);
		addr_to_string(&(tsi->extra_peers_data[tsi->extra_peers_size].addr),
			       (u08bits*)tsi->extra_peers_data[tsi->extra_peers_size].saddr);
		tsi->extra_peers_size += 1;
	}
}

struct tsi_arg {
	struct turn_session_info* tsi;
	ioa_addr *addr;
};

static int turn_session_info_foreachcb(ur_map_key_type key, ur_map_value_type value, void *arg)
{
	UNUSED_ARG(value);

	int port = (int)key;
	struct tsi_arg *ta = (struct tsi_arg *)arg;
	if(port && ta && ta->tsi && ta->addr) {
		ioa_addr a;
		addr_cpy(&a,ta->addr);
		addr_set_port(&a,port);
		turn_session_info_add_peer(ta->tsi,&a);
	}
	return 0;
}

int turn_session_info_copy_from(struct turn_session_info* tsi, ts_ur_super_session *ss)
{
	int ret = -1;

	if(tsi && ss) {
		tsi->id = ss->id;
		tsi->bps = ss->bps;
		tsi->start_time = ss->start_time;
		tsi->valid = is_allocation_valid(&(ss->alloc)) && !(ss->to_be_closed) && (ss->quota_used);
		if(tsi->valid) {
			if(ss->alloc.relay_sessions[ALLOC_IPV4_INDEX].s) {
				tsi->expiration_time = ss->alloc.relay_sessions[ALLOC_IPV4_INDEX].expiration_time;
				if(ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].s) {
					if(turn_time_before(tsi->expiration_time,ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].expiration_time)) {
						tsi->expiration_time = ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].expiration_time;
					}
				}
			} else if(ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].s) {
				tsi->expiration_time = ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].expiration_time;
			}
			if(ss->client_socket) {
				tsi->client_protocol = get_ioa_socket_type(ss->client_socket);
				addr_cpy(&(tsi->local_addr_data.addr),get_local_addr_from_ioa_socket(ss->client_socket));
				addr_to_string(&(tsi->local_addr_data.addr),(u08bits*)tsi->local_addr_data.saddr);
				addr_cpy(&(tsi->remote_addr_data.addr),get_remote_addr_from_ioa_socket(ss->client_socket));
				addr_to_string(&(tsi->remote_addr_data.addr),(u08bits*)tsi->remote_addr_data.saddr);
			}
			{
				if(ss->alloc.relay_sessions[ALLOC_IPV4_INDEX].s) {
					tsi->peer_protocol = get_ioa_socket_type(ss->alloc.relay_sessions[ALLOC_IPV4_INDEX].s);
					if(ss->alloc.is_valid) {
						addr_cpy(&(tsi->relay_addr_data_ipv4.addr),get_local_addr_from_ioa_socket(ss->alloc.relay_sessions[ALLOC_IPV4_INDEX].s));
						addr_to_string(&(tsi->relay_addr_data_ipv4.addr),(u08bits*)tsi->relay_addr_data_ipv4.saddr);
					}
				}
				if(ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].s) {
					tsi->peer_protocol = get_ioa_socket_type(ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].s);
					if(ss->alloc.is_valid) {
						addr_cpy(&(tsi->relay_addr_data_ipv6.addr),get_local_addr_from_ioa_socket(ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].s));
						addr_to_string(&(tsi->relay_addr_data_ipv6.addr),(u08bits*)tsi->relay_addr_data_ipv6.saddr);
					}
				}
			}
			STRCPY(tsi->username,ss->username);
			tsi->enforce_fingerprints = ss->enforce_fingerprints;
			STRCPY(tsi->tls_method, get_ioa_socket_tls_method(ss->client_socket));
			STRCPY(tsi->tls_cipher, get_ioa_socket_tls_cipher(ss->client_socket));
			STRCPY(tsi->realm, ss->realm_options.name);
			STRCPY(tsi->origin, ss->origin);

			if(ss->t_received_packets > ss->received_packets)
				tsi->received_packets = ss->t_received_packets;
			else
				tsi->received_packets = ss->received_packets;

			if(ss->t_sent_packets > ss->sent_packets)
				tsi->sent_packets = ss->t_sent_packets;
			else
				tsi->sent_packets = ss->sent_packets;

			if(ss->t_received_bytes > ss->received_bytes)
				tsi->received_bytes = ss->t_received_bytes;
			else
				tsi->received_bytes = ss->received_bytes;

			if(ss->t_sent_bytes > ss->sent_bytes)
				tsi->sent_bytes = ss->t_sent_bytes;
			else
				tsi->sent_bytes = ss->sent_bytes;

			{
				tsi->received_rate = ss->received_rate;
				tsi->sent_rate = ss->sent_rate;
				tsi->total_rate = tsi->received_rate + tsi->sent_rate;
			}

			tsi->is_mobile = ss->is_mobile;

			{
				size_t i;
				for(i=0;i<TURN_PERMISSION_HASHTABLE_SIZE;++i) {

					turn_permission_array *parray = &(ss->alloc.addr_to_perm.table[i]);

					{
						size_t j;
						for(j=0;j<TURN_PERMISSION_ARRAY_SIZE;++j) {
							turn_permission_slot* slot = &(parray->main_slots[j]);
							if(slot->info.allocated) {
								turn_session_info_add_peer(tsi,&(slot->info.addr));
								struct tsi_arg arg = {
									tsi,
									&(slot->info.addr)
								};
								lm_map_foreach_arg(&(slot->info.chns), turn_session_info_foreachcb, &arg);
							}
						}
					}

					{
						turn_permission_slot **slots = parray->extra_slots;
						if(slots) {
							size_t sz = parray->extra_sz;
							size_t j;
							for(j=0;j<sz;++j) {
								turn_permission_slot* slot = slots[j];
								if(slot && slot->info.allocated) {
									turn_session_info_add_peer(tsi,&(slot->info.addr));
									struct tsi_arg arg = {
										tsi,
										&(slot->info.addr)
									};
									lm_map_foreach_arg(&(slot->info.chns), turn_session_info_foreachcb, &arg);
								}
							}
						}
					}
				}
			}

			{
				tcp_connection_list *tcl = &(ss->alloc.tcs);
				if(tcl->elems) {
					size_t i;
					size_t sz = tcl->sz;
					for(i=0;i<sz;++i) {
						if(tcl->elems[i]) {
							tcp_connection *tc = tcl->elems[i];
							if(tc) {
								turn_session_info_add_peer(tsi,&(tc->peer_addr));
							}
						}
					}
				}
			}
		}

		ret = 0;
	}

	return ret;
}

int report_turn_session_info(turn_turnserver *server, ts_ur_super_session *ss, int force_invalid)
{
	if(server && ss && server->send_turn_session_info) {
		struct turn_session_info tsi;
		turn_session_info_init(&tsi);
		if(turn_session_info_copy_from(&tsi,ss)<0) {
			turn_session_info_clean(&tsi);
		} else {
			if(force_invalid)
				tsi.valid = 0;
			if(server->send_turn_session_info(&tsi)<0) {
				turn_session_info_clean(&tsi);
			} else {
				return 0;
			}
		}
	}

	return -1;
}

/////////// SS /////////////////

static int mobile_id_to_string(mobile_id_t mid, char *dst, size_t dst_sz)
{
	size_t output_length = 0;

	if(!dst)
		return -1;

	char *s = base64_encode((const unsigned char *)&mid,
	                    sizeof(mid),
	                    &output_length);

	if(!s)
		return -1;

	if(!output_length || (output_length+1 > dst_sz)) {
		turn_free(s, output_length);
		return -1;
	}

	ns_bcopy(s, dst, output_length);

	turn_free(s, output_length);

	dst[output_length] = 0;

	return (int)output_length;
}

static mobile_id_t string_to_mobile_id(char* src)
{
	mobile_id_t mid = 0;

	if(src) {

		size_t output_length = 0;

		unsigned char *out = base64_decode(src, strlen(src), &output_length);

		if(out) {

			if(output_length == sizeof(mid)) {
				mid = *((mobile_id_t*)out);
			}

			turn_free(out, output_length);
		}
	}

	return mid;
}

static mobile_id_t get_new_mobile_id(turn_turnserver* server)
{
	mobile_id_t newid = 0;

	if(server && server->mobile_connections_map) {
		ur_map *map = server->mobile_connections_map;
		u64bits sid = server->id;
		sid = sid<<56;
		do {
			while (!newid) {
				if(TURN_RANDOM_SIZE == sizeof(mobile_id_t))
					newid = (mobile_id_t)turn_random();
				else {
					newid = (mobile_id_t)turn_random();
					newid = (newid<<32) + (mobile_id_t)turn_random();
				}
				if(!newid) {
					continue;
				}
				newid = newid & 0x00FFFFFFFFFFFFFFLL;
				if(!newid) {
					continue;
				}
				newid = newid | sid;
			}
		} while(ur_map_get(map, (ur_map_key_type)newid, NULL));
	}
	return newid;
}

static void put_session_into_mobile_map(ts_ur_super_session *ss)
{
	if(ss && ss->server) {
		turn_turnserver* server = (turn_turnserver*)(ss->server);
		if(*(server->mobility) && server->mobile_connections_map) {
			if(!(ss->mobile_id)) {
				ss->mobile_id = get_new_mobile_id(server);
				mobile_id_to_string(ss->mobile_id, ss->s_mobile_id, sizeof(ss->s_mobile_id));
			}
			ur_map_put(server->mobile_connections_map, (ur_map_key_type)(ss->mobile_id), (ur_map_value_type)ss);
		}
	}

}

static void put_session_into_map(ts_ur_super_session *ss)
{
	if(ss && ss->server) {
		turn_turnserver* server = (turn_turnserver*)(ss->server);
		if(!(ss->id)) {
			ss->id = (turnsession_id)((turnsession_id)server->id * TURN_SESSION_ID_FACTOR);
			ss->id += ++(server->session_id_counter);
			ss->start_time = server->ctime;
		}
		ur_map_put(server->sessions_map, (ur_map_key_type)(ss->id), (ur_map_value_type)ss);
		put_session_into_mobile_map(ss);
	}
}

static void delete_session_from_mobile_map(ts_ur_super_session *ss)
{
	if(ss && ss->server && ss->mobile_id) {
		turn_turnserver* server = (turn_turnserver*)(ss->server);
		if(server->mobile_connections_map) {
			ur_map_del(server->mobile_connections_map, (ur_map_key_type)(ss->mobile_id), NULL);
		}
		ss->mobile_id = 0;
		ss->s_mobile_id[0] = 0;
	}
}

static void delete_session_from_map(ts_ur_super_session *ss)
{
	if(ss && ss->server) {
		turn_turnserver* server = (turn_turnserver*)(ss->server);
		ur_map_del(server->sessions_map, (ur_map_key_type)(ss->id), NULL);
		delete_session_from_mobile_map(ss);
	}
}

static ts_ur_super_session* get_session_from_map(turn_turnserver* server, turnsession_id sid)
{
	ts_ur_super_session *ss = NULL;
	if(server) {
		ur_map_value_type value = 0;
		if(ur_map_get(server->sessions_map, (ur_map_key_type)sid, &value) && value) {
			ss = (ts_ur_super_session*)value;
		}
	}
	return ss;
}

void turn_cancel_session(turn_turnserver *server, turnsession_id sid)
{
	if(server) {
		ts_ur_super_session* ts = get_session_from_map(server, sid);
		if(ts) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Session %018llu to be forcefully canceled\n",(unsigned long long)sid);
			shutdown_client_connection(server, ts, 0, "Forceful shutdown");
		}
	}
}

static ts_ur_super_session* get_session_from_mobile_map(turn_turnserver* server, mobile_id_t mid)
{
	ts_ur_super_session *ss = NULL;
	if(server && *(server->mobility) && server->mobile_connections_map && mid) {
		ur_map_value_type value = 0;
		if(ur_map_get(server->mobile_connections_map, (ur_map_key_type)mid, &value) && value) {
			ss = (ts_ur_super_session*)value;
		}
	}
	return ss;
}

static ts_ur_super_session* create_new_ss(turn_turnserver* server) {
	//
	//printf("%s: 111.111: session size=%lu\n",__FUNCTION__,(unsigned long)sizeof(ts_ur_super_session));
	//
	ts_ur_super_session *ss = (ts_ur_super_session*)turn_malloc(sizeof(ts_ur_super_session));
	ns_bzero(ss,sizeof(ts_ur_super_session));
	ss->server = server;
	get_default_realm_options(&(ss->realm_options));
	put_session_into_map(ss);
	init_allocation(ss,&(ss->alloc), server->tcp_relay_connections);
	return ss;
}

static void delete_ur_map_ss(void *p) {
	if (p) {
		ts_ur_super_session* ss = (ts_ur_super_session*) p;
		delete_session_from_map(ss);
		IOA_CLOSE_SOCKET(ss->client_socket);
		clear_allocation(get_allocation_ss(ss));
		IOA_EVENT_DEL(ss->to_be_allocated_timeout_ev);
		turn_free(p,sizeof(ts_ur_super_session));
	}
}

/////////// clean all /////////////////////

static int turn_server_remove_all_from_ur_map_ss(ts_ur_super_session* ss) {
	if (!ss)
		return 0;
	else {
		int ret = 0;
		if (ss->client_socket) {
			clear_ioa_socket_session_if(ss->client_socket, ss);
		}
		if (get_relay_socket_ss(ss,AF_INET)) {
			clear_ioa_socket_session_if(get_relay_socket_ss(ss,AF_INET), ss);
		}
		if (get_relay_socket_ss(ss,AF_INET6)) {
			clear_ioa_socket_session_if(get_relay_socket_ss(ss,AF_INET6), ss);
		}
		delete_ur_map_ss(ss);
		return ret;
	}
}

/////////////////////////////////////////////////////////////////

static void client_ss_channel_timeout_handler(ioa_engine_handle e, void* arg) {

	UNUSED_ARG(e);

	if (!arg)
		return;

	ch_info* chn = (ch_info*) arg;

	turn_channel_delete(chn);
}

static void client_ss_perm_timeout_handler(ioa_engine_handle e, void* arg) {

	UNUSED_ARG(e);

	if (!arg) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s: empty permission to be cleaned\n",__FUNCTION__);
		return;
	}

	turn_permission_info* tinfo = (turn_permission_info*) arg;

	if(!(tinfo->allocated)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s: unallocated permission to be cleaned\n",__FUNCTION__);
		return;
	}

	if(!(tinfo->lifetime_ev)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s: strange (1) permission to be cleaned\n",__FUNCTION__);
	}

	if(!(tinfo->owner)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s: strange (2) permission to be cleaned\n",__FUNCTION__);
	}

	turn_permission_clean(tinfo);
}

///////////////////////////////////////////////////////////////////

static int update_turn_permission_lifetime(ts_ur_super_session *ss, turn_permission_info *tinfo, turn_time_t time_delta) {

	if (ss && tinfo && tinfo->owner) {

		turn_turnserver *server = (turn_turnserver *) (ss->server);

		if (server) {

			if(!time_delta) time_delta = STUN_PERMISSION_LIFETIME;
			tinfo->expiration_time = server->ctime + time_delta;

			IOA_EVENT_DEL(tinfo->lifetime_ev);
			tinfo->lifetime_ev = set_ioa_timer(server->e, time_delta, 0,
							client_ss_perm_timeout_handler, tinfo, 0,
							"client_ss_channel_timeout_handler");

			if(server->verbose) {
				tinfo->verbose = 1;
				tinfo->session_id = ss->id;
				char s[257]="\0";
				addr_to_string(&(tinfo->addr),(u08bits*)s);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "session %018llu: peer %s lifetime updated: %lu\n",(unsigned long long)ss->id,s,(unsigned long)time_delta);
			}

			return 0;
		}
	}
	return -1;
}

static int update_channel_lifetime(ts_ur_super_session *ss, ch_info* chn)
{

	if (chn) {

		turn_permission_info* tinfo = (turn_permission_info*) (chn->owner);

		if (tinfo && tinfo->owner) {

			turn_turnserver *server = (turn_turnserver *) (ss->server);

			if (server) {

				if (update_turn_permission_lifetime(ss, tinfo, STUN_CHANNEL_LIFETIME) < 0)
					return -1;

				chn->expiration_time = server->ctime + STUN_CHANNEL_LIFETIME;

				IOA_EVENT_DEL(chn->lifetime_ev);
				chn->lifetime_ev = set_ioa_timer(server->e, STUN_CHANNEL_LIFETIME, 0,
								client_ss_channel_timeout_handler,
								chn, 0,
								"client_ss_channel_timeout_handler");

				return 0;
			}
		}
	}
	return -1;
}

/////////////// TURN ///////////////////////////

#define SKIP_ATTRIBUTES case STUN_ATTRIBUTE_OAUTH_ACCESS_TOKEN: case STUN_ATTRIBUTE_PRIORITY: case STUN_ATTRIBUTE_FINGERPRINT: case STUN_ATTRIBUTE_MESSAGE_INTEGRITY: break; \
	case STUN_ATTRIBUTE_USERNAME: case STUN_ATTRIBUTE_REALM: case STUN_ATTRIBUTE_NONCE: case STUN_ATTRIBUTE_ORIGIN: \
	sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),\
		ioa_network_buffer_get_size(in_buffer->nbh), sar); \
	continue

static u08bits get_transport_value(const u08bits *value) {
	if((value[0] == STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE)||
	   (value[0] == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE)) {
		return value[0];
	}
	return 0;
}

static int handle_turn_allocate(turn_turnserver *server,
				ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				int *err_code, 	const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
				ioa_net_data *in_buffer, ioa_network_buffer_handle nbh) {


	int err_code4 = 0;
	int err_code6 = 0;

	allocation* alloc = get_allocation_ss(ss);

	if (is_allocation_valid(alloc)) {

		if (!stun_tid_equals(tid, &(alloc->tid))) {
			*err_code = 437;
			*reason = (const u08bits *)"Wrong TID";
		} else {
			size_t len = ioa_network_buffer_get_size(nbh);
			ioa_addr xor_relayed_addr1, *pxor_relayed_addr1=NULL;
			ioa_addr xor_relayed_addr2, *pxor_relayed_addr2=NULL;
			ioa_addr *relayed_addr1 = get_local_addr_from_ioa_socket(get_relay_socket_ss(ss,AF_INET));
			ioa_addr *relayed_addr2 = get_local_addr_from_ioa_socket(get_relay_socket_ss(ss,AF_INET6));

			if(get_relay_session_failure(alloc,AF_INET)) {
				addr_set_any(&xor_relayed_addr1);
				pxor_relayed_addr1 = &xor_relayed_addr1;
			} else if(relayed_addr1) {
				if(server->external_ip_set) {
					addr_cpy(&xor_relayed_addr1, &(server->external_ip));
					addr_set_port(&xor_relayed_addr1,addr_get_port(relayed_addr1));
				} else {
					addr_cpy(&xor_relayed_addr1, relayed_addr1);
				}
				pxor_relayed_addr1 = &xor_relayed_addr1;
			}

			if(get_relay_session_failure(alloc,AF_INET6)) {
				addr_set_any(&xor_relayed_addr2);
				pxor_relayed_addr2 = &xor_relayed_addr2;
			} else if(relayed_addr2) {
				if(server->external_ip_set) {
					addr_cpy(&xor_relayed_addr2, &(server->external_ip));
					addr_set_port(&xor_relayed_addr2,addr_get_port(relayed_addr2));
				} else {
					addr_cpy(&xor_relayed_addr2, relayed_addr2);
				}
				pxor_relayed_addr2 = &xor_relayed_addr2;
			}

			if(pxor_relayed_addr1 || pxor_relayed_addr2) {
				u32bits lifetime = 0;
				if(pxor_relayed_addr1) {
					lifetime = (get_relay_session(alloc,pxor_relayed_addr1->ss.sa_family)->expiration_time - server->ctime);
				} else if(pxor_relayed_addr2) {
					lifetime = (get_relay_session(alloc,pxor_relayed_addr2->ss.sa_family)->expiration_time - server->ctime);
				}
				stun_set_allocate_response_str(ioa_network_buffer_data(nbh), &len,
							tid,
							pxor_relayed_addr1, pxor_relayed_addr2,
							get_remote_addr_from_ioa_socket(ss->client_socket),
							lifetime, 0, NULL, 0,
							ss->s_mobile_id);
				ioa_network_buffer_set_size(nbh,len);
				*resp_constructed = 1;
			}
		}

	} else {

		u08bits transport = 0;
		turn_time_t lifetime = 0;
		int even_port = -1;
		int dont_fragment = 0;
		u64bits in_reservation_token = 0;
		int af4 = 0;
		int af6 = 0;
		u08bits username[STUN_MAX_USERNAME_SIZE+1]="\0";
		size_t ulen = 0;
		band_limit_t bps = 0;
		band_limit_t max_bps = 0;

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {

			int attr_type = stun_attr_get_type(sar);

			if(attr_type == STUN_ATTRIBUTE_USERNAME) {
				const u08bits* value = stun_attr_get_value(sar);
				if (value) {
					ulen = stun_attr_get_len(sar);
					if(ulen>=sizeof(username)) {
						*err_code = 400;
						*reason = (const u08bits *)"User name is too long";
						break;
					}
					ns_bcopy(value,username,ulen);
					username[ulen]=0;
					if(!is_secure_username(username)) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: wrong username: %s\n", __FUNCTION__, (char*)username);
						username[0]=0;
						*err_code = 400;
						break;
					}
				}
			}

			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_NEW_BANDWIDTH:
				bps = stun_attr_get_bandwidth(sar);
				break;
			case STUN_ATTRIBUTE_MOBILITY_TICKET:
				if(!(*(server->mobility))) {
					*err_code = 405;
					*reason = (const u08bits *)"Mobility Forbidden";
				} else if (stun_attr_get_len(sar) != 0) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong Mobility Field";
				} else {
					ss->is_mobile = 1;
				}
				break;
			case STUN_ATTRIBUTE_REQUESTED_TRANSPORT: {
				if (stun_attr_get_len(sar) != 4) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong Transport Field";
				} else if(transport) {
					*err_code = 400;
					*reason = (const u08bits *)"Duplicate Transport Fields";
				} else {
					const u08bits* value = stun_attr_get_value(sar);
					if (value) {
						transport = get_transport_value(value);
						if (!transport) {
							*err_code = 442;
						}
						if((transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE) && *(server->no_tcp_relay)) {
							*err_code = 442;
							*reason = (const u08bits *)"TCP Transport is not allowed by the TURN Server configuration";
						} else if((transport == STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE) && *(server->no_udp_relay)) {
							*err_code = 442;
							*reason = (const u08bits *)"UDP Transport is not allowed by the TURN Server configuration";
						} else if(ss->client_socket) {
							SOCKET_TYPE cst = get_ioa_socket_type(ss->client_socket);
							if((transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE) && !is_stream_socket(cst)) {
								*err_code = 400;
								*reason = (const u08bits *)"Wrong Transport Data";
							} else {
								ss->is_tcp_relay = (transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE);
							}
						}
					} else {
						*err_code = 400;
						*reason = (const u08bits *)"Wrong Transport Data";
					}
				}
			}
				break;
			case STUN_ATTRIBUTE_DONT_FRAGMENT:
				dont_fragment = 1;
				if(!(server->dont_fragment))
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
				break;
			case STUN_ATTRIBUTE_LIFETIME: {
			  if (stun_attr_get_len(sar) != 4) {
			    *err_code = 400;
			    *reason = (const u08bits *)"Wrong Lifetime Field";
			  } else {
			    const u08bits* value = stun_attr_get_value(sar);
			    if (!value) {
			      *err_code = 400;
			      *reason = (const u08bits *)"Wrong Lifetime Data";
			    } else {
			      lifetime = nswap32(*((const u32bits*)value));
			    }
			  }
			}
			  break;
			case STUN_ATTRIBUTE_EVEN_PORT: {
			  if (in_reservation_token) {
			    *err_code = 400;
			    *reason = (const u08bits *)"Even Port and Reservation Token cannot be used together";
			  } else {
			    even_port = stun_attr_get_even_port(sar);
			    if(even_port) {
			    	if (af4 && af6) {
			    		*err_code = 400;
			    		*reason = (const u08bits *)"Even Port cannot be used with Dual Allocation";
			    	}
			    }
			  }
			}
			  break;
			case STUN_ATTRIBUTE_RESERVATION_TOKEN: {
			  int len = stun_attr_get_len(sar);
			  if (len != 8) {
			    *err_code = 400;
			    *reason = (const u08bits *)"Wrong Format of Reservation Token";
			  } else if(af4 || af6) {
				  *err_code = 400;
				  *reason = (const u08bits *)"Address family attribute can not be used with reservation token request";
			  } else {
			    if (even_port >= 0) {
			      *err_code = 400;
			      *reason = (const u08bits *)"Reservation Token cannot be used in this request with even port";
			    } else if (in_reservation_token) {
			      *err_code = 400;
			      *reason = (const u08bits *)"Reservation Token cannot be used in this request";
			    } else {
			      in_reservation_token = stun_attr_get_reservation_token_value(sar);
			    }
			  }
			}
			  break;
			case STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY:
				if(even_port>0) {
					*err_code = 400;
					*reason = (const u08bits *)"Even Port cannot be used with Dual Allocation";
					break;
				}
			case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY: {
				if(in_reservation_token) {
					*err_code = 400;
					*reason = (const u08bits *)"Address family attribute can not be used with reservation token request";
				} else if(af4 || af6) {
					*err_code = 400;
					*reason = (const u08bits *)"Extra address family attribute can not be used in the request";
				} else {
					int af_req = stun_get_requested_address_family(sar);
					switch (af_req) {
					case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
						if(attr_type == STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY) {
							*err_code = 400;
							*reason = (const u08bits *)"Invalid value of the additional address family attribute";
						} else {
							af4 = af_req;
						}
						break;
					case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
						if(attr_type == STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY) {
							af4 = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4;
						}
						af6 = af_req;
						break;
					default:
						*err_code = 440;
					}
				}
			}
			  break;
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), 
						     ioa_network_buffer_get_size(in_buffer->nbh), 
						     sar);
		}

		if (!transport) {

		  *err_code = 400;
		  if(!(*reason))
		    *reason = (const u08bits *)"Transport field missed or wrong";
		  
		} else if (*ua_num > 0) {

		  *err_code = 420;

		} else if (*err_code) {

			;

		} else if((transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE) && (dont_fragment || in_reservation_token || (even_port!=-1))) {

			*err_code = 400;
			if(!(*reason))
			    *reason = (const u08bits *)"Request parameters are incompatible with TCP transport";

		} else {

			if(*(server->mobility)) {
				if(!(ss->is_mobile)) {
					delete_session_from_mobile_map(ss);
				}
			}

			lifetime = stun_adjust_allocate_lifetime(lifetime, ss->max_session_time_auth);
			u64bits out_reservation_token = 0;

			if(inc_quota(ss, username)<0) {

				*err_code = 486;

			} else {

				if(server->allocate_bps_func) {
					max_bps = ss->realm_options.perf_options.max_bps;
					if(max_bps && (!bps || (bps && (bps>max_bps)))) {
						bps = max_bps;
					}
					if(bps && (ss->bps == 0)) {
						ss->bps = server->allocate_bps_func(bps,1);
						if(!(ss->bps)) {
							*err_code = 486;
							*reason = (const u08bits *)"Allocation Bandwidth Quota Reached";
						}
					}
				}

				if(af4) af4 = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4;
				if(af6) af6 = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;

				if(af4 && af6) {
					if(server->external_ip_set) {
						*err_code = 440;
						*reason = (const u08bits *)"Dual allocation cannot be supported in the current server configuration";
					}
					if(even_port > 0) {
						*err_code = 440;
						*reason = (const u08bits *)"Dual allocation cannot be supported with even-port functionality";
					}
				}

				if(!(*err_code)) {
					if(!af4 && !af6) {
						int af4res = create_relay_connection(server, ss, lifetime,
							STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT, transport,
							even_port, in_reservation_token, &out_reservation_token,
							err_code, reason,
							tcp_peer_accept_connection);
						if(af4res<0) {
							set_relay_session_failure(alloc,AF_INET);
							if(!(*err_code)) {
								*err_code = 437;
							}
						}
					} else if(!af4 && af6) {
						int af6res = create_relay_connection(server, ss, lifetime,
							af6, transport,
							even_port, in_reservation_token, &out_reservation_token,
							err_code, reason,
							tcp_peer_accept_connection);
						if(af6res<0) {
							set_relay_session_failure(alloc,AF_INET6);
							if(!(*err_code)) {
								*err_code = 437;
							}
						}
					} else if(af4 && !af6) {
						int af4res = create_relay_connection(server, ss, lifetime,
							af4, transport,
							even_port, in_reservation_token, &out_reservation_token,
							err_code, reason,
							tcp_peer_accept_connection);
						if(af4res<0) {
							set_relay_session_failure(alloc,AF_INET);
							if(!(*err_code)) {
								*err_code = 437;
							}
						}
					} else {
						const u08bits *reason4 = NULL;
						const u08bits *reason6 = NULL;
						{
							int af4res = create_relay_connection(server, ss, lifetime,
									af4, transport,
									even_port, in_reservation_token, &out_reservation_token,
									&err_code4, &reason4,
									tcp_peer_accept_connection);
							if(af4res<0) {
								set_relay_session_failure(alloc,AF_INET);
								if(!err_code4) {
									err_code4 = 440;
								}
							}
						}
						{
							int af6res = create_relay_connection(server, ss, lifetime,
												af6, transport,
												even_port, in_reservation_token, &out_reservation_token,
												&err_code6, &reason6,
												tcp_peer_accept_connection);
							if(af6res<0) {
								set_relay_session_failure(alloc,AF_INET6);
								if(!err_code6) {
									err_code6 = 440;
								}
							}
						}

						if(err_code4 && err_code6) {
							if(reason4) {
								*err_code = err_code4;
								*reason = reason4;
							} else if(reason6) {
								*err_code = err_code6;
								*reason = reason6;
							} else {
								*err_code = err_code4;
							}
						}
					}
				}

				if (*err_code) {

					if(!(*reason)) {
						*reason = (const u08bits *)"Cannot create relay endpoint(s)";
					}

				} else {

					set_allocation_valid(alloc,1);

					stun_tid_cpy(&(alloc->tid), tid);

					size_t len = ioa_network_buffer_get_size(nbh);

					ioa_addr xor_relayed_addr1, *pxor_relayed_addr1=NULL;
					ioa_addr xor_relayed_addr2, *pxor_relayed_addr2=NULL;
					ioa_addr *relayed_addr1 = get_local_addr_from_ioa_socket(get_relay_socket_ss(ss,AF_INET));
					ioa_addr *relayed_addr2 = get_local_addr_from_ioa_socket(get_relay_socket_ss(ss,AF_INET6));

					if(get_relay_session_failure(alloc,AF_INET)) {
						addr_set_any(&xor_relayed_addr1);
						pxor_relayed_addr1 = &xor_relayed_addr1;
					} else if(relayed_addr1) {
						if(server->external_ip_set) {
							addr_cpy(&xor_relayed_addr1, &(server->external_ip));
							addr_set_port(&xor_relayed_addr1,addr_get_port(relayed_addr1));
						} else {
							addr_cpy(&xor_relayed_addr1, relayed_addr1);
						}
						pxor_relayed_addr1 = &xor_relayed_addr1;
					}

					if(get_relay_session_failure(alloc,AF_INET6)) {
						addr_set_any(&xor_relayed_addr2);
						pxor_relayed_addr2 = &xor_relayed_addr2;
					} else if(relayed_addr2) {
						if(server->external_ip_set) {
							addr_cpy(&xor_relayed_addr2, &(server->external_ip));
							addr_set_port(&xor_relayed_addr2,addr_get_port(relayed_addr2));
						} else {
							addr_cpy(&xor_relayed_addr2, relayed_addr2);
						}
						pxor_relayed_addr2 = &xor_relayed_addr2;
					}

					if(pxor_relayed_addr1 || pxor_relayed_addr2) {

						stun_set_allocate_response_str(ioa_network_buffer_data(nbh), &len, tid,
									pxor_relayed_addr1, pxor_relayed_addr2,
									get_remote_addr_from_ioa_socket(ss->client_socket), lifetime,
									0,NULL,
									out_reservation_token,
									ss->s_mobile_id);

						if(ss->bps) {
							stun_attr_add_bandwidth_str(ioa_network_buffer_data(nbh), &len, ss->bps);
						}

						ioa_network_buffer_set_size(nbh,len);
						*resp_constructed = 1;

						turn_report_allocation_set(&(ss->alloc), lifetime, 0);
					}
				}
			}
		}
	}

	if (!(*resp_constructed)) {

		if (!(*err_code)) {
			*err_code = 437;
		}

		size_t len = ioa_network_buffer_get_size(nbh);
		stun_set_allocate_response_str(ioa_network_buffer_data(nbh), &len, tid, NULL, NULL, NULL, 0, *err_code, *reason, 0, ss->s_mobile_id);
		ioa_network_buffer_set_size(nbh,len);
		*resp_constructed = 1;
	}

	if(*resp_constructed && !(*err_code)) {
		if(err_code4) {
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_address_error_code(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4, err_code4);
			ioa_network_buffer_set_size(nbh,len);
		}
		if(err_code6) {
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_address_error_code(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6, err_code6);
			ioa_network_buffer_set_size(nbh,len);
		}
	}

	return 0;
}

static void copy_auth_parameters(ts_ur_super_session *orig_ss, ts_ur_super_session *ss) {
	if(orig_ss && ss) {
		dec_quota(ss);
		ns_bcopy(orig_ss->nonce,ss->nonce,sizeof(ss->nonce));
		ss->nonce_expiration_time = orig_ss->nonce_expiration_time;
		ns_bcopy(&(orig_ss->realm_options),&(ss->realm_options),sizeof(ss->realm_options));
		ns_bcopy(orig_ss->username,ss->username,sizeof(ss->username));
		ss->hmackey_set = orig_ss->hmackey_set;
		ns_bcopy(orig_ss->hmackey,ss->hmackey,sizeof(ss->hmackey));
		ss->oauth = orig_ss->oauth;
		ns_bcopy(orig_ss->origin,ss->origin,sizeof(ss->origin));
		ss->origin_set = orig_ss->origin_set;
		ns_bcopy(orig_ss->pwd,ss->pwd,sizeof(ss->pwd));
		ss->max_session_time_auth = orig_ss->max_session_time_auth;
		inc_quota(ss,ss->username);
	}
}

static int handle_turn_refresh(turn_turnserver *server,
			       ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
			       int *err_code, 	const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
			       ioa_net_data *in_buffer, ioa_network_buffer_handle nbh,
			       int message_integrity, int *no_response, int can_resume) {

	allocation* a = get_allocation_ss(ss);
	int af4c = 0;
	int af6c = 0;
	int af4 = 0;
	int af6 = 0;
	{
		int i;
		for(i = 0;i<ALLOC_PROTOCOLS_NUMBER; ++i) {
			if(a->relay_sessions[i].s && !ioa_socket_tobeclosed(a->relay_sessions[i].s)) {
				int family = get_ioa_socket_address_family(a->relay_sessions[i].s);
				if(AF_INET == family) {
					af4c = 1;
				} else if(AF_INET6 == family) {
					af6c = 1;
				}
			}
		}
	}

	if (!is_allocation_valid(a) && !(*(server->mobility))) {

		*err_code = 437;
		*reason = (const u08bits *)"Invalid allocation";

	} else {

		turn_time_t lifetime = 0;
		int to_delete = 0;
		mobile_id_t mid = 0;
		char smid[sizeof(ss->s_mobile_id)] = "\0";

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_MOBILITY_TICKET: {
				if(!(*(server->mobility))) {
					*err_code = 405;
					*reason = (const u08bits *)"Mobility forbidden";
				} else {
					int smid_len = stun_attr_get_len(sar);
					if(smid_len>0 && (((size_t)smid_len)<sizeof(smid))) {
						const u08bits* smid_val = stun_attr_get_value(sar);
						if(smid_val) {
							ns_bcopy(smid_val, smid, (size_t)smid_len);
							mid = string_to_mobile_id(smid);
							if(is_allocation_valid(a) && (mid != ss->old_mobile_id)) {
								*err_code = 400;
								*reason = (const u08bits *)"Mobility ticket cannot be used for a stable, already established allocation";
							}
						}
					} else {
						*err_code = 400;
						*reason = (const u08bits *)"Mobility ticket has wrong length";
					}
				}
			}
				break;
			case STUN_ATTRIBUTE_LIFETIME: {
				if (stun_attr_get_len(sar) != 4) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong Lifetime field format";
				} else {
					const u08bits* value = stun_attr_get_value(sar);
					if (!value) {
						*err_code = 400;
						*reason = (const u08bits *)"Wrong lifetime field data";
					} else {
						lifetime = nswap32(*((const u32bits*)value));
						if (!lifetime)
							to_delete = 1;
					}
				}
			}
				break;
			case STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY: /* deprecated, for backward compatibility with older versions of TURN-bis */
			case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY: {
				int af_req = stun_get_requested_address_family(sar);
				{
					int is_err = 0;
					switch (af_req) {
					case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
						if(!af4c) {
							is_err = 1;
						} else {
							af4 = 1;
						}
						break;
					case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
						if(!af6c) {
							is_err = 1;
						} else {
							af6 = 1;
						}
						break;
					default:
						is_err = 1;
					}

					if(is_err) {
						*err_code = 443;
						*reason = (const u08bits *)"Peer Address Family Mismatch (1)";
					}
				}
			}
				break;
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), 
						     ioa_network_buffer_get_size(in_buffer->nbh), sar);
		}

		if (*ua_num > 0) {

			*err_code = 420;

		} else if (*err_code) {

			;

		} else if(!is_allocation_valid(a)) {

			if(mid && smid[0]) {

				turnserver_id tsid = ((0xFF00000000000000LL) & mid)>>56;

				if(tsid != server->id) {

					if(server->send_socket_to_relay) {
						ioa_socket_handle new_s = detach_ioa_socket(ss->client_socket);
						if(new_s) {
						  if(server->send_socket_to_relay(tsid, mid, tid, new_s, message_integrity, 
										  RMT_MOBILE_SOCKET, in_buffer, can_resume)<0) {
						    *err_code = 400;
						    *reason = (const u08bits *)"Wrong mobile ticket";
						  } else {
						    *no_response = 1;
						  }
						} else {
							*err_code = 500;
							*reason = (const u08bits *)"Cannot create new socket";
							return -1;
						}
					} else {
						*err_code = 500;
						*reason = (const u08bits *)"Server send socket procedure is not set";
					}

					ss->to_be_closed = 1;

				} else {

					ts_ur_super_session *orig_ss = get_session_from_mobile_map(server, mid);
					if(!orig_ss || orig_ss->to_be_closed || ioa_socket_tobeclosed(orig_ss->client_socket)) {
						*err_code = 404;
						*reason = (const u08bits *)"Allocation not found";
					} else if(orig_ss == ss) {
						*err_code = 437;
						*reason = (const u08bits *)"Invalid allocation";
					} else if(!(orig_ss->is_mobile)) {
						*err_code = 500;
						*reason = (const u08bits *)"Software error: invalid mobile allocation";
					} else if(orig_ss->client_socket == ss->client_socket) {
						*err_code = 500;
						*reason = (const u08bits *)"Software error: invalid mobile client socket (orig)";
					} else if(!(ss->client_socket)) {
						*err_code = 500;
						*reason = (const u08bits *)"Software error: invalid mobile client socket (new)";
					} else {

						get_realm_options_by_name(orig_ss->realm_options.name, &(ss->realm_options));

						//Check security:
						int postpone_reply = 0;

						if(!(ss->hmackey_set)) {
							copy_auth_parameters(orig_ss,ss);
						}

						if(check_stun_auth(server, ss, tid, resp_constructed, err_code, reason, in_buffer, nbh,
								STUN_METHOD_REFRESH, &message_integrity, &postpone_reply, can_resume)<0) {
							if(!(*err_code)) {
								*err_code = 401;
							}
						}

						if(postpone_reply) {

							*no_response = 1;

						} else if(!(*err_code)) {

							//Session transfer:

							if (to_delete)
								lifetime = 0;
							else {
								lifetime = stun_adjust_allocate_lifetime(lifetime, ss->max_session_time_auth);
							}

							if (af4c && refresh_relay_connection(server, orig_ss, lifetime, 0, 0, 0,
										err_code, AF_INET) < 0) {

								if (!(*err_code)) {
									*err_code = 437;
									*reason = (const u08bits *)"Cannot refresh relay connection (internal error)";
								}

							} else if (af6c && refresh_relay_connection(server, orig_ss, lifetime, 0, 0, 0,
										err_code, AF_INET6) < 0) {

								if (!(*err_code)) {
									*err_code = 437;
									*reason = (const u08bits *)"Cannot refresh relay connection (internal error)";
								}

							} else {

								//Transfer socket:

								ioa_socket_handle s = detach_ioa_socket(ss->client_socket);

								ss->to_be_closed = 1;

								if(!s) {
									*err_code = 500;
								} else {

									if(attach_socket_to_session(server, s, orig_ss) < 0) {
										if(orig_ss->client_socket != s) {
											IOA_CLOSE_SOCKET(s);
										}
										*err_code = 500;
									} else {

										if(ss->hmackey_set) {
											copy_auth_parameters(ss,orig_ss);
										}

										delete_session_from_mobile_map(ss);
										delete_session_from_mobile_map(orig_ss);
										put_session_into_mobile_map(orig_ss);

										//Use new buffer and redefine ss:
										nbh = ioa_network_buffer_allocate(server->e);

										dec_quota(ss);
										ss = orig_ss;
										inc_quota(ss,ss->username);

										ss->old_mobile_id = mid;
										size_t len = ioa_network_buffer_get_size(nbh);

										turn_report_allocation_set(&(ss->alloc), lifetime, 1);

										stun_init_success_response_str(STUN_METHOD_REFRESH, ioa_network_buffer_data(nbh), &len, tid);
										u32bits lt = nswap32(lifetime);

										stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_LIFETIME,
												(const u08bits*) &lt, 4);
										ioa_network_buffer_set_size(nbh,len);

										stun_attr_add_str(ioa_network_buffer_data(nbh), &len,
											STUN_ATTRIBUTE_MOBILITY_TICKET,
											(u08bits*)ss->s_mobile_id,strlen(ss->s_mobile_id));
										ioa_network_buffer_set_size(nbh,len);

										{
											static const u08bits *field = (const u08bits *) TURN_SOFTWARE;
											static const size_t fsz = sizeof(TURN_SOFTWARE)-1;
											size_t len = ioa_network_buffer_get_size(nbh);
											stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
											ioa_network_buffer_set_size(nbh, len);
										}

										if(message_integrity) {
											stun_attr_add_integrity_str(server->ct,ioa_network_buffer_data(nbh),&len,ss->hmackey,ss->pwd,SHATYPE_DEFAULT);
											ioa_network_buffer_set_size(nbh,len);
										}

										if ((server->fingerprint) || ss->enforce_fingerprints) {
											if (stun_attr_add_fingerprint_str(ioa_network_buffer_data(nbh), &len) < 0) {
												*err_code = 500;
												ioa_network_buffer_delete(server->e, nbh);
												return -1;
											}
											ioa_network_buffer_set_size(nbh, len);
										}

										*no_response = 1;

										return write_client_connection(server, ss, nbh, TTL_IGNORE, TOS_IGNORE);
									}
								}
							}
						}

						report_turn_session_info(server,orig_ss,0);
					}
				}
			} else {
				*err_code = 437;
				*reason = (const u08bits *)"Invalid allocation";
			}

		} else {

			if (to_delete)
				lifetime = 0;
			else {
				lifetime = stun_adjust_allocate_lifetime(lifetime, ss->max_session_time_auth);
			}

			if(!af4 && !af6) {
				af4 = af4c;
				af6 = af6c;
			}

			if (af4 && refresh_relay_connection(server, ss, lifetime, 0, 0, 0,
					err_code, AF_INET) < 0) {

				if (!(*err_code)) {
					*err_code = 437;
					*reason = (const u08bits *)"Cannot refresh relay connection (internal error)";
				}

			} else if (af6 && refresh_relay_connection(server, ss, lifetime, 0, 0, 0,
					err_code, AF_INET6) < 0) {

				if (!(*err_code)) {
					*err_code = 437;
					*reason = (const u08bits *)"Cannot refresh relay connection (internal error)";
				}

			} else {

				turn_report_allocation_set(&(ss->alloc), lifetime, 1);

				size_t len = ioa_network_buffer_get_size(nbh);
				stun_init_success_response_str(STUN_METHOD_REFRESH, ioa_network_buffer_data(nbh), &len, tid);

				if(ss->s_mobile_id[0]) {
					stun_attr_add_str(ioa_network_buffer_data(nbh), &len,
									STUN_ATTRIBUTE_MOBILITY_TICKET,
									(u08bits*)ss->s_mobile_id,strlen(ss->s_mobile_id));
					ioa_network_buffer_set_size(nbh,len);
				}

				u32bits lt = nswap32(lifetime);
				stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_LIFETIME,
						(const u08bits*) &lt, 4);

				ioa_network_buffer_set_size(nbh,len);

				*resp_constructed = 1;
			}
		}
	}

	if(!no_response) {
		if (!(*resp_constructed)) {

			if (!(*err_code)) {
				*err_code = 437;
			}

			size_t len = ioa_network_buffer_get_size(nbh);
			stun_init_error_response_str(STUN_METHOD_REFRESH, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
			ioa_network_buffer_set_size(nbh,len);

			*resp_constructed = 1;
		}
	}

	return 0;
}

/* RFC 6062 ==>> */

static void tcp_deliver_delayed_buffer(unsent_buffer *ub, ioa_socket_handle s, ts_ur_super_session *ss)
{
	if(ub && s && ub->bufs && ub->sz && ss) {
		size_t i = 0;
		do {
			ioa_network_buffer_handle nbh = top_unsent_buffer(ub);
			if(!nbh)
				break;

			u32bits bytes = (u32bits)ioa_network_buffer_get_size(nbh);

			int ret = send_data_from_ioa_socket_nbh(s, NULL, nbh, TTL_IGNORE, TOS_IGNORE, NULL);
			if (ret < 0) {
				set_ioa_socket_tobeclosed(s);
			} else {
				++(ss->sent_packets);
				ss->sent_bytes += bytes;
				turn_report_session_usage(ss);
			}
			pop_unsent_buffer(ub);
		} while(!ioa_socket_tobeclosed(s) && ((i++)<MAX_UNSENT_BUFFER_SIZE));
	}
}

static void tcp_peer_input_handler(ioa_socket_handle s, int event_type, ioa_net_data *in_buffer, void *arg, int can_resume)
{
	if (!(event_type & IOA_EV_READ) || !arg)
		return;

	UNUSED_ARG(s);
	UNUSED_ARG(can_resume);

	tcp_connection *tc = (tcp_connection*)arg;
	ts_ur_super_session *ss=NULL;
	allocation *a=(allocation*)tc->owner;
	if(a) {
		ss=(ts_ur_super_session*)a->owner;
	}

	if((tc->state != TC_STATE_READY) || !(tc->client_s)) {
		add_unsent_buffer(&(tc->ub_to_client), in_buffer->nbh);
		in_buffer->nbh = NULL;
		return;
	}

	ioa_network_buffer_handle nbh = in_buffer->nbh;
	in_buffer->nbh = NULL;

	u32bits bytes = (u32bits)ioa_network_buffer_get_size(nbh);

	int ret = send_data_from_ioa_socket_nbh(tc->client_s, NULL, nbh, TTL_IGNORE, TOS_IGNORE, NULL);
	if (ret < 0) {
		set_ioa_socket_tobeclosed(s);
	} else if(ss) {
		++(ss->sent_packets);
		ss->sent_bytes += bytes;
		turn_report_session_usage(ss);
	}
}

static void tcp_client_input_handler_rfc6062data(ioa_socket_handle s, int event_type, ioa_net_data *in_buffer, void *arg, int can_resume)
{
	if (!(event_type & IOA_EV_READ) || !arg)
		return;

	UNUSED_ARG(s);
	UNUSED_ARG(can_resume);

	tcp_connection *tc = (tcp_connection*)arg;
	ts_ur_super_session *ss=NULL;
	allocation *a=(allocation*)tc->owner;
	if(a) {
		ss=(ts_ur_super_session*)a->owner;
	}

	if(tc->state != TC_STATE_READY)
		return;

	if(!(tc->peer_s))
		return;

	ioa_network_buffer_handle nbh = in_buffer->nbh;
	in_buffer->nbh = NULL;

	if(ss) {
		u32bits bytes = (u32bits)ioa_network_buffer_get_size(nbh);
		++(ss->received_packets);
		ss->received_bytes += bytes;
	}

	int ret = send_data_from_ioa_socket_nbh(tc->peer_s, NULL, nbh, TTL_IGNORE, TOS_IGNORE, NULL);
	if (ret < 0) {
		set_ioa_socket_tobeclosed(s);
	}

	turn_report_session_usage(ss);
}

static void tcp_conn_bind_timeout_handler(ioa_engine_handle e, void *arg)
{
	UNUSED_ARG(e);
	if(arg) {
		tcp_connection *tc = (tcp_connection *)arg;
		delete_tcp_connection(tc);
	}
}

static void tcp_peer_connection_completed_callback(int success, void *arg)
{
	if(arg) {
		tcp_connection *tc = (tcp_connection *)arg;
		allocation *a = (allocation*)(tc->owner);
		ts_ur_super_session *ss = (ts_ur_super_session*)(a->owner);
		turn_turnserver *server=(turn_turnserver*)(ss->server);
		int err_code = 0;

		IOA_EVENT_DEL(tc->peer_conn_timeout);

		ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
		size_t len = ioa_network_buffer_get_size(nbh);

		if(success) {
			if(register_callback_on_ioa_socket(server->e, tc->peer_s, IOA_EV_READ, tcp_peer_input_handler, tc, 1)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot set TCP peer data input callback\n", __FUNCTION__);
				success=0;
				err_code = 500;
			}
		}

		if(success) {
			tc->state = TC_STATE_PEER_CONNECTED;
			stun_init_success_response_str(STUN_METHOD_CONNECT, ioa_network_buffer_data(nbh), &len, &(tc->tid));
			stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_CONNECTION_ID,
									(const u08bits*)&(tc->id), 4);

			IOA_EVENT_DEL(tc->conn_bind_timeout);
			tc->conn_bind_timeout = set_ioa_timer(server->e, TCP_CONN_BIND_TIMEOUT, 0,
									tcp_conn_bind_timeout_handler, tc, 0,
									"tcp_conn_bind_timeout_handler");

		} else {
			tc->state = TC_STATE_FAILED;
			if(!err_code) {
				err_code = 447;
			}
			{
				char ls[257]="\0";
				char rs[257]="\0";
				ioa_addr *laddr = get_local_addr_from_ioa_socket(ss->client_socket);
				if(laddr)
					addr_to_string(laddr,(u08bits*)ls);
				addr_to_string(&(tc->peer_addr),(u08bits*)rs);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: failure to connect from %s to %s\n", __FUNCTION__, ls,rs);
			}
			stun_init_error_response_str(STUN_METHOD_CONNECT, ioa_network_buffer_data(nbh), &len, err_code, NULL, &(tc->tid));
		}

		ioa_network_buffer_set_size(nbh,len);

		if(need_stun_authentication(server, ss)) {
			stun_attr_add_integrity_str(server->ct,ioa_network_buffer_data(nbh),&len,ss->hmackey,ss->pwd,SHATYPE_DEFAULT);
			ioa_network_buffer_set_size(nbh,len);
		}

		write_client_connection(server, ss, nbh, TTL_IGNORE, TOS_IGNORE);

		if(!success) {
			delete_tcp_connection(tc);
		}
		/* test */
		else if(0)
		{
			int i = 0;
			for(i=0;i<22;i++) {
				ioa_network_buffer_handle nbh_test = ioa_network_buffer_allocate(server->e);
				size_t len_test = ioa_network_buffer_get_size(nbh_test);
				u08bits *data = ioa_network_buffer_data(nbh_test);
				const char* data_test="111.111.111.111.111";
				len_test = strlen(data_test);
				ns_bcopy(data_test,data,len_test);
				ioa_network_buffer_set_size(nbh_test,len_test);
				send_data_from_ioa_socket_nbh(tc->peer_s, NULL, nbh_test, TTL_IGNORE, TOS_IGNORE, NULL);
			}
		}
	}
}

static void tcp_peer_conn_timeout_handler(ioa_engine_handle e, void *arg)
{
	UNUSED_ARG(e);

	tcp_peer_connection_completed_callback(0,arg);
}

static int tcp_start_connection_to_peer(turn_turnserver *server, ts_ur_super_session *ss, stun_tid *tid,
				allocation *a, ioa_addr *peer_addr,
				int *err_code, const u08bits **reason)
{
	FUNCSTART;

	if(!ss) {
		*err_code = 500;
		*reason = (const u08bits *)"Server error: empty session";
		FUNCEND;
		return -1;
	}

	if(!peer_addr) {
		*err_code = 500;
		*reason = (const u08bits *)"Server error: empty peer addr";
		FUNCEND;
		return -1;
	}

	if(!get_relay_socket(a,peer_addr->ss.sa_family)) {
		*err_code = 500;
		*reason = (const u08bits *)"Server error: no relay connection created";
		FUNCEND;
		return -1;
	}

	tcp_connection *tc = get_tcp_connection_by_peer(a, peer_addr);
	if(tc) {
		*err_code = 446;
		FUNCEND;
		return -1;
	}

	tc = create_tcp_connection(server->id, a, tid, peer_addr, err_code);
	if(!tc) {
		if(!(*err_code)) {
			*err_code = 500;
			*reason = (const u08bits *)"Server error: TCP connection object creation failed";
		}
		FUNCEND;
		return -1;
	} else if(*err_code) {
		delete_tcp_connection(tc);
		FUNCEND;
		return -1;
	}

	IOA_EVENT_DEL(tc->peer_conn_timeout);
	tc->peer_conn_timeout = set_ioa_timer(server->e, TCP_PEER_CONN_TIMEOUT, 0,
						tcp_peer_conn_timeout_handler, tc, 0,
						"tcp_peer_conn_timeout_handler");

	ioa_socket_handle tcs = ioa_create_connecting_tcp_relay_socket(get_relay_socket(a,peer_addr->ss.sa_family),
			peer_addr, tcp_peer_connection_completed_callback, tc);
	if(!tcs) {
		delete_tcp_connection(tc);
		*err_code = 500;
		*reason = (const u08bits *)"Server error: TCP relay socket for connection cannot be created";
		FUNCEND;
		return -1;
	}

	tc->state = TC_STATE_CLIENT_TO_PEER_CONNECTING;
	if(tc->peer_s != tcs) {
		IOA_CLOSE_SOCKET(tc->peer_s);
		tc->peer_s = tcs;
	}
	set_ioa_socket_sub_session(tc->peer_s,tc);

	FUNCEND;
	return 0;
}

static void tcp_peer_accept_connection(ioa_socket_handle s, void *arg)
{
	if(s) {

		if(!arg) {
			close_ioa_socket(s);
			return;
		}

		ts_ur_super_session *ss = (ts_ur_super_session*)arg;
		turn_turnserver *server=(turn_turnserver*)(ss->server);

		FUNCSTART;

		allocation *a = &(ss->alloc);
		ioa_addr *peer_addr = get_remote_addr_from_ioa_socket(s);
		if(!peer_addr) {
			close_ioa_socket(s);
			FUNCEND;
			return;
		}

		tcp_connection *tc = get_tcp_connection_by_peer(a, peer_addr);
		if(tc) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: peer data socket with this address already exist\n", __FUNCTION__);
			if(tc->peer_s != s)
				close_ioa_socket(s);
			FUNCEND;
			return;
		}

		if(!good_peer_addr(server, ss->realm_options.name, peer_addr)) {
			u08bits saddr[256];
			addr_to_string(peer_addr, saddr);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: an attempt to connect from a peer with forbidden address: %s\n", __FUNCTION__,saddr);
			close_ioa_socket(s);
			FUNCEND;
			return;
		}

		if(!can_accept_tcp_connection_from_peer(a,peer_addr,server->server_relay)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: peer has no permission to connect\n", __FUNCTION__);
			close_ioa_socket(s);
			FUNCEND;
			return;
		}

		stun_tid tid;
		ns_bzero(&tid,sizeof(stun_tid));
		int err_code=0;
		tc = create_tcp_connection(server->id, a, &tid, peer_addr, &err_code);
		if(!tc) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot create TCP connection\n", __FUNCTION__);
			close_ioa_socket(s);
			FUNCEND;
			return;
		}

		tc->state = TC_STATE_PEER_CONNECTED;
		tc->peer_s = s;

		set_ioa_socket_session(s,ss);
		set_ioa_socket_sub_session(s,tc);

		if(register_callback_on_ioa_socket(server->e, s, IOA_EV_READ, tcp_peer_input_handler, tc, 1)<0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot set TCP peer data input callback\n", __FUNCTION__);
			IOA_CLOSE_SOCKET(tc->peer_s);
			tc->state = TC_STATE_UNKNOWN;
			FUNCEND;
			return;
		}

		IOA_EVENT_DEL(tc->conn_bind_timeout);
		tc->conn_bind_timeout = set_ioa_timer(server->e, TCP_CONN_BIND_TIMEOUT, 0,
							tcp_conn_bind_timeout_handler, tc, 0,
							"tcp_conn_bind_timeout_handler");

		ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
		size_t len = ioa_network_buffer_get_size(nbh);

		stun_init_indication_str(STUN_METHOD_CONNECTION_ATTEMPT, ioa_network_buffer_data(nbh), &len);
		stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_CONNECTION_ID,
					(const u08bits*)&(tc->id), 4);
		stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer_addr);

		ioa_network_buffer_set_size(nbh,len);

		{
			static const u08bits *field = (const u08bits *) TURN_SOFTWARE;
			static const size_t fsz = sizeof(TURN_SOFTWARE)-1;
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
			ioa_network_buffer_set_size(nbh, len);
		}

		if ((server->fingerprint) || ss->enforce_fingerprints) {
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_fingerprint_str(ioa_network_buffer_data(nbh), &len);
			ioa_network_buffer_set_size(nbh, len);
		}

		write_client_connection(server, ss, nbh, TTL_IGNORE, TOS_IGNORE);

		FUNCEND;
	}
}

static int handle_turn_connect(turn_turnserver *server,
				    ts_ur_super_session *ss, stun_tid *tid,
				    int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
				    ioa_net_data *in_buffer) {

	FUNCSTART;
	ioa_addr peer_addr;
	int peer_found = 0;
	addr_set_any(&peer_addr);
	allocation* a = get_allocation_ss(ss);

	if(!(ss->is_tcp_relay)) {
		*err_code = 403;
		*reason = (const u08bits *)"Connect cannot be used with UDP relay";
	} else if (!is_allocation_valid(a)) {
		*err_code = 437;
	} else {

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
			  {
				if(stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh),
						       ioa_network_buffer_get_size(in_buffer->nbh),
						       sar, &peer_addr,
						       NULL) == -1) {
					*err_code = 400;
					*reason = (const u08bits *)"Bad Peer Address";
				} else {
					if(!get_relay_socket(a,peer_addr.ss.sa_family)) {
						*err_code = 443;
						*reason = (const u08bits *)"Peer Address Family Mismatch (2)";
					}

					peer_found = 1;
				}
				break;
			  }
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
						     ioa_network_buffer_get_size(in_buffer->nbh),
						     sar);
		}

		if (*ua_num > 0) {

			*err_code = 420;

		} else if (*err_code) {

			;

		} else if (!peer_found) {

			*err_code = 400;
			*reason = (const u08bits *)"Where is Peer Address ?";

		} else {
			if(!good_peer_addr(server,ss->realm_options.name,&peer_addr)) {
				*err_code = 403;
				*reason = (const u08bits *) "Forbidden IP";
			} else {
				tcp_start_connection_to_peer(server, ss, tid, a, &peer_addr, err_code, reason);
			}
		}
	}

	FUNCEND;
	return 0;
}

static int handle_turn_connection_bind(turn_turnserver *server,
			       ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
			       int *err_code, 	const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
			       ioa_net_data *in_buffer, ioa_network_buffer_handle nbh, int message_integrity,
			       int can_resume) {

	allocation* a = get_allocation_ss(ss);

	u16bits method = STUN_METHOD_CONNECTION_BIND;

	if(ss->to_be_closed) {

		*err_code = 400;

	} else if (is_allocation_valid(a)) {

		*err_code = 400;
		*reason = (const u08bits *)"Bad request: CONNECTION_BIND cannot be issued after allocation";

	} else if(!is_stream_socket(get_ioa_socket_type(ss->client_socket))) {

		*err_code = 400;
		*reason = (const u08bits *)"Bad request: CONNECTION_BIND only possible with TCP/TLS";

	} else {
		tcp_connection_id id = 0;

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_CONNECTION_ID: {
				if (stun_attr_get_len(sar) != 4) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong Connection ID field format";
				} else {
					const u08bits* value = stun_attr_get_value(sar);
					if (!value) {
						*err_code = 400;
						*reason = (const u08bits *)"Wrong Connection ID field data";
					} else {
						id = *((const u32bits*)value); //AS-IS encoding, no conversion to/from network byte order
					}
				}
			}
				break;
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
						     ioa_network_buffer_get_size(in_buffer->nbh), sar);
		}

		if (*ua_num > 0) {

			*err_code = 420;

		} else if (*err_code) {

			;

		} else {
			if(server->send_socket_to_relay) {
				turnserver_id sid = (id & 0xFF000000)>>24;
				ioa_socket_handle s = ss->client_socket;
				if(s && !ioa_socket_tobeclosed(s)) {
					ioa_socket_handle new_s = detach_ioa_socket(s);
					if(new_s) {
					  if(server->send_socket_to_relay(sid, id, tid, new_s, message_integrity, RMT_CB_SOCKET, in_buffer, can_resume)<0) {
					    *err_code = 400;
					    *reason = (const u08bits *)"Wrong connection id";
					  }
					} else {
						*err_code = 500;
					}
				} else {
					*err_code = 500;
				}
			} else {
				*err_code = 500;
			}
			ss->to_be_closed = 1;
		}
	}

	if (!(*resp_constructed) && ss->client_socket && !ioa_socket_tobeclosed(ss->client_socket)) {

		if (!(*err_code)) {
			*err_code = 437;
		}

		size_t len = ioa_network_buffer_get_size(nbh);
		stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
		ioa_network_buffer_set_size(nbh,len);

		*resp_constructed = 1;
	}

	return 0;
}

int turnserver_accept_tcp_client_data_connection(turn_turnserver *server, tcp_connection_id tcid, stun_tid *tid, ioa_socket_handle s, int message_integrity, ioa_net_data *in_buffer, int can_resume)
{
	if(!server)
		return -1;

	FUNCSTART;

	tcp_connection *tc = NULL;
	ts_ur_super_session *ss = NULL;

	int err_code = 0;
	const u08bits *reason = NULL;

	ioa_socket_handle s_to_delete = s;

	if(tcid && tid && s) {

		tc = get_tcp_connection_by_id(server->tcp_relay_connections, tcid);
		ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
		int resp_constructed = 0;
		if(!tc || (tc->state == TC_STATE_READY) || (tc->client_s)) {
			err_code = 400;
		} else {
			allocation *a = (allocation*)(tc->owner);
			if(!a || !(a->owner)) {
				err_code = 500;
			} else {
				ss = (ts_ur_super_session*)(a->owner);

				if(ss->to_be_closed || ioa_socket_tobeclosed(ss->client_socket)) {
					err_code = 404;
				} else {
					//Check security:
					int postpone_reply = 0;
					check_stun_auth(server, ss, tid, &resp_constructed, &err_code, &reason, in_buffer, nbh,
						STUN_METHOD_CONNECTION_BIND, &message_integrity, &postpone_reply, can_resume);

					if(postpone_reply) {

						ioa_network_buffer_delete(server->e, nbh);
						return 0;

					} else if(!err_code) {
						tc->state = TC_STATE_READY;
						tc->client_s = s;
						s_to_delete = NULL;
						set_ioa_socket_session(s,ss);
						set_ioa_socket_sub_session(s,tc);
						set_ioa_socket_app_type(s,TCP_CLIENT_DATA_SOCKET);
						if(register_callback_on_ioa_socket(server->e, s, IOA_EV_READ, tcp_client_input_handler_rfc6062data, tc, 1)<0) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot set TCP client data input callback\n", __FUNCTION__);
							err_code = 500;
						} else {
							IOA_EVENT_DEL(tc->conn_bind_timeout);
						}
					}
				}
			}
		}

		if(tc)
			get_and_clean_tcp_connection_by_id(server->tcp_relay_connections, tcid);

		if(!resp_constructed) {
			if(!err_code) {
				size_t len = ioa_network_buffer_get_size(nbh);
				stun_init_success_response_str(STUN_METHOD_CONNECTION_BIND, ioa_network_buffer_data(nbh), &len, tid);
				ioa_network_buffer_set_size(nbh,len);
			} else {
				size_t len = ioa_network_buffer_get_size(nbh);
				stun_init_error_response_str(STUN_METHOD_CONNECTION_BIND, ioa_network_buffer_data(nbh), &len, err_code, NULL, tid);
				ioa_network_buffer_set_size(nbh,len);
			}
		}

		{
			static const u08bits *field = (const u08bits *) TURN_SOFTWARE;
			static const size_t fsz = sizeof(TURN_SOFTWARE)-1;
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
			ioa_network_buffer_set_size(nbh, len);
		}

		if(message_integrity && ss) {
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_integrity_str(server->ct,ioa_network_buffer_data(nbh),&len,ss->hmackey,ss->pwd,SHATYPE_DEFAULT);
			ioa_network_buffer_set_size(nbh,len);
		}

		if ((server->fingerprint) || (ss &&(ss->enforce_fingerprints))) {
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_fingerprint_str(ioa_network_buffer_data(nbh), &len);
			ioa_network_buffer_set_size(nbh, len);
		}

		if(server->verbose) {
			log_method(ss, "CONNECTION_BIND", err_code, reason);
		}

		if(ss && !err_code) {
			send_data_from_ioa_socket_nbh(s, NULL, nbh, TTL_IGNORE, TOS_IGNORE, NULL);
			tcp_deliver_delayed_buffer(&(tc->ub_to_client),s,ss);
			IOA_CLOSE_SOCKET(s_to_delete);
			FUNCEND;
			return 0;
		} else {
			/* Just to set the necessary structures for the packet sending: */
			if(register_callback_on_ioa_socket(server->e, s, IOA_EV_READ, NULL, NULL, 1)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: cannot set TCP tmp client data input callback\n", __FUNCTION__);
				ioa_network_buffer_delete(server->e, nbh);
			} else {
				send_data_from_ioa_socket_nbh(s, NULL, nbh, TTL_IGNORE, TOS_IGNORE, NULL);
			}
		}
	}

	IOA_CLOSE_SOCKET(s_to_delete);

	FUNCEND;
	return -1;
}

/* <<== RFC 6062 */

static int handle_turn_channel_bind(turn_turnserver *server,
				    ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				    int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
				    ioa_net_data *in_buffer, ioa_network_buffer_handle nbh) {

	FUNCSTART;
	u16bits chnum = 0;
	ioa_addr peer_addr;
	addr_set_any(&peer_addr);
	allocation* a = get_allocation_ss(ss);
	int addr_found = 0;

	if(ss->is_tcp_relay) {
		*err_code = 403;
		*reason = (const u08bits *)"Channel bind cannot be used with TCP relay";
	} else if (is_allocation_valid(a)) {

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_CHANNEL_NUMBER: {
				if (chnum) {
					chnum = 0;
					*err_code = 400;
					*reason = (const u08bits *)"Channel number cannot be duplicated in this request";
					break;
				}
				chnum = stun_attr_get_channel_number(sar);
				if (!chnum) {
					*err_code = 400;
					*reason = (const u08bits *)"Channel number cannot be zero in this request";
					break;
				}
			}
				break;
			case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
			  {
				stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh), 
						       ioa_network_buffer_get_size(in_buffer->nbh), 
						       sar, &peer_addr,
						       NULL);

				if(!get_relay_socket(a,peer_addr.ss.sa_family)) {
					*err_code = 443;
					*reason = (const u08bits *)"Peer Address Family Mismatch (3)";
				}

				if(addr_get_port(&peer_addr) < 1) {
					*err_code = 400;
					*reason = (const u08bits *)"Empty port number in channel bind request";
				} else {
					addr_found = 1;
				}

				break;
			  }
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), 
						     ioa_network_buffer_get_size(in_buffer->nbh), 
						     sar);
		}

		if (*ua_num > 0) {

			*err_code = 420;

		} else if (*err_code) {

			;

		} else if (!chnum || addr_any(&peer_addr) || !addr_found) {

			*err_code = 400;
			*reason = (const u08bits *)"Bad channel bind request";

		} else if(!STUN_VALID_CHANNEL(chnum)) {

			*err_code = 400;
			*reason = (const u08bits *)"Bad channel number";

		} else {

			ch_info* chn = allocation_get_ch_info(a, chnum);
			turn_permission_info* tinfo = NULL;

			if (chn) {
				if (!addr_eq(&peer_addr, &(chn->peer_addr))) {
					*err_code = 400;
					*reason = (const u08bits *)"You cannot use the same channel number with different peer";
				} else {
					tinfo = (turn_permission_info*) (chn->owner);
					if (!tinfo) {
						*err_code = 500;
						*reason = (const u08bits *)"Wrong permission info";
					} else {
						if (!addr_eq_no_port(&peer_addr, &(tinfo->addr))) {
							*err_code = 500;
							*reason = (const u08bits *)"Wrong permission info and peer addr conbination";
						} else if (chn->port != addr_get_port(&peer_addr)) {
							*err_code = 500;
							*reason = (const u08bits *)"Wrong port number";
						}
					}
				}

			} else {

				chn = allocation_get_ch_info_by_peer_addr(a, &peer_addr);
				if(chn) {
					*err_code = 400;
					*reason = (const u08bits *)"You cannot use the same peer with different channel number";
				} else {
					if(!good_peer_addr(server,ss->realm_options.name,&peer_addr)) {
						*err_code = 403;
						*reason = (const u08bits *) "Forbidden IP";
					} else {
						chn = allocation_get_new_ch_info(a, chnum, &peer_addr);
						if (!chn) {
							*err_code = 500;
							*reason = (const u08bits *) "Cannot find channel data";
						} else {
							tinfo = (turn_permission_info*) (chn->owner);
							if (!tinfo) {
								*err_code = 500;
								*reason
									= (const u08bits *) "Wrong turn permission info";
							}
						}
					}
				}
			}

			if (!(*err_code) && chn && tinfo) {

			  if (update_channel_lifetime(ss,chn) < 0) {
			    *err_code = 500;
			    *reason = (const u08bits *)"Cannot update channel lifetime (internal error)";
			  } else {
				  size_t len = ioa_network_buffer_get_size(nbh);
				  stun_set_channel_bind_response_str(ioa_network_buffer_data(nbh), &len, tid, 0, NULL);
				  ioa_network_buffer_set_size(nbh,len);
				  *resp_constructed = 1;

				  if(!(ss->is_mobile)) {
					  if(get_ioa_socket_type(ss->client_socket) == UDP_SOCKET ||
							  get_ioa_socket_type(ss->client_socket) == TCP_SOCKET ||
							  get_ioa_socket_type(ss->client_socket) == SCTP_SOCKET) {
						  if(get_ioa_socket_type(get_relay_socket(&(ss->alloc),peer_addr.ss.sa_family)) == UDP_SOCKET) {
							  chn->kernel_channel = CREATE_TURN_CHANNEL_KERNEL(chn->chnum,
								  get_ioa_socket_address_family(ss->client_socket),
								  peer_addr.ss.sa_family,
								  (get_ioa_socket_type(ss->client_socket)==UDP_SOCKET ? IPPROTO_UDP : IPPROTO_TCP),
								  &(get_remote_addr_from_ioa_socket(ss->client_socket)->ss),
								  &(get_local_addr_from_ioa_socket(ss->client_socket)->ss),
								  &(get_local_addr_from_ioa_socket(get_relay_socket(&(ss->alloc),peer_addr.ss.sa_family))),
								  &(get_remote_addr_from_ioa_socket(get_relay_socket(&(ss->alloc),peer_addr.ss.sa_family)))
							  );
						  }
					  }
				  }
			  }
			}
		}
	}

	FUNCEND;
	return 0;
}

static int handle_turn_binding(turn_turnserver *server,
				    ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				    int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
				    ioa_net_data *in_buffer, ioa_network_buffer_handle nbh,
				    int *origin_changed, ioa_addr *response_origin,
				    int *dest_changed, ioa_addr *response_destination,
				    u32bits cookie, int old_stun) {

	FUNCSTART;
	int change_ip = 0;
	int change_port = 0;
	int padding = 0;
	int response_port_present = 0;
	u16bits response_port = 0;
	SOCKET_TYPE st = get_ioa_socket_type(ss->client_socket);
	int use_reflected_from = 0;

	if(!(ss->client_socket))
		return -1;

	*origin_changed = 0;
	*dest_changed = 0;

	stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
						    ioa_network_buffer_get_size(in_buffer->nbh));
	while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
		int attr_type = stun_attr_get_type(sar);
		switch (attr_type) {
		case OLD_STUN_ATTRIBUTE_PASSWORD:
		SKIP_ATTRIBUTES;
		case STUN_ATTRIBUTE_CHANGE_REQUEST:
/*
 * This fix allows the client program from the Stuntman source to make STUN binding requests
 * to this server.
 *
 * It was provided by  John Selbie, from STUNTMAN project:
 *
 * "Here's the gist of the change. Stuntman comes with a STUN client library
 * and client program. The client program displays the mapped IP address and
 * port if it gets back a successful binding response.
 * It also interops with JSTUN, a Java implementation of STUN.
 * However, the JSTUN server refuses to respond to any binding request that
 * doesn't have a CHANGE-REQUEST attribute in it.
 * ... workaround is for the client to make a request with an empty CHANGE-REQUEST
 * attribute (neither the ip or port bit are set)."
 *
 */
			stun_attr_get_change_request_str(sar, &change_ip, &change_port);
			if( (!is_rfc5780(server)) && (change_ip || change_port)) {
				*err_code = 420;
				*reason = (const u08bits *)"Unknown attribute: TURN server was configured without RFC 5780 support";
				break;
			}
			if(change_ip || change_port) {
				if(st != UDP_SOCKET) {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong request: applicable only to UDP protocol";
				}
			}
			break;
		case STUN_ATTRIBUTE_PADDING:
			if(response_port_present) {
				*err_code = 400;
				*reason = (const u08bits *)"Wrong request format: you cannot use PADDING and RESPONSE_PORT together";
			} else if((st != UDP_SOCKET) && (st != DTLS_SOCKET)) {
				*err_code = 400;
				*reason = (const u08bits *)"Wrong request: padding applicable only to UDP and DTLS protocols";
			} else {
				padding = 1;
			}
			break;
		case STUN_ATTRIBUTE_RESPONSE_PORT:
			if(padding) {
				*err_code = 400;
				*reason = (const u08bits *)"Wrong request format: you cannot use PADDING and RESPONSE_PORT together";
			} else if(st != UDP_SOCKET) {
				*err_code = 400;
				*reason = (const u08bits *)"Wrong request: applicable only to UDP protocol";
			} else {
				int rp = stun_attr_get_response_port_str(sar);
				if(rp>=0) {
					response_port_present = 1;
					response_port = (u16bits)rp;
				} else {
					*err_code = 400;
					*reason = (const u08bits *)"Wrong response port format";
				}
			}
			break;
		case OLD_STUN_ATTRIBUTE_RESPONSE_ADDRESS:
			if(old_stun) {
				use_reflected_from = 1;
				stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh),
							ioa_network_buffer_get_size(in_buffer->nbh),
							sar, response_destination, response_destination);
			}
			break;
		default:
			if(attr_type>=0x0000 && attr_type<=0x7FFF)
				unknown_attrs[(*ua_num)++] = nswap16(attr_type);
		};
		sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
					     ioa_network_buffer_get_size(in_buffer->nbh),
					     sar);
	}

	if (*ua_num > 0) {

		*err_code = 420;

	} else if (*err_code) {

		;

	} else if(ss->client_socket && get_remote_addr_from_ioa_socket(ss->client_socket)) {

		size_t len = ioa_network_buffer_get_size(nbh);
		if (stun_set_binding_response_str(ioa_network_buffer_data(nbh), &len, tid,
					get_remote_addr_from_ioa_socket(ss->client_socket), 0, NULL, cookie, old_stun) >= 0) {

			addr_cpy(response_origin, get_local_addr_from_ioa_socket(ss->client_socket));

			*resp_constructed = 1;

			if(old_stun && use_reflected_from) {
				stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
						OLD_STUN_ATTRIBUTE_REFLECTED_FROM,
						get_remote_addr_from_ioa_socket(ss->client_socket));
			}

			if(!is_rfc5780(server)) {

				if(old_stun) {
					stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
								OLD_STUN_ATTRIBUTE_SOURCE_ADDRESS, response_origin);
					stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
								OLD_STUN_ATTRIBUTE_CHANGED_ADDRESS, response_origin);
				} else {
					stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
							STUN_ATTRIBUTE_RESPONSE_ORIGIN, response_origin);
				}

			} else if(ss->client_socket) {

				ioa_addr other_address;

				if(get_other_address(server,ss,&other_address) == 0) {

					addr_cpy(response_destination, get_remote_addr_from_ioa_socket(ss->client_socket));

					if(change_ip) {
						*origin_changed = 1;
						if(change_port) {
							addr_cpy(response_origin,&other_address);
						} else {
							int old_port = addr_get_port(response_origin);
							addr_cpy(response_origin,&other_address);
							addr_set_port(response_origin,old_port);
						}
					} else if(change_port) {
						*origin_changed = 1;
						addr_set_port(response_origin,addr_get_port(&other_address));
					}

					if(old_stun) {
						stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
									OLD_STUN_ATTRIBUTE_SOURCE_ADDRESS, response_origin);
						stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
									OLD_STUN_ATTRIBUTE_CHANGED_ADDRESS, &other_address);
					} else {
						stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
									STUN_ATTRIBUTE_RESPONSE_ORIGIN, response_origin);
						stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
									STUN_ATTRIBUTE_OTHER_ADDRESS, &other_address);
					}

					if(response_port_present) {
						*dest_changed = 1;
						addr_set_port(response_destination, (int)response_port);
					}

					if(padding) {
						int mtu = get_local_mtu_ioa_socket(ss->client_socket);
						if(mtu<68)
							mtu=1500;

						mtu = (mtu >> 2) << 2;
						stun_attr_add_padding_str(ioa_network_buffer_data(nbh), &len, (u16bits)mtu);
					}
				}
			}
		}
		ioa_network_buffer_set_size(nbh, len);
	}

	FUNCEND;
	return 0;
}

static int handle_turn_send(turn_turnserver *server, ts_ur_super_session *ss,
			    int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
			    ioa_net_data *in_buffer) {

	FUNCSTART;

	ioa_addr peer_addr;
	const u08bits* value = NULL;
	int len = -1;
	int addr_found = 0;
	int set_df = 0;

	addr_set_any(&peer_addr);
	allocation* a = get_allocation_ss(ss);

	if(ss->is_tcp_relay) {
		*err_code = 403;
		*reason = (const u08bits *)"Send cannot be used with TCP relay";
	} else if (is_allocation_valid(a) && (in_buffer->recv_ttl != 0)) {

		stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), 
							    ioa_network_buffer_get_size(in_buffer->nbh));
		while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
			int attr_type = stun_attr_get_type(sar);
			switch (attr_type) {
			SKIP_ATTRIBUTES;
			case STUN_ATTRIBUTE_DONT_FRAGMENT:
				if(!(server->dont_fragment))
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
				else
					set_df = 1;
				break;
			case STUN_ATTRIBUTE_XOR_PEER_ADDRESS: {
				if (addr_found) {
					*err_code = 400;
					*reason = (const u08bits *)"Address duplication";
				} else {
					stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh), 
							       ioa_network_buffer_get_size(in_buffer->nbh),
							       sar, &peer_addr,
							       NULL);
				}
			}
				break;
			case STUN_ATTRIBUTE_DATA: {
				if (len >= 0) {
					*err_code = 400;
					*reason = (const u08bits *)"Data duplication";
				} else {
					len = stun_attr_get_len(sar);
					value = stun_attr_get_value(sar);
				}
			}
				break;
			default:
				if(attr_type>=0x0000 && attr_type<=0x7FFF)
					unknown_attrs[(*ua_num)++] = nswap16(attr_type);
			};
			sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), 
						     ioa_network_buffer_get_size(in_buffer->nbh), 
						     sar);
		}

		if (*err_code) {
			;
		} else if (*ua_num > 0) {

			*err_code = 420;

		} else if (!addr_any(&peer_addr) && len >= 0) {

			turn_permission_info* tinfo = NULL;

			if(!(server->server_relay))
				tinfo = allocation_get_permission(a, &peer_addr);

			if (tinfo || (server->server_relay)) {

				set_df_on_ioa_socket(get_relay_socket_ss(ss,peer_addr.ss.sa_family), set_df);

				ioa_network_buffer_handle nbh = in_buffer->nbh;
				if(value && len>0) {
					u16bits offset = (u16bits)(value - ioa_network_buffer_data(nbh));
					ioa_network_buffer_add_offset_size(nbh,offset,0,len);
				} else {
					len = 0;
					ioa_network_buffer_set_size(nbh,len);
				}
				ioa_network_buffer_header_init(nbh);
				send_data_from_ioa_socket_nbh(get_relay_socket_ss(ss,peer_addr.ss.sa_family), &peer_addr, nbh, in_buffer->recv_ttl-1, in_buffer->recv_tos, NULL);
				in_buffer->nbh = NULL;
			}

		} else {
			*err_code = 400;
			*reason = (const u08bits *)"No address found";
		}
	}

	FUNCEND;
	return 0;
}

static int update_permission(ts_ur_super_session *ss, ioa_addr *peer_addr) {

	if (!ss || !peer_addr)
		return -1;

	allocation* a = get_allocation_ss(ss);

	turn_permission_info* tinfo = allocation_get_permission(a, peer_addr);

	if (!tinfo) {
		tinfo = allocation_add_permission(a, peer_addr);
	}

	if (!tinfo)
		return -1;

	if (update_turn_permission_lifetime(ss, tinfo, 0) < 0)
		return -1;

	ch_info *chn = get_turn_channel(tinfo, peer_addr);
	if(chn) {
		if (update_channel_lifetime(ss, chn) < 0)
			return -1;
	}

	return 0;
}

static int handle_turn_create_permission(turn_turnserver *server,
					 ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
					 int *err_code, const u08bits **reason, u16bits *unknown_attrs, u16bits *ua_num,
					 ioa_net_data *in_buffer, ioa_network_buffer_handle nbh) {

	int ret = -1;

	int addr_found = 0;

	UNUSED_ARG(server);

	allocation* a = get_allocation_ss(ss);

	if (is_allocation_valid(a)) {

		{
			stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
							    ioa_network_buffer_get_size(in_buffer->nbh));

			while (sar && (!(*err_code)) && (*ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {

				int attr_type = stun_attr_get_type(sar);

				switch (attr_type) {

				SKIP_ATTRIBUTES;

				case STUN_ATTRIBUTE_XOR_PEER_ADDRESS: {

					ioa_addr peer_addr;
					addr_set_any(&peer_addr);

					stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh),
						       ioa_network_buffer_get_size(in_buffer->nbh),
						       sar, &peer_addr,
						       NULL);

					if(!get_relay_socket(a,peer_addr.ss.sa_family)) {
						*err_code = 443;
						*reason = (const u08bits *)"Peer Address Family Mismatch (4)";
					} else if(!good_peer_addr(server, ss->realm_options.name, &peer_addr)) {
						*err_code = 403;
						*reason = (const u08bits *) "Forbidden IP";
					} else {
						addr_found++;
					}
				}
					break;
				default:
					if(attr_type>=0x0000 && attr_type<=0x7FFF)
						unknown_attrs[(*ua_num)++] = nswap16(attr_type);
				};
				sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
						     ioa_network_buffer_get_size(in_buffer->nbh), 
						     sar);
			}
		}

		if (*ua_num > 0) {

			*err_code = 420;

		} else if (*err_code) {

			;

		} else if (!addr_found) {

			*err_code = 400;
			*reason = (const u08bits *)"No address found";

		} else {

			stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
										    ioa_network_buffer_get_size(in_buffer->nbh));

			while (sar) {

				int attr_type = stun_attr_get_type(sar);

				switch (attr_type) {

				SKIP_ATTRIBUTES;

				case STUN_ATTRIBUTE_XOR_PEER_ADDRESS: {

					ioa_addr peer_addr;
					addr_set_any(&peer_addr);

					stun_attr_get_addr_str(ioa_network_buffer_data(in_buffer->nbh),
									       ioa_network_buffer_get_size(in_buffer->nbh),
									       sar, &peer_addr,
									       NULL);

					addr_set_port(&peer_addr, 0);
					if (update_permission(ss, &peer_addr) < 0) {
						*err_code = 500;
						*reason = (const u08bits *)"Cannot update some permissions (critical server software error)";
					}
				}
					break;
				default:
					;
				}

				sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
									     ioa_network_buffer_get_size(in_buffer->nbh),
									     sar);
			}

			if(*err_code == 0) {
				size_t len = ioa_network_buffer_get_size(nbh);
				stun_init_success_response_str(STUN_METHOD_CREATE_PERMISSION,
							ioa_network_buffer_data(nbh), &len, tid);
				ioa_network_buffer_set_size(nbh,len);

				ret = 0;
				*resp_constructed = 1;
			}
		}
	}

	return ret;
}

// AUTH ==>>

static int need_stun_authentication(turn_turnserver *server, ts_ur_super_session *ss)
{
	UNUSED_ARG(ss);

	if(server) {
		switch(server->ct) {
		case TURN_CREDENTIALS_LONG_TERM:
			return 1;
		default:
			;
		};
	}

	return 0;
}

static int create_challenge_response(ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
				int *err_code, 	const u08bits **reason,
				ioa_network_buffer_handle nbh,
				u16bits method)
{
	size_t len = ioa_network_buffer_get_size(nbh);
	stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
	*resp_constructed = 1;
	stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_NONCE,
					ss->nonce, (int)(NONCE_MAX_SIZE-1));
	char *realm = ss->realm_options.name;
	stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_REALM,
					(u08bits*)realm, (int)(strlen((s08bits*)(realm))));

	if(ss->server) {
		turn_turnserver* server = (turn_turnserver*)ss->server;
		if(server->oauth) {
			const char *server_name = server->oauth_server_name;
			if(!(server_name && server_name[0])) {
				server_name = realm;
			}
			stun_attr_add_str(ioa_network_buffer_data(nbh), &len,
    			STUN_ATTRIBUTE_THIRD_PARTY_AUTHORIZATION,
    			(const u08bits*)(server_name),
    			strlen(server_name));
		}
    }

	ioa_network_buffer_set_size(nbh,len);
	return 0;
}

#if !defined(min)
#define min(a,b) ((a)<=(b) ? (a) : (b))
#endif

static void resume_processing_after_username_check(int success,  int oauth, int max_session_time, hmackey_t hmackey, password_t pwd, turn_turnserver *server, u64bits ctxkey, ioa_net_data *in_buffer, u08bits *realm)
{

	if(server && in_buffer && in_buffer->nbh) {

		ts_ur_super_session *ss = get_session_from_map(server,(turnsession_id)ctxkey);
		if(ss && ss->client_socket) {
			turn_turnserver *server = (turn_turnserver *)ss->server;

			if(success) {
				ns_bcopy(hmackey,ss->hmackey,sizeof(hmackey_t));
				ss->hmackey_set = 1;
				ss->oauth = oauth;
				ss->max_session_time_auth = (turn_time_t)max_session_time;
				ns_bcopy(pwd,ss->pwd,sizeof(password_t));
				if(realm && realm[0] && strcmp((char*)realm,ss->realm_options.name)) {
					dec_quota(ss);
					get_realm_options_by_name((char*)realm, &(ss->realm_options));
					inc_quota(ss,ss->username);
				}
			}

			read_client_connection(server,ss,in_buffer,0,0);

			close_ioa_socket_after_processing_if_necessary(ss->client_socket);

			ioa_network_buffer_delete(server->e, in_buffer->nbh);
			in_buffer->nbh=NULL;
		}
	}
}

static int check_stun_auth(turn_turnserver *server,
			ts_ur_super_session *ss, stun_tid *tid, int *resp_constructed,
			int *err_code, 	const u08bits **reason,
			ioa_net_data *in_buffer, ioa_network_buffer_handle nbh,
			u16bits method, int *message_integrity,
			int *postpone_reply,
			int can_resume)
{
	u08bits usname[STUN_MAX_USERNAME_SIZE+1];
	u08bits nonce[STUN_MAX_NONCE_SIZE+1];
	u08bits realm[STUN_MAX_REALM_SIZE+1];
	size_t alen = 0;

	if(!need_stun_authentication(server, ss))
		return 0;

	int new_nonce = 0;

	{
		int generate_new_nonce = 0;
		if(ss->nonce[0]==0) {
			generate_new_nonce = 1;
			new_nonce = 1;
		}

		if(*(server->stale_nonce)) {
			if(turn_time_before(ss->nonce_expiration_time,server->ctime)) {
				generate_new_nonce = 1;
			}
		}

		if(generate_new_nonce) {

			int i = 0;

			if(TURN_RANDOM_SIZE == 8) {
				for(i=0;i<(NONCE_LENGTH_32BITS>>1);i++) {
					u08bits *s = ss->nonce + 8*i;
					u64bits rand=(u64bits)turn_random();
					snprintf((s08bits*)s, NONCE_MAX_SIZE-8*i, "%08lx",(unsigned long)rand);
				}
			} else {
				for(i=0;i<NONCE_LENGTH_32BITS;i++) {
					u08bits *s = ss->nonce + 4*i;
					u32bits rand=(u32bits)turn_random();
					snprintf((s08bits*)s, NONCE_MAX_SIZE-4*i, "%04x",(unsigned int)rand);
				}
			}
			ss->nonce_expiration_time = server->ctime + STUN_NONCE_EXPIRATION_TIME;
		}
	}

	/* MESSAGE_INTEGRITY ATTR: */

	stun_attr_ref sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(in_buffer->nbh),
							    ioa_network_buffer_get_size(in_buffer->nbh),
							    STUN_ATTRIBUTE_MESSAGE_INTEGRITY);

	if(!sar) {
		*err_code = 401;
		return create_challenge_response(ss,tid,resp_constructed,err_code,reason,nbh,method);
	}

	{
		int sarlen = stun_attr_get_len(sar);

		switch(sarlen) {
		case SHA1SIZEBYTES:
			break;
		case SHA256SIZEBYTES:
		case SHA384SIZEBYTES:
		case SHA512SIZEBYTES:
		default:
			*err_code = 401;
			return create_challenge_response(ss,tid,resp_constructed,err_code,reason,nbh,method);
		};
	}

	{

		/* REALM ATTR: */

		sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(in_buffer->nbh),
					  ioa_network_buffer_get_size(in_buffer->nbh),
					  STUN_ATTRIBUTE_REALM);

		if(!sar) {
			*err_code = 400;
			return -1;
		}

		alen = min((size_t)stun_attr_get_len(sar),sizeof(realm)-1);
		ns_bcopy(stun_attr_get_value(sar),realm,alen);
		realm[alen]=0;

		if(method == STUN_METHOD_CONNECTION_BIND) {

			get_realm_options_by_name((char *)realm, &(ss->realm_options));

		} else if(strcmp((char*)realm, (char*)(ss->realm_options.name))) {
			if(!(ss->oauth)){
				if(method == STUN_METHOD_ALLOCATE) {
					*err_code = 437;
					*reason = (const u08bits*)"Allocation mismatch: wrong credentials: the realm value is incorrect";
				} else {
					*err_code = 441;
					*reason = (const u08bits*)"Wrong credentials: the realm value is incorrect";
				}
				return -1;
			} else {
				ns_bcopy(ss->realm_options.name,realm,sizeof(ss->realm_options.name));
			}
		}
	}

	/* USERNAME ATTR: */

	sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(in_buffer->nbh),
					  ioa_network_buffer_get_size(in_buffer->nbh),
					  STUN_ATTRIBUTE_USERNAME);

	if(!sar) {
		*err_code = 400;
		return -1;
	}

	alen = min((size_t)stun_attr_get_len(sar),sizeof(usname)-1);
	ns_bcopy(stun_attr_get_value(sar),usname,alen);
	usname[alen]=0;

	if(!is_secure_username(usname)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: wrong username: %s\n", __FUNCTION__, (char*)usname);
		usname[0]=0;
		*err_code = 400;
		return -1;
	} else if(ss->username[0]) {
		if(strcmp((char*)ss->username,(char*)usname)) {
			if(ss->oauth) {
				ss->hmackey_set = 0;
				STRCPY(ss->username,usname);
			} else {
				if(method == STUN_METHOD_ALLOCATE) {
					*err_code = 437;
					*reason = (const u08bits*)"Allocation mismatch: wrong credentials";
				} else {
					*err_code = 441;
				}
				return -1;
			}
		}
	} else {
		STRCPY(ss->username,usname);
	}

	{
		/* NONCE ATTR: */

		sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(in_buffer->nbh),
					  ioa_network_buffer_get_size(in_buffer->nbh),
					  STUN_ATTRIBUTE_NONCE);

		if(!sar) {
			*err_code = 400;
			return -1;
		}

		alen = min((size_t)stun_attr_get_len(sar),sizeof(nonce)-1);
		ns_bcopy(stun_attr_get_value(sar),nonce,alen);
		nonce[alen]=0;

		/* Stale Nonce check: */

		if(new_nonce) {
			*err_code = 438;
			*reason = (const u08bits*)"Wrong nonce";
			return create_challenge_response(ss,tid,resp_constructed,err_code,reason,nbh,method);
		}

		if(strcmp((s08bits*)ss->nonce,(s08bits*)nonce)) {
			*err_code = 438;
			*reason = (const u08bits*)"Stale nonce";
			return create_challenge_response(ss,tid,resp_constructed,err_code,reason,nbh,method);
		}
	}

	/* Password */
	if(!(ss->hmackey_set) && (ss->pwd[0] == 0)) {
		if(can_resume) {
			(server->userkeycb)(server->id, server->ct, server->oauth, &(ss->oauth), usname, realm, resume_processing_after_username_check, in_buffer, ss->id, postpone_reply);
			if(*postpone_reply) {
				return 0;
			}
		}

		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"%s: Cannot find credentials of user <%s>\n",
				__FUNCTION__, (char*)usname);
		*err_code = 401;
		return create_challenge_response(ss,tid,resp_constructed,err_code,reason,nbh,method);
	}

	/* Check integrity */
	if(stun_check_message_integrity_by_key_str(server->ct,ioa_network_buffer_data(in_buffer->nbh),
					  ioa_network_buffer_get_size(in_buffer->nbh),
					  ss->hmackey,
					  ss->pwd,
					  SHATYPE_DEFAULT)<1) {

		if(can_resume) {
			(server->userkeycb)(server->id, server->ct, server->oauth, &(ss->oauth), usname, realm, resume_processing_after_username_check, in_buffer, ss->id, postpone_reply);
			if(*postpone_reply) {
				return 0;
			}
		}

		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"%s: user %s credentials are incorrect\n",
				__FUNCTION__, (char*)usname);
		*err_code = 401;
		return create_challenge_response(ss,tid,resp_constructed,err_code,reason,nbh,method);
	}

	*message_integrity = 1;

	return 0;
}

//<<== AUTH

static void set_alternate_server(turn_server_addrs_list_t *asl, const ioa_addr *local_addr, size_t *counter, u16bits method, stun_tid *tid, int *resp_constructed, int *err_code, const u08bits **reason, ioa_network_buffer_handle nbh)
{
	if(asl && asl->size && local_addr) {

		size_t i;

		/* to prevent indefinite cycle: */

		for(i=0;i<asl->size;++i) {
			ioa_addr *addr = &(asl->addrs[i]);
			if(addr_eq(addr,local_addr))
				return;
		}

		for(i=0;i<asl->size;++i) {
			if(*counter>=asl->size)
				*counter = 0;
			ioa_addr *addr = &(asl->addrs[*counter]);
			*counter +=1;
			if(addr->ss.sa_family == local_addr->ss.sa_family) {

				*err_code = 300;

				size_t len = ioa_network_buffer_get_size(nbh);
				stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
				*resp_constructed = 1;
				stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_ALTERNATE_SERVER, addr);
				ioa_network_buffer_set_size(nbh,len);

				return;
			}
		}
	}
}

static int handle_turn_command(turn_turnserver *server, ts_ur_super_session *ss, ioa_net_data *in_buffer, ioa_network_buffer_handle nbh, int *resp_constructed, int can_resume)
{

	stun_tid tid;
	int err_code = 0;
	const u08bits *reason = NULL;
	int no_response = 0;
	int message_integrity = 0;

	if(!(ss->client_socket))
		return -1;

	u16bits unknown_attrs[MAX_NUMBER_OF_UNKNOWN_ATTRS];
	u16bits ua_num = 0;
	u16bits method = stun_get_method_str(ioa_network_buffer_data(in_buffer->nbh), 
					     ioa_network_buffer_get_size(in_buffer->nbh));

	*resp_constructed = 0;

	stun_tid_from_message_str(ioa_network_buffer_data(in_buffer->nbh), 
				  ioa_network_buffer_get_size(in_buffer->nbh), 
				  &tid);

	if (stun_is_request_str(ioa_network_buffer_data(in_buffer->nbh), 
				ioa_network_buffer_get_size(in_buffer->nbh))) {

		if((method == STUN_METHOD_BINDING) && (*(server->no_stun))) {

			no_response = 1;
			if(server->verbose) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"%s: STUN method 0x%x ignored\n",
									__FUNCTION__, (unsigned int)method);
			}

		} else if((method != STUN_METHOD_BINDING) && (*(server->stun_only))) {

				no_response = 1;
				if(server->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: STUN method 0x%x ignored\n",
										__FUNCTION__, (unsigned int)method);
				}

		} else if((method != STUN_METHOD_BINDING) || (*(server->secure_stun))) {

			if(method == STUN_METHOD_ALLOCATE) {

				allocation *a = get_allocation_ss(ss);
				if(is_allocation_valid(a)) {
					if(!stun_tid_equals(&(a->tid), &tid)) {
						err_code = 437;
						reason = (const u08bits *)"Mismatched allocation: wrong transaction ID";
					}
				}

				if(!err_code) {
					SOCKET_TYPE cst = get_ioa_socket_type(ss->client_socket);
					turn_server_addrs_list_t *asl = server->alternate_servers_list;

					if(((cst == UDP_SOCKET)||(cst == DTLS_SOCKET)) && server->self_udp_balance &&
							server->aux_servers_list && server->aux_servers_list->size) {
						asl = server->aux_servers_list;
					} else if(((cst == TLS_SOCKET) || (cst == DTLS_SOCKET) ||(cst == TLS_SCTP_SOCKET)) &&
							server->tls_alternate_servers_list && server->tls_alternate_servers_list->size) {
						asl = server->tls_alternate_servers_list;
					}

					if(asl && asl->size) {
						turn_mutex_lock(&(asl->m));
						set_alternate_server(asl,get_local_addr_from_ioa_socket(ss->client_socket),&(server->as_counter),method,&tid,resp_constructed,&err_code,&reason,nbh);
						turn_mutex_unlock(&(asl->m));
					}
				}
			}

			/* check that the realm is the same as in the original request */
			if(ss->origin_set) {
				stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
					ioa_network_buffer_get_size(in_buffer->nbh));

				int origin_found = 0;
				int norigins = 0;

				while(sar && !origin_found) {
					if(stun_attr_get_type(sar) == STUN_ATTRIBUTE_ORIGIN) {
						int sarlen = stun_attr_get_len(sar);
						if(sarlen>0) {
							++norigins;
							char *o = (char*)turn_malloc(sarlen+1);
							ns_bcopy(stun_attr_get_value(sar),o,sarlen);
							o[sarlen]=0;
							char *corigin = (char*)turn_malloc(STUN_MAX_ORIGIN_SIZE+1);
							corigin[0]=0;
							if(get_canonic_origin(o,corigin,STUN_MAX_ORIGIN_SIZE)<0) {
								TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
									"%s: Wrong origin format: %s\n",
									__FUNCTION__, o);
							}
							if(!strncmp(ss->origin,corigin,STUN_MAX_ORIGIN_SIZE)) {
								origin_found = 1;
							}
							turn_free(corigin,sarlen+1);
							turn_free(o,sarlen+1);
						}
					}
					sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
							ioa_network_buffer_get_size(in_buffer->nbh), sar);
				}

				if(server->check_origin && *(server->check_origin)) {
					if(ss->origin[0]) {
						if(!origin_found) {
							err_code = 441;
							reason = (const u08bits *)"The origin attribute does not match the initial session origin value";
							if(server->verbose) {
								char smethod[129];
								stun_method_str(method,smethod);
								log_method(ss, smethod, err_code, reason);
							}
						}
					} else if(norigins > 0){
						err_code = 441;
						reason = (const u08bits *)"The origin attribute is empty, does not match the initial session origin value";
						if(server->verbose) {
							char smethod[129];
							stun_method_str(method,smethod);
							log_method(ss, smethod, err_code, reason);
						}
					}
				}
			}

			/* get the initial origin value */
			if(!err_code && !(ss->origin_set) && (method == STUN_METHOD_ALLOCATE)) {

				stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh),
					ioa_network_buffer_get_size(in_buffer->nbh));

				int origin_found = 0;

				while(sar && !origin_found) {
					if(stun_attr_get_type(sar) == STUN_ATTRIBUTE_ORIGIN) {
						int sarlen = stun_attr_get_len(sar);
						if(sarlen>0) {
							char *o = (char*)turn_malloc(sarlen+1);
							ns_bcopy(stun_attr_get_value(sar),o,sarlen);
							o[sarlen]=0;
							char *corigin = (char*)turn_malloc(STUN_MAX_ORIGIN_SIZE+1);
							corigin[0]=0;
							if(get_canonic_origin(o,corigin,STUN_MAX_ORIGIN_SIZE)<0) {
								TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
									"%s: Wrong origin format: %s\n",
									__FUNCTION__, o);
							}
							strncpy(ss->origin,corigin,STUN_MAX_ORIGIN_SIZE);
							turn_free(corigin,sarlen+1);
							turn_free(o,sarlen+1);
							origin_found = get_realm_options_by_origin(ss->origin,&(ss->realm_options));
						}
					}
					sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh),
							ioa_network_buffer_get_size(in_buffer->nbh), sar);
				}

				ss->origin_set = 1;
			}

			if(!err_code && !(*resp_constructed) && !no_response) {
				if(method == STUN_METHOD_CONNECTION_BIND) {
					;
				} else if(!(*(server->mobility)) || (method != STUN_METHOD_REFRESH) || is_allocation_valid(get_allocation_ss(ss))) {
					int postpone_reply = 0;
					check_stun_auth(server, ss, &tid, resp_constructed, &err_code, &reason, in_buffer, nbh, method, &message_integrity, &postpone_reply, can_resume);
					if(postpone_reply)
						no_response = 1;
				}
			}
		}

		if (!err_code && !(*resp_constructed) && !no_response) {

			switch (method){

			case STUN_METHOD_ALLOCATE:

			{
				handle_turn_allocate(server, ss, &tid, resp_constructed, &err_code, &reason,
							unknown_attrs, &ua_num, in_buffer, nbh);

				if(server->verbose) {
				  log_method(ss, "ALLOCATE", err_code, reason);
				}

				break;
			}

			case STUN_METHOD_CONNECT:

				handle_turn_connect(server, ss, &tid, &err_code, &reason,
							unknown_attrs, &ua_num, in_buffer);

				if(server->verbose) {
				  log_method(ss, "CONNECT", err_code, reason);
				}

				if(!err_code)
					no_response = 1;

				break;

			case STUN_METHOD_CONNECTION_BIND:

				handle_turn_connection_bind(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh, message_integrity, can_resume);

				if(server->verbose && err_code) {
				  log_method(ss, "CONNECTION_BIND", err_code, reason);
				}

				break;

			case STUN_METHOD_REFRESH:

				handle_turn_refresh(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh, message_integrity,
								&no_response, can_resume);

				if(server->verbose) {
				  log_method(ss, "REFRESH", err_code, reason);
				}
				break;

			case STUN_METHOD_CHANNEL_BIND:

				handle_turn_channel_bind(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);

				if(server->verbose) {
				  log_method(ss, "CHANNEL_BIND", err_code, reason);
				}
				break;

			case STUN_METHOD_CREATE_PERMISSION:

				handle_turn_create_permission(server, ss, &tid, resp_constructed, &err_code, &reason,
								unknown_attrs, &ua_num, in_buffer, nbh);

				if(server->verbose) {
				  log_method(ss, "CREATE_PERMISSION", err_code, reason);
				}
				break;

			case STUN_METHOD_BINDING:

			{
				int origin_changed=0;
				ioa_addr response_origin;
				int dest_changed=0;
				ioa_addr response_destination;

				handle_turn_binding(server, ss, &tid, resp_constructed, &err_code, &reason,
							unknown_attrs, &ua_num, in_buffer, nbh,
							&origin_changed, &response_origin,
							&dest_changed, &response_destination,
							0, 0);

				if(server->verbose) {
				  log_method(ss, "BINDING", err_code, reason);
				}

				if(*resp_constructed && !err_code && (origin_changed || dest_changed)) {

					if (server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "RFC 5780 request successfully processed\n");
					}

					{
						static const u08bits *field = (const u08bits *) TURN_SOFTWARE;
						static const size_t fsz = sizeof(TURN_SOFTWARE)-1;
						size_t len = ioa_network_buffer_get_size(nbh);
						stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
						ioa_network_buffer_set_size(nbh, len);
					}

					send_turn_message_to(server, nbh, &response_origin, &response_destination);

					no_response = 1;
				}

				break;
			}
			default:
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unsupported STUN request received, method 0x%x\n",(unsigned int)method);
			};
		}

	} else if (stun_is_indication_str(ioa_network_buffer_data(in_buffer->nbh), 
					  ioa_network_buffer_get_size(in_buffer->nbh))) {

		no_response = 1;
		int postpone = 0;

		if (!postpone && !err_code) {

			switch (method){

			case STUN_METHOD_BINDING:
				//ICE ?
				break;

			case STUN_METHOD_SEND:

				handle_turn_send(server, ss, &err_code, &reason, unknown_attrs, &ua_num, in_buffer);

				if(eve(server->verbose)) {
				  log_method(ss, "SEND", err_code, reason);
				}

				break;

			case STUN_METHOD_DATA:

				err_code = 403;

				if(eve(server->verbose)) {
				  log_method(ss, "DATA", err_code, reason);
				}

				break;

			default:
				if (server->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unsupported STUN indication received: method 0x%x\n",(unsigned int)method);
				}
			}
		};

	} else {

		no_response = 1;

		if (server->verbose) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Wrong STUN message received\n");
		}
	}

	if(ss->to_be_closed || !(ss->client_socket) || ioa_socket_tobeclosed(ss->client_socket))
		return 0;

	if (ua_num > 0) {

		err_code = 420;

		size_t len = ioa_network_buffer_get_size(nbh);
		stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, err_code, NULL, &tid);

		stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES, (const u08bits*) unknown_attrs, (ua_num
						* 2));

		ioa_network_buffer_set_size(nbh,len);

		*resp_constructed = 1;
	}

	if (!no_response) {

		if (!(*resp_constructed)) {

			if (!err_code)
				err_code = 400;

			size_t len = ioa_network_buffer_get_size(nbh);
			stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, err_code, reason, &tid);
			ioa_network_buffer_set_size(nbh,len);
			*resp_constructed = 1;
		}

		{
			static const u08bits *field = (const u08bits *) TURN_SOFTWARE;
			static const size_t fsz = sizeof(TURN_SOFTWARE)-1;
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
			ioa_network_buffer_set_size(nbh, len);
		}

		if(message_integrity) {
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_integrity_str(server->ct,ioa_network_buffer_data(nbh),&len,ss->hmackey,ss->pwd,SHATYPE_DEFAULT);
			ioa_network_buffer_set_size(nbh,len);
		}

		if(err_code) {
			if(server->verbose) {
			  log_method(ss, "message", err_code, reason);
			}
		}

	} else {
		*resp_constructed = 0;
	}

	return 0;
}

static int handle_old_stun_command(turn_turnserver *server, ts_ur_super_session *ss, ioa_net_data *in_buffer, ioa_network_buffer_handle nbh, int *resp_constructed, u32bits cookie)
{

	stun_tid tid;
	int err_code = 0;
	const u08bits *reason = NULL;
	int no_response = 0;

	u16bits unknown_attrs[MAX_NUMBER_OF_UNKNOWN_ATTRS];
	u16bits ua_num = 0;
	u16bits method = stun_get_method_str(ioa_network_buffer_data(in_buffer->nbh),
					     ioa_network_buffer_get_size(in_buffer->nbh));

	*resp_constructed = 0;

	stun_tid_from_message_str(ioa_network_buffer_data(in_buffer->nbh),
				  ioa_network_buffer_get_size(in_buffer->nbh),
				  &tid);

	if (stun_is_request_str(ioa_network_buffer_data(in_buffer->nbh),
				ioa_network_buffer_get_size(in_buffer->nbh))) {

		if(method != STUN_METHOD_BINDING) {
			no_response = 1;
			if(server->verbose) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"%s: OLD STUN method 0x%x ignored\n",
							__FUNCTION__, (unsigned int)method);
			}
		}

		if (!err_code && !(*resp_constructed) && !no_response) {

			int origin_changed=0;
			ioa_addr response_origin;
			int dest_changed=0;
			ioa_addr response_destination;

			handle_turn_binding(server, ss, &tid, resp_constructed, &err_code, &reason,
						unknown_attrs, &ua_num, in_buffer, nbh,
						&origin_changed, &response_origin,
						&dest_changed, &response_destination,
						cookie,1);

			if(server->verbose) {
			  log_method(ss, "OLD BINDING", err_code, reason);
			}

			if(*resp_constructed && !err_code && (origin_changed || dest_changed)) {

				if (server->verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "RFC3489 CHANGE request successfully processed\n");
				}

				{
					size_t newsz = (((sizeof(TURN_SOFTWARE))>>2) + 1)<<2;
					u08bits software[120];
					if(newsz>sizeof(software))
						newsz = sizeof(software);
					ns_bcopy(TURN_SOFTWARE,software,newsz);
					size_t len = ioa_network_buffer_get_size(nbh);
					stun_attr_add_str(ioa_network_buffer_data(nbh), &len, OLD_STUN_ATTRIBUTE_SERVER, software, newsz);
					ioa_network_buffer_set_size(nbh, len);
				}

				send_turn_message_to(server, nbh, &response_origin, &response_destination);

				no_response = 1;
			}
		}
	} else {

		no_response = 1;

		if (server->verbose) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Wrong OLD STUN message received\n");
		}
	}

	if (ua_num > 0) {

		err_code = 420;

		size_t len = ioa_network_buffer_get_size(nbh);
		old_stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, err_code, NULL, &tid, cookie);

		stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES, (const u08bits*) unknown_attrs, (ua_num * 2));

		ioa_network_buffer_set_size(nbh,len);

		*resp_constructed = 1;
	}

	if (!no_response) {

		if (!(*resp_constructed)) {

			if (!err_code)
				err_code = 400;

			size_t len = ioa_network_buffer_get_size(nbh);
			old_stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, err_code, reason, &tid, cookie);
			ioa_network_buffer_set_size(nbh,len);
			*resp_constructed = 1;
		}

		{
			size_t newsz = (((sizeof(TURN_SOFTWARE))>>2) + 1)<<2;
			u08bits software[120];
			if(newsz>sizeof(software))
				newsz = sizeof(software);
			ns_bcopy(TURN_SOFTWARE,software,newsz);
			size_t len = ioa_network_buffer_get_size(nbh);
			stun_attr_add_str(ioa_network_buffer_data(nbh), &len, OLD_STUN_ATTRIBUTE_SERVER, software, newsz);
			ioa_network_buffer_set_size(nbh, len);
		}

		if(err_code) {
			if(server->verbose) {
			  log_method(ss, "OLD STUN message", err_code, reason);
			}
		}

	} else {
		*resp_constructed = 0;
	}

	return 0;
}

//////////////////////////////////////////////////////////////////

static int write_to_peerchannel(ts_ur_super_session* ss, u16bits chnum, ioa_net_data *in_buffer) {

	int rc = 0;

	if (ss && (in_buffer->recv_ttl!=0)) {

		allocation* a = get_allocation_ss(ss);

		if (is_allocation_valid(a)) {

			ch_info* chn = allocation_get_ch_info(a, chnum);

			if (!chn)
				return -1;

			/* Channel packets are always sent with DF=0: */
			set_df_on_ioa_socket(get_relay_socket_ss(ss, chn->peer_addr.ss.sa_family), 0);

			ioa_network_buffer_handle nbh = in_buffer->nbh;

			ioa_network_buffer_add_offset_size(in_buffer->nbh, STUN_CHANNEL_HEADER_LENGTH, 0, ioa_network_buffer_get_size(in_buffer->nbh)-STUN_CHANNEL_HEADER_LENGTH);

			ioa_network_buffer_header_init(nbh);

			rc = send_data_from_ioa_socket_nbh(get_relay_socket_ss(ss, chn->peer_addr.ss.sa_family), &(chn->peer_addr), nbh, in_buffer->recv_ttl-1, in_buffer->recv_tos, NULL);
			in_buffer->nbh = NULL;
		}
	}

	return rc;
}

static void client_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *data, void *arg, int can_resume);
static void peer_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *data, void *arg, int can_resume);

/////////////// Client actions /////////////////

int shutdown_client_connection(turn_turnserver *server, ts_ur_super_session *ss, int force, const char* reason) {

	FUNCSTART;

	if (!ss)
		return -1;

	report_turn_session_info(server,ss,1);
	dec_quota(ss);
	dec_bps(ss);

	allocation* alloc = get_allocation_ss(ss);
	if (!is_allocation_valid(alloc)) {
		force = 1;
	}

	if(!force && ss->is_mobile) {

		if (ss->client_socket && server->verbose) {

			char sraddr[129]="\0";
			char sladdr[129]="\0";
			addr_to_string(get_remote_addr_from_ioa_socket(ss->client_socket),(u08bits*)sraddr);
			addr_to_string(get_local_addr_from_ioa_socket(ss->client_socket),(u08bits*)sladdr);

			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "session %018llu: closed (1st stage), user <%s> realm <%s> origin <%s>, local %s, remote %s, reason: %s\n",(unsigned long long)(ss->id),(char*)ss->username,(char*)ss->realm_options.name,(char*)ss->origin, sladdr,sraddr,reason);
		}

		IOA_CLOSE_SOCKET(ss->client_socket);

		FUNCEND;

		return 0;
	}

	if (eve(server->verbose)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"closing session 0x%lx, client socket 0x%lx (socket session=0x%lx)\n",
				(long) ss,
				(long) ss->client_socket,
				(long)get_ioa_socket_session(ss->client_socket));
	}

	if (server->disconnect)
		server->disconnect(ss);

	if (server->verbose) {

		char sraddr[129]="\0";
		char sladdr[129]="\0";
		addr_to_string(get_remote_addr_from_ioa_socket(ss->client_socket),(u08bits*)sraddr);
		addr_to_string(get_local_addr_from_ioa_socket(ss->client_socket),(u08bits*)sladdr);

		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "session %018llu: closed (2nd stage), user <%s> realm <%s> origin <%s>, local %s, remote %s, reason: %s\n",
					(unsigned long long)(ss->id), (char*)ss->username,(char*)ss->realm_options.name,(char*)ss->origin, sladdr,sraddr, reason);
	}

	IOA_CLOSE_SOCKET(ss->client_socket);
	{
		int i;
		for(i=0;i<ALLOC_PROTOCOLS_NUMBER;++i) {
			IOA_CLOSE_SOCKET(ss->alloc.relay_sessions[i].s);
		}
	}

	turn_server_remove_all_from_ur_map_ss(ss);

	FUNCEND;

	return 0;
}

static void client_to_be_allocated_timeout_handler(ioa_engine_handle e,
		void *arg) {

	if (!arg)
		return;

	UNUSED_ARG(e);

	ts_ur_super_session* ss = (ts_ur_super_session*) arg;

	turn_turnserver* server = (turn_turnserver*) (ss->server);

	if (!server)
		return;

	FUNCSTART;

	int to_close = 0;

	ioa_socket_handle s = ss->client_socket;

	if(!s || ioa_socket_tobeclosed(s)) {
		to_close = 1;
	} else if(get_ioa_socket_app_type(s) == HTTPS_CLIENT_SOCKET) {
		;
	} else {
		ioa_socket_handle rs4 = ss->alloc.relay_sessions[ALLOC_IPV4_INDEX].s;
		ioa_socket_handle rs6 = ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].s;
		if((!rs4 || ioa_socket_tobeclosed(rs4)) && (!rs6 || ioa_socket_tobeclosed(rs6))) {
			to_close = 1;
		} else if(ss->client_socket == NULL) {
			to_close = 1;
		} else if(!(ss->alloc.relay_sessions[ALLOC_IPV4_INDEX].lifetime_ev) &&
				!(ss->alloc.relay_sessions[ALLOC_IPV6_INDEX].lifetime_ev)) {
			to_close = 1;
		} else if(!(ss->to_be_allocated_timeout_ev)) {
			to_close = 1;
		}
	}

	if(to_close) {
		IOA_EVENT_DEL(ss->to_be_allocated_timeout_ev);
		shutdown_client_connection(server, ss, 1, "allocation watchdog determined stale session state");
	}

	FUNCEND;
}

static int write_client_connection(turn_turnserver *server, ts_ur_super_session* ss, ioa_network_buffer_handle nbh, int ttl, int tos) {

	FUNCSTART;

	if (!(ss->client_socket)) {
		ioa_network_buffer_delete(server->e, nbh);
		FUNCEND;
		return -1;
	} else {

		if (eve(server->verbose)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"%s: prepare to write to s 0x%lx\n", __FUNCTION__,
				(long) (ss->client_socket));
		}

		int skip = 0;
		int ret = send_data_from_ioa_socket_nbh(ss->client_socket, NULL, nbh, ttl, tos, &skip);

		if(!skip) {
			++(ss->sent_packets);
			ss->sent_bytes += (u32bits)ioa_network_buffer_get_size(nbh);
			turn_report_session_usage(ss);
		}

		FUNCEND;
		return ret;
	}
}

static void client_ss_allocation_timeout_handler(ioa_engine_handle e, void *arg) {

	UNUSED_ARG(e);

	if (!arg)
		return;

	relay_endpoint_session *rsession = (relay_endpoint_session*)arg;

	if(!(rsession->s))
		return;

	ts_ur_super_session* ss = get_ioa_socket_session(rsession->s);

	if (!ss)
		return;

	allocation* a =  get_allocation_ss(ss);

	turn_turnserver* server = (turn_turnserver*) (ss->server);

	if (!server) {
		clear_allocation(a);
		return;
	}

	FUNCSTART;

	int family = get_ioa_socket_address_family(rsession->s);

	set_allocation_family_invalid(a,family);

	if(!get_relay_socket(a, AF_INET) && !get_relay_socket(a, AF_INET6)) {
		shutdown_client_connection(server, ss, 0, "allocation timeout");
	}

	FUNCEND;
}

static int create_relay_connection(turn_turnserver* server,
				   ts_ur_super_session *ss, u32bits lifetime,
				   int address_family, u08bits transport,
				   int even_port, u64bits in_reservation_token, u64bits *out_reservation_token,
				   int *err_code, const u08bits **reason,
				   accept_cb acb) {

	if (server && ss && ss->client_socket && !ioa_socket_tobeclosed(ss->client_socket)) {

		allocation* a = get_allocation_ss(ss);
		relay_endpoint_session* newelem = NULL;
		ioa_socket_handle rtcp_s = NULL;

		if (in_reservation_token) {

			ioa_socket_handle s = NULL;

			if ((get_ioa_socket_from_reservation(server->e, in_reservation_token,&s) < 0)||
				!s ||
				ioa_socket_tobeclosed(s)) {

				IOA_CLOSE_SOCKET(s);
				*err_code = 404;
				*reason = (const u08bits *)"Cannot find reserved socket";
				return -1;
			}

			int family = get_ioa_socket_address_family(s);

			newelem = get_relay_session_ss(ss,family);

			if(newelem->s != s) {

				IOA_CLOSE_SOCKET(newelem->s);

				ns_bzero(newelem, sizeof(relay_endpoint_session));
				newelem->s = s;
			}

			addr_debug_print(server->verbose, get_local_addr_from_ioa_socket(newelem->s), "Local relay addr (RTCP)");

		} else {

			newelem = get_relay_session_ss(ss,get_family(address_family));

			IOA_CLOSE_SOCKET(newelem->s);

			ns_bzero(newelem, sizeof(relay_endpoint_session));
			newelem->s = NULL;

			int res = create_relay_ioa_sockets(server->e,
							ss->client_socket,
							address_family, transport,
							even_port, &(newelem->s), &rtcp_s, out_reservation_token,
							err_code, reason, acb, ss);
			if (res < 0) {
				if(!(*err_code))
					*err_code = 508;
				if(!(*reason))
					*reason = (const u08bits *)"Cannot create socket";
				IOA_CLOSE_SOCKET(newelem->s);
				IOA_CLOSE_SOCKET(rtcp_s);
				return -1;
			}
		}

		if (newelem->s == NULL) {
			IOA_CLOSE_SOCKET(rtcp_s);
			*err_code = 508;
			*reason = (const u08bits *)"Cannot create relay socket";
			return -1;
		}

		if (rtcp_s) {
			if (out_reservation_token && *out_reservation_token) {
				/* OK */
			} else {
				IOA_CLOSE_SOCKET(newelem->s);
				IOA_CLOSE_SOCKET(rtcp_s);
				*err_code = 500;
				*reason = (const u08bits *)"Wrong reservation tokens (internal error)";
				return -1;
			}
		}

		/* RFC6156: do not use DF when IPv6 is involved: */
		if((get_ioa_socket_address_family(newelem->s) == AF_INET6) ||
		   (get_ioa_socket_address_family(ss->client_socket) == AF_INET6))
			set_do_not_use_df(newelem->s);

		if(get_ioa_socket_type(newelem->s) != TCP_SOCKET) {
			if(register_callback_on_ioa_socket(server->e, newelem->s, IOA_EV_READ,peer_input_handler, ss, 0)<0) {
				return -1;
			}
		}

		if (lifetime<1)
			lifetime = STUN_DEFAULT_ALLOCATE_LIFETIME;
		else if(lifetime>STUN_MAX_ALLOCATE_LIFETIME)
			lifetime = STUN_MAX_ALLOCATE_LIFETIME;

		ioa_timer_handle ev = set_ioa_timer(server->e, lifetime, 0,
				client_ss_allocation_timeout_handler, newelem, 0,
				"client_ss_allocation_timeout_handler");
		set_allocation_lifetime_ev(a, server->ctime + lifetime, ev, get_ioa_socket_address_family(newelem->s));

		set_ioa_socket_session(newelem->s, ss);
	}

	return 0;
}

static int refresh_relay_connection(turn_turnserver* server,
		ts_ur_super_session *ss, u32bits lifetime, int even_port,
		u64bits in_reservation_token, u64bits *out_reservation_token,
		int *err_code, int family) {

	UNUSED_ARG(even_port);
	UNUSED_ARG(in_reservation_token);
	UNUSED_ARG(out_reservation_token);
	UNUSED_ARG(err_code);

	allocation* a = get_allocation_ss(ss);

	if (server && ss && is_allocation_valid(a)) {

		if (lifetime < 1) {
			lifetime = 1;
		}

		ioa_timer_handle ev = set_ioa_timer(server->e, lifetime, 0,
				client_ss_allocation_timeout_handler, get_relay_session(a,family), 0,
				"refresh_client_ss_allocation_timeout_handler");

		set_allocation_lifetime_ev(a, server->ctime + lifetime, ev, family);

		return 0;

	} else {
		return -1;
	}
}

static int read_client_connection(turn_turnserver *server,
				  	  	  	  	  ts_ur_super_session *ss, ioa_net_data *in_buffer,
				  	  	  	  	  int can_resume, int count_usage) {

	FUNCSTART;

	if (!server || !ss || !in_buffer || !(ss->client_socket) || ss->to_be_closed || ioa_socket_tobeclosed(ss->client_socket)) {
		FUNCEND;
		return -1;
	}

	int ret = (int)ioa_network_buffer_get_size(in_buffer->nbh);
	if (ret < 0) {
		FUNCEND;
		return -1;
	}

	if(count_usage) {
		++(ss->received_packets);
		ss->received_bytes += (u32bits)ioa_network_buffer_get_size(in_buffer->nbh);
		turn_report_session_usage(ss);
	}

	if (eve(server->verbose)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
			      "%s: data.buffer=0x%lx, data.len=%ld\n", __FUNCTION__,
			      (long)ioa_network_buffer_data(in_buffer->nbh), 
			      (long)ioa_network_buffer_get_size(in_buffer->nbh));
	}

	u16bits chnum = 0;
	u32bits old_stun_cookie = 0;

	size_t blen = ioa_network_buffer_get_size(in_buffer->nbh);
	size_t orig_blen = blen;
	SOCKET_TYPE st = get_ioa_socket_type(ss->client_socket);
	SOCKET_APP_TYPE sat = get_ioa_socket_app_type(ss->client_socket);
	int is_padding_mandatory = is_stream_socket(st);

	if(sat == HTTP_CLIENT_SOCKET) {

		if(server->verbose) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: HTTP connection input: %s\n", __FUNCTION__, (char*)ioa_network_buffer_data(in_buffer->nbh));
		}

		handle_http_echo(ss->client_socket);

	} else if(sat == HTTPS_CLIENT_SOCKET) {

		//???

	} else if (stun_is_channel_message_str(ioa_network_buffer_data(in_buffer->nbh),
					&blen,
					&chnum,
					is_padding_mandatory)) {

		if(ss->is_tcp_relay) {
			//Forbidden
			FUNCEND;
			return -1;
		}

		int rc = 0;

		if(blen<=orig_blen) {
			ioa_network_buffer_set_size(in_buffer->nbh,blen);
			rc = write_to_peerchannel(ss, chnum, in_buffer);
		}

		if (eve(server->verbose)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: wrote to peer %d bytes\n",
					__FUNCTION__, (int) rc);
		}

		FUNCEND;
		return 0;

	} else if (stun_is_command_message_full_check_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh), 0, &(ss->enforce_fingerprints))) {

		ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
		int resp_constructed = 0;

		u16bits method = stun_get_method_str(ioa_network_buffer_data(in_buffer->nbh),
						ioa_network_buffer_get_size(in_buffer->nbh));

		handle_turn_command(server, ss, in_buffer, nbh, &resp_constructed, can_resume);

		if((method != STUN_METHOD_BINDING) && (method != STUN_METHOD_SEND))
			report_turn_session_info(server,ss,0);

		if(ss->to_be_closed || ioa_socket_tobeclosed(ss->client_socket)) {
			FUNCEND;
			ioa_network_buffer_delete(server->e, nbh);
			return 0;
		}

		if (resp_constructed) {

			if ((server->fingerprint) || ss->enforce_fingerprints) {
				size_t len = ioa_network_buffer_get_size(nbh);
				if (stun_attr_add_fingerprint_str(ioa_network_buffer_data(nbh), &len) < 0) {
					FUNCEND	;
					ioa_network_buffer_delete(server->e, nbh);
					return -1;
				}
				ioa_network_buffer_set_size(nbh, len);
			}

			int ret = write_client_connection(server, ss, nbh, TTL_IGNORE, TOS_IGNORE);

			FUNCEND	;
			return ret;
		} else {
			ioa_network_buffer_delete(server->e, nbh);
			return 0;
		}

	} else if (old_stun_is_command_message_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh), &old_stun_cookie) && !(*(server->no_stun))) {

		ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
		int resp_constructed = 0;

		handle_old_stun_command(server, ss, in_buffer, nbh, &resp_constructed, old_stun_cookie);

		if (resp_constructed) {

			int ret = write_client_connection(server, ss, nbh, TTL_IGNORE, TOS_IGNORE);

			FUNCEND	;
			return ret;
		} else {
			ioa_network_buffer_delete(server->e, nbh);
			return 0;
		}

	} else {
		SOCKET_TYPE st = get_ioa_socket_type(ss->client_socket);
		if(is_stream_socket(st)) {
			if(is_http((char*)ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh))) {
				const char *proto = "HTTP";
				ioa_network_buffer_data(in_buffer->nbh)[ioa_network_buffer_get_size(in_buffer->nbh)] = 0;
				if(st==TLS_SOCKET) {
					proto = "HTTPS";
					set_ioa_socket_app_type(ss->client_socket,HTTPS_CLIENT_SOCKET);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: %s (%s %s) request: %s\n", __FUNCTION__, proto, get_ioa_socket_cipher(ss->client_socket), get_ioa_socket_ssl_method(ss->client_socket), (char*)ioa_network_buffer_data(in_buffer->nbh));
					if(server->send_https_socket) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s socket to be detached: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)ss->client_socket, get_ioa_socket_type(ss->client_socket), get_ioa_socket_app_type(ss->client_socket));
						ioa_socket_handle new_s = detach_ioa_socket(ss->client_socket);
						if(new_s) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s new detached socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)new_s, get_ioa_socket_type(new_s), get_ioa_socket_app_type(new_s));
							server->send_https_socket(new_s);
						}
						ss->to_be_closed = 1;
					}
				} else {
					set_ioa_socket_app_type(ss->client_socket,HTTP_CLIENT_SOCKET);
					if(server->verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: %s request: %s\n", __FUNCTION__, proto, (char*)ioa_network_buffer_data(in_buffer->nbh));
					}
					handle_http_echo(ss->client_socket);
				}
				return 0;
			}
		}
	}

	//Unrecognized message received, ignore it

	FUNCEND;
	return -1;
}

static int attach_socket_to_session(turn_turnserver* server, ioa_socket_handle s, ts_ur_super_session* ss) {

	int ret = -1;
	FUNCSTART;

	if(s && server && ss && !ioa_socket_tobeclosed(s)) {

		if(ss->client_socket != s) {

			IOA_CLOSE_SOCKET(ss->client_socket);

			ss->client_socket = s;

			if(register_callback_on_ioa_socket(server->e, s, IOA_EV_READ,
					client_input_handler, ss, 0)<0) {
				return -1;
			}

			set_ioa_socket_session(s, ss);
		}

		ret = 0;
	}

	FUNCEND;
	return ret;
}

int open_client_connection_session(turn_turnserver* server,
				struct socket_message *sm) {

	FUNCSTART;
	if (!server)
		return -1;

	if (!(sm->s))
		return -1;

	ts_ur_super_session* ss = create_new_ss(server);

	ss->client_socket = sm->s;

	if(register_callback_on_ioa_socket(server->e, ss->client_socket, IOA_EV_READ,
			client_input_handler, ss, 0)<0) {
		return -1;
	}

	set_ioa_socket_session(ss->client_socket, ss);

	int at = TURN_MAX_ALLOCATE_TIMEOUT;
	if(*(server->stun_only))
	  at = TURN_MAX_ALLOCATE_TIMEOUT_STUN_ONLY;

	IOA_EVENT_DEL(ss->to_be_allocated_timeout_ev);
	ss->to_be_allocated_timeout_ev = set_ioa_timer(server->e,
			at, 0,
			client_to_be_allocated_timeout_handler, ss, 1,
			"client_to_be_allocated_timeout_handler");

	if(sm->nd.nbh) {
		client_input_handler(ss->client_socket,IOA_EV_READ,&(sm->nd),ss,sm->can_resume);
		ioa_network_buffer_delete(server->e, sm->nd.nbh);
		sm->nd.nbh = NULL;
	}

	FUNCEND;

	return 0;
}

/////////////// io handlers ///////////////////

static void peer_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *in_buffer, void *arg, int can_resume) {

	if (!(event_type & IOA_EV_READ) || !arg) return;

	if(in_buffer->recv_ttl==0) return;

	UNUSED_ARG(can_resume);

	if(!s || ioa_socket_tobeclosed(s)) return;

	ts_ur_super_session* ss = (ts_ur_super_session*) arg;

	if(!ss) return;

	if(ss->to_be_closed) return;

	if(!(ss->client_socket) || ioa_socket_tobeclosed(ss->client_socket)) return;

	turn_turnserver *server = (turn_turnserver*) (ss->server);

	if (!server) return;

	relay_endpoint_session* elem = get_relay_session_ss(ss, get_ioa_socket_address_family(s));
	if (elem->s == NULL) {
		return;
	}

	int offset = STUN_CHANNEL_HEADER_LENGTH;

	int ilen = min((int)ioa_network_buffer_get_size(in_buffer->nbh),
			(int)(ioa_network_buffer_get_capacity_udp() - offset));

	if (ilen >= 0) {

		allocation* a = get_allocation_ss(ss);
		if (is_allocation_valid(a)) {

			u16bits chnum = 0;

			ioa_network_buffer_handle nbh = NULL;

			turn_permission_info* tinfo = allocation_get_permission(a,
							&(in_buffer->src_addr));
			if (tinfo) {
				chnum = get_turn_channel_number(tinfo, &(in_buffer->src_addr));
			} else if(!(server->server_relay)) {
				return;
			}

			if (chnum) {

				size_t len = (size_t)(ilen);

				nbh = in_buffer->nbh;

				ioa_network_buffer_add_offset_size(nbh,
								0,
								STUN_CHANNEL_HEADER_LENGTH,
								ioa_network_buffer_get_size(nbh)+STUN_CHANNEL_HEADER_LENGTH);

				ioa_network_buffer_header_init(nbh);

				SOCKET_TYPE st = get_ioa_socket_type(ss->client_socket);
				int do_padding = is_stream_socket(st);

				stun_init_channel_message_str(chnum, ioa_network_buffer_data(nbh), &len, len, do_padding);
				ioa_network_buffer_set_size(nbh,len);
				in_buffer->nbh = NULL;
				if (eve(server->verbose)) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"%s: send channel 0x%x\n", __FUNCTION__,
							(int) (chnum));
				}
			} else {

				size_t len = 0;

				nbh = ioa_network_buffer_allocate(server->e);
				stun_init_indication_str(STUN_METHOD_DATA, ioa_network_buffer_data(nbh), &len);
				stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_DATA,
								ioa_network_buffer_data(in_buffer->nbh), (size_t)ilen);
				stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &len,
						STUN_ATTRIBUTE_XOR_PEER_ADDRESS,
						&(in_buffer->src_addr));
				ioa_network_buffer_set_size(nbh,len);

				{
					static const u08bits *field = (const u08bits *) TURN_SOFTWARE;
					static const size_t fsz = sizeof(TURN_SOFTWARE)-1;
					size_t len = ioa_network_buffer_get_size(nbh);
					stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
					ioa_network_buffer_set_size(nbh, len);
				}

				if ((server->fingerprint) || ss->enforce_fingerprints) {
					size_t len = ioa_network_buffer_get_size(nbh);
					stun_attr_add_fingerprint_str(ioa_network_buffer_data(nbh), &len);
					ioa_network_buffer_set_size(nbh, len);
				}
			}
			if (eve(server->verbose)) {
				u16bits* t = (u16bits*) ioa_network_buffer_data(nbh);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Send data: 0x%x\n",
						(int) (nswap16(t[0])));
			}

			write_client_connection(server, ss, nbh, in_buffer->recv_ttl-1, in_buffer->recv_tos);
		}
	}
}

static void client_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *data, void *arg, int can_resume) {

	if (!arg)
		return;

	UNUSED_ARG(s);
	UNUSED_ARG(event_type);

	ts_ur_super_session* ss = (ts_ur_super_session*)arg;

	turn_turnserver *server = (turn_turnserver*)ss->server;

	if (!server) {
		return;
	}

	if (ss->client_socket != s) {
		return;
	}

	read_client_connection(server, ss, data, can_resume, 1);

	if (ss->to_be_closed) {
		if(server->verbose) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"session %018llu: client socket to be closed in client handler: ss=0x%lx\n", (unsigned long long)(ss->id), (long)ss);
		}
		set_ioa_socket_tobeclosed(s);
	}
}

///////////////////////////////////////////////////////////

void init_turn_server(turn_turnserver* server,
		turnserver_id id, int verbose, ioa_engine_handle e, turn_credential_type ct,
		int stun_port, int fingerprint, dont_fragment_option_t dont_fragment,
		get_user_key_cb userkeycb,
		check_new_allocation_quota_cb chquotacb,
		release_allocation_quota_cb raqcb,
		ioa_addr *external_ip,
		vintp check_origin,
		vintp no_tcp_relay,
		vintp no_udp_relay,
		vintp stale_nonce,
		vintp stun_only,
		vintp no_stun,
		turn_server_addrs_list_t *alternate_servers_list,
		turn_server_addrs_list_t *tls_alternate_servers_list,
		turn_server_addrs_list_t *aux_servers_list,
		int self_udp_balance,
		vintp no_multicast_peers, vintp no_loopback_peers,
		ip_range_list_t* ip_whitelist, ip_range_list_t* ip_blacklist,
		send_socket_to_relay_cb send_socket_to_relay,
		vintp secure_stun, vintp mobility, int server_relay,
		send_turn_session_info_cb send_turn_session_info,
		send_https_socket_cb send_https_socket,
		allocate_bps_cb allocate_bps_func,
		int oauth, const char* oauth_server_name) {

	if (!server)
		return;

	ns_bzero(server,sizeof(turn_turnserver));

	server->e = e;
	server->id = id;
	server->ctime = turn_time();
	server->session_id_counter = 0;
	server->sessions_map = ur_map_create();
	server->tcp_relay_connections = ur_map_create();
	server->ct = ct;
	server->userkeycb = userkeycb;
	server->chquotacb = chquotacb;
	server->raqcb = raqcb;
	server->no_multicast_peers = no_multicast_peers;
	server->no_loopback_peers = no_loopback_peers;
	server->secure_stun = secure_stun;
	server->mobility = mobility;
	server->server_relay = server_relay;
	server->send_turn_session_info = send_turn_session_info;
	server->send_https_socket = send_https_socket;
	server->oauth = oauth;
	if(oauth)
		server->oauth_server_name = oauth_server_name;
	if(mobility)
		server->mobile_connections_map = ur_map_create();

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"turn server id=%d created\n",(int)id);

	server->check_origin = check_origin;
	server->no_tcp_relay = no_tcp_relay;
	server->no_udp_relay = no_udp_relay;

	server->alternate_servers_list = alternate_servers_list;
	server->tls_alternate_servers_list = tls_alternate_servers_list;
	server->aux_servers_list = aux_servers_list;
	server->self_udp_balance = self_udp_balance;

	server->stale_nonce = stale_nonce;
	server->stun_only = stun_only;
	server->no_stun = no_stun;

	server->dont_fragment = dont_fragment;
	server->fingerprint = fingerprint;
	if(external_ip) {
		addr_cpy(&(server->external_ip), external_ip);
		server->external_ip_set = 1;
	}
	if (stun_port < 1)
		stun_port = DEFAULT_STUN_PORT;

	server->verbose = verbose;

	server->ip_whitelist = ip_whitelist;
	server->ip_blacklist = ip_blacklist;

	server->send_socket_to_relay = send_socket_to_relay;

	server->allocate_bps_func = allocate_bps_func;

	set_ioa_timer(server->e, 1, 0, timer_timeout_handler, server, 1, "timer_timeout_handler");
}

ioa_engine_handle turn_server_get_engine(turn_turnserver *s) {
	if(s)
		return s->e;
	return NULL;
}

void set_disconnect_cb(turn_turnserver* server, int(*disconnect)(
		ts_ur_super_session*)) {
	server->disconnect = disconnect;
}

//////////////////////////////////////////////////////////////////
