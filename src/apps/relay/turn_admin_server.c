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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>

#include <pthread.h>

#include <signal.h>

#include "libtelnet.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/http.h>

#include "userdb.h"
#include "mainrelay.h"

#include "ns_turn_utils.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

#include "turn_admin_server.h"

#include "http_server.h"

#include "dbdrivers/dbdriver.h"

///////////////////////////////

struct admin_server adminserver;

int use_cli = 1;

ioa_addr cli_addr;
int cli_addr_set = 0;

int cli_port = CLI_DEFAULT_PORT;

char cli_password[CLI_PASSWORD_LENGTH] = "";

int cli_max_output_sessions = DEFAULT_CLI_MAX_OUTPUT_SESSIONS;

///////////////////////////////

struct cli_session {
	evutil_socket_t fd;
	int auth_completed;
	size_t cmds;
	struct bufferevent *bev;
	ioa_addr addr;
	telnet_t *ts;
	FILE* f;
	char realm[STUN_MAX_REALM_SIZE+1];
	char origin[STUN_MAX_ORIGIN_SIZE+1];
	realm_params_t *rp;
};

///////////////////////////////

#define CLI_PASSWORD_TRY_NUMBER (5)

static const char *CLI_HELP_STR[] = 
  {"",
   "  ?, h, help - print this text",
   "",
   "  quit, q, exit, bye - end CLI session",
   "",
   "  stop, shutdown, halt - shutdown TURN Server",
   "",
   "  pc - print configuration",
   "",
   "  sr <realm> - set CLI session realm",
   "",
   "  ur - unset CLI session realm",
   "",
   "  so <origin> - set CLI session origin",
   "",
   "  uo - unset CLI session origin",
   "",
   "  tc <param-name> - toggle a configuration parameter",
   "     (see pc command output for togglable param names)",
   "",
   "  cc <param-name> <param-value> - change a configuration parameter",
   "     (see pc command output for changeable param names)",
   "",
   "  ps [username] - print sessions, with optional exact user match",
   "",
   "  psp <usernamestr> - print sessions, with partial user string match",
   "",
   "  psd <file-name> - dump ps command output into file on the TURN server system",
   "",
   "  pu [udp|tcp|dtls|tls]- print current users",
   "",
   "  lr - log reset",
   "",
   "  aas ip[:port} - add an alternate server reference",
   "  das ip[:port] - delete an alternate server reference",
   "  atas ip[:port] - add a TLS alternate server reference",
   "  dtas ip[:port] - delete a TLS alternate server reference",
   "",
   "  cs <session-id> - cancel session, forcefully"
   "",
   NULL};

static const char *CLI_GREETING_STR[] = {
  "TURN Server",
  TURN_SOFTWARE,
  NULL};

static char CLI_CURSOR[] = "> ";

static const telnet_telopt_t cli_telopts[] = {
    { TELNET_TELOPT_ECHO,      TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_TTYPE,     TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_COMPRESS2, TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_ZMP,       TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_MSSP,      TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_BINARY,    TELNET_WONT, TELNET_DONT },
    { TELNET_TELOPT_NAWS,      TELNET_WONT, TELNET_DONT },
    { -1, 0, 0 }
  };

struct toggleable_command {
	const char *cmd;
	vintp data;
};

struct toggleable_command tcmds[] = {
				{"stale-nonce",&turn_params.stale_nonce},
				{"stun-only",&turn_params.stun_only},
				{"no-stun",&turn_params.no_stun},
				{"secure-stun",&turn_params.secure_stun},
				{"no-udp-relay",&turn_params.no_udp_relay},
				{"no-tcp-relay",&turn_params.no_tcp_relay},
				{"no-multicast-peers",&turn_params.no_multicast_peers},
				{"no-loopback-peers",&turn_params.no_loopback_peers},
				{"mobility",&turn_params.mobility},
				{NULL,NULL}
};

///////////////////////////////

static void myprintf(struct cli_session *cs, const char *format, ...)
{
	if(cs && format) {
		va_list args;
		va_start (args, format);
		if(cs->f) {
			vfprintf(cs->f, format, args);
		} else {
			telnet_vprintf(cs->ts, format, args);
		}
		va_end (args);
	}
}

static void log_reset(struct cli_session* cs)
{
	if(cs) {
	  reset_rtpprintf();
	  myprintf(cs,"  log reset done\n");
	}
}

static void print_str_array(struct cli_session* cs, const char** sa)
{
  if(cs && sa) {
    int i=0;
    while(sa[i]) {
      myprintf(cs,"%s\n",sa[i]);
      i++;
    }
  }
}

static const char* get_flag(int val)
{
	if(val)
		return "ON";
	return "OFF";
}

static void cli_print_flag(struct cli_session* cs, int flag, const char* name, int changeable)
{
	if(cs && cs->ts && name) {
		const char *sc="";
		if(changeable)
			sc=" (*)";
		myprintf(cs,"  %s: %s%s\n",name,get_flag(flag),sc);
	}
}

static void cli_print_uint(struct cli_session* cs, unsigned long value, const char* name, int changeable)
{
	if(cs && cs->ts && name) {
		const char *sc="";
		if(changeable==1)
			sc=" (*)";
		else if(changeable==2)
			sc=" (**)";
		myprintf(cs,"  %s: %lu%s\n",name,value,sc);
	}
}

static void cli_print_str(struct cli_session* cs, const char *value, const char* name, int changeable)
{
	if(cs && cs->ts && name && value) {
		if(value[0] == 0)
			value="empty";
		const char *sc="";
		if(changeable==1)
			sc=" (*)";
		else if(changeable==2)
			sc=" (**)";
		myprintf(cs,"  %s: %s%s\n",name,value,sc);
	}
}

static void cli_print_addr(struct cli_session* cs, ioa_addr *value, int use_port, const char* name, int changeable)
{
	if(cs && cs->ts && name && value) {
		const char *sc="";
		if(changeable==1)
			sc=" (*)";
		else if(changeable==2)
			sc=" (**)";
		char s[256];
		if(!use_port)
			addr_to_string_no_port(value,(u08bits*)s);
		else
			addr_to_string(value,(u08bits*)s);
		myprintf(cs,"  %s: %s%s\n",name,s,sc);
	}
}

static void cli_print_addr_list(struct cli_session* cs, turn_server_addrs_list_t *value, int use_port, const char* name, int changeable)
{
	if(cs && cs->ts && name && value && value->size && value->addrs) {
		const char *sc="";
		if(changeable==1)
			sc=" (*)";
		else if(changeable==2)
			sc=" (**)";
		char s[256];
		size_t i;
		for(i=0;i<value->size;i++) {
			if(!use_port)
				addr_to_string_no_port(&(value->addrs[i]),(u08bits*)s);
			else
				addr_to_string(&(value->addrs[i]),(u08bits*)s);
			myprintf(cs,"  %s: %s%s\n",name,s,sc);
		}
	}
}

static void cli_print_str_array(struct cli_session* cs, char **value, size_t sz, const char* name, int changeable)
{
	if(cs && cs->ts && name && value && sz) {
		const char *sc="";
		if(changeable==1)
			sc=" (*)";
		else if(changeable==2)
			sc=" (**)";
		size_t i;
		for(i=0;i<sz;i++) {
			if(value[i])
				myprintf(cs,"  %s: %s%s\n",name,value[i],sc);
		}
	}
}

static void cli_print_ip_range_list(struct cli_session* cs, ip_range_list_t *value, const char* name, int changeable)
{
	if(cs && cs->ts && name && value && value->ranges_number && value->rs) {
		const char *sc="";
		if(changeable==1)
			sc=" (*)";
		else if(changeable==2)
			sc=" (**)";
		size_t i;
		for(i=0;i<value->ranges_number;++i) {
			if(value->rs[i].realm[0]) {
				if(cs->realm[0] && strcmp(cs->realm,value->rs[i].realm)) {
					continue;
				} else {
					myprintf(cs,"  %s: %s (%s)%s\n",name,value->rs[i].str,value->rs[i].realm,sc);
				}
			} else {
				myprintf(cs,"  %s: %s%s\n",name,value->rs[i].str,sc);
			}
		}
	}
}

static void toggle_cli_param(struct cli_session* cs, const char* pn)
{
	if(cs && cs->ts && pn) {

		int i=0;

		while(tcmds[i].cmd && tcmds[i].data) {
			if(strcmp(tcmds[i].cmd,pn) == 0) {
				*(tcmds[i].data) = !(*(tcmds[i].data));
				cli_print_flag(cs,*(tcmds[i].data),tcmds[i].cmd,0);
				return;
			}
			++i;
		}

		myprintf(cs, "\n");
		myprintf(cs, "  Error: unknown or constant parameter: %s.\n",pn);
		myprintf(cs, "  You can toggle only the following parameters:\n");
		myprintf(cs, "\n");

		i=0;

		while(tcmds[i].cmd && tcmds[i].data) {
			cli_print_flag(cs,*(tcmds[i].data),tcmds[i].cmd,0);
			++i;
		}

		myprintf(cs,"\n");
	}
}

static void change_cli_param(struct cli_session* cs, const char* pn)
{
	if(cs && cs->ts && pn) {

		if(strstr(pn,"total-quota")==pn) {
			turn_params.total_quota = atoi(pn+strlen("total-quota"));
			cli_print_uint(cs,(unsigned long)turn_params.total_quota,"total-quota",2);
			return;
		} else if(strstr(pn,"user-quota")==pn) {
			turn_params.user_quota = atoi(pn+strlen("user-quota"));
			cli_print_uint(cs,(unsigned long)turn_params.user_quota,"user-quota",2);
			return;
		} else if(strstr(pn,"max-bps")==pn) {
			set_max_bps((band_limit_t)strtoul(pn+strlen("max-bps"),NULL,10));
			cli_print_uint(cs,(unsigned long)get_max_bps(),"max-bps",2);
			return;
		} else if(strstr(pn,"bps-capacity")==pn) {
			set_bps_capacity((band_limit_t)strtoul(pn+strlen("bps-capacity"),NULL,10));
			cli_print_uint(cs,(unsigned long)get_bps_capacity(),"bps-capacity",2);
			return;
		} else if(strstr(pn,"cli-max-output-sessions")==pn) {
			cli_max_output_sessions = atoi(pn+strlen("cli-max-output-sessions"));
			cli_print_uint(cs,(unsigned long)cli_max_output_sessions,"cli-max-output-sessions",2);
			return;
		}

		myprintf(cs, "\n");
		myprintf(cs, "  Error: unknown or constant parameter: %s.\n",pn);
		myprintf(cs, "\n");
	}
}

struct ps_arg {
	struct cli_session* cs;
	size_t counter;
	turn_time_t ct;
	const char *username;
	const char *pname;
	int exact_match;
	ur_string_map* users;
	size_t *user_counters;
	char **user_names;
	size_t users_number;
};

static int print_session(ur_map_key_type key, ur_map_value_type value, void *arg)
{
	if(key && value && arg) {
		struct ps_arg *csarg = (struct ps_arg*)arg;
		struct cli_session* cs = csarg->cs;
		struct turn_session_info *tsi = (struct turn_session_info *)value;

		if(cs->realm[0] && strcmp(cs->realm,tsi->realm))
			return 0;

		if(cs->origin[0] && strcmp(cs->origin,tsi->origin))
					return 0;

		if(csarg->users) {

			const char *pn=csarg->pname;
			if(pn[0]) {
				if(!strcmp(pn,"TLS") || !strcmp(pn,"tls") || !strcmp(pn,"Tls")) {
					if((tsi->client_protocol != TLS_SOCKET)||(tsi->client_protocol != TLS_SCTP_SOCKET))
						return 0;
				} else if(!strcmp(pn,"DTLS") || !strcmp(pn,"dtls") || !strcmp(pn,"Dtls")) {
					if(tsi->client_protocol != DTLS_SOCKET)
						return 0;
				} else if(!strcmp(pn,"TCP") || !strcmp(pn,"tcp") || !strcmp(pn,"Tcp")) {
					if((tsi->client_protocol != TCP_SOCKET)||(tsi->client_protocol != SCTP_SOCKET))
						return 0;
				} else if(!strcmp(pn,"UDP") || !strcmp(pn,"udp") || !strcmp(pn,"Udp")) {
					if(tsi->client_protocol != UDP_SOCKET)
						return 0;
				} else {
					return 0;
				}
			}

			ur_string_map_value_type value;
			if(!ur_string_map_get(csarg->users, (ur_string_map_key_type)(char*)tsi->username, &value)) {
				value = (ur_string_map_value_type)csarg->users_number;
				csarg->users_number += 1;
				csarg->user_counters = (size_t*)turn_realloc(csarg->user_counters,
						(size_t)value * sizeof(size_t),
						csarg->users_number * sizeof(size_t));
				csarg->user_names = (char**)turn_realloc(csarg->user_names,
						(size_t)value * sizeof(char*),
						csarg->users_number * sizeof(char*));
				csarg->user_names[(size_t)value] = turn_strdup((char*)tsi->username);
				csarg->user_counters[(size_t)value] = 0;
				ur_string_map_put(csarg->users, (ur_string_map_key_type)(char*)tsi->username, value);
			}
			csarg->user_counters[(size_t)value] += 1;
		} else {
			if(csarg->username[0]) {
				if(csarg->exact_match) {
					if(strcmp((char*)tsi->username, csarg->username))
						return 0;
				} else {
					if(!strstr((char*)tsi->username, csarg->username))
						return 0;
				}
			}
			if(cs->f || (unsigned long)csarg->counter<(unsigned long)cli_max_output_sessions) {
				myprintf(cs, "\n");
				myprintf(cs,"    %lu) id=%018llu, user <%s>:\n",
								(unsigned long)(csarg->counter+1),
								(unsigned long long)tsi->id,
								tsi->username);
				if(tsi->realm[0])
					myprintf(cs,"      realm: %s\n",tsi->realm);
				if(tsi->origin[0])
					myprintf(cs,"      origin: %s\n",tsi->origin);
				if(turn_time_before(csarg->ct, tsi->start_time)) {
					myprintf(cs,"      started: undefined time\n");
				} else {
					myprintf(cs,"      started %lu secs ago\n",(unsigned long)(csarg->ct - tsi->start_time));
				}
				if(turn_time_before(tsi->expiration_time,csarg->ct)) {
					myprintf(cs,"      expired\n");
				} else {
					myprintf(cs,"      expiring in %lu secs\n",(unsigned long)(tsi->expiration_time - csarg->ct));
				}
				myprintf(cs,"      client protocol %s, relay protocol %s\n",socket_type_name(tsi->client_protocol),socket_type_name(tsi->peer_protocol));
				{
					if(!tsi->local_addr_data.saddr[0])
						addr_to_string(&(tsi->local_addr_data.addr),(u08bits*)tsi->local_addr_data.saddr);
					if(!tsi->remote_addr_data.saddr[0])
						addr_to_string(&(tsi->remote_addr_data.addr),(u08bits*)tsi->remote_addr_data.saddr);
					if(!tsi->relay_addr_data_ipv4.saddr[0])
						addr_to_string(&(tsi->relay_addr_data_ipv4.addr),(u08bits*)tsi->relay_addr_data_ipv4.saddr);
					if(!tsi->relay_addr_data_ipv6.saddr[0])
						addr_to_string(&(tsi->relay_addr_data_ipv6.addr),(u08bits*)tsi->relay_addr_data_ipv6.saddr);
					myprintf(cs,"      client addr %s, server addr %s\n",
									tsi->remote_addr_data.saddr,
									tsi->local_addr_data.saddr);
					if(tsi->relay_addr_data_ipv4.saddr[0]) {
						myprintf(cs,"      relay addr %s\n", tsi->relay_addr_data_ipv4.saddr);
					}
					if(tsi->relay_addr_data_ipv6.saddr[0]) {
						myprintf(cs,"      relay addr %s\n", tsi->relay_addr_data_ipv6.saddr);
					}
				}
				myprintf(cs,"      fingerprints enforced: %s\n",get_flag(tsi->enforce_fingerprints));
				myprintf(cs,"      mobile: %s\n",get_flag(tsi->is_mobile));
				if(tsi->tls_method[0]) {
					myprintf(cs,"      TLS method: %s\n",tsi->tls_method);
					myprintf(cs,"      TLS cipher: %s\n",tsi->tls_cipher);
				}
				if(tsi->bps)
					myprintf(cs,"      Max throughput: %lu bytes per second\n",(unsigned long)tsi->bps);
				myprintf(cs,"      usage: rp=%lu, rb=%lu, sp=%lu, sb=%lu\n",(unsigned long)(tsi->received_packets), (unsigned long)(tsi->received_bytes),(unsigned long)(tsi->sent_packets),(unsigned long)(tsi->sent_bytes));
				myprintf(cs,"       rate: r=%lu, s=%lu, total=%lu (bytes per sec)\n",(unsigned long)(tsi->received_rate), (unsigned long)(tsi->sent_rate),(unsigned long)(tsi->total_rate));
				if(tsi->main_peers_size) {
					myprintf(cs,"      peers:\n");
					size_t i;
					for(i=0;i<tsi->main_peers_size;++i) {
						if(!(tsi->main_peers_data[i].saddr[0]))
							addr_to_string(&(tsi->main_peers_data[i].addr),(u08bits*)tsi->main_peers_data[i].saddr);
						myprintf(cs,"          %s\n",tsi->main_peers_data[i].saddr);
					}
					if(tsi->extra_peers_size && tsi->extra_peers_data) {
						for(i=0;i<tsi->extra_peers_size;++i) {
							if(!(tsi->extra_peers_data[i].saddr[0]))
								addr_to_string(&(tsi->extra_peers_data[i].addr),(u08bits*)tsi->extra_peers_data[i].saddr);
							myprintf(cs,"          %s\n",tsi->extra_peers_data[i].saddr);
						}
					}
				}
			}
		}

		csarg->counter += 1;
	}
	return 0;
}

static void cancel_session(struct cli_session* cs, const char* ssid)
{
	if(cs && cs->ts && ssid && *ssid) {
		turnsession_id sid = strtoull(ssid,NULL,10);
		send_session_cancellation_to_relay(sid);
	}
}

static void print_sessions(struct cli_session* cs, const char* pn, int exact_match, int print_users)
{
	if(cs && cs->ts && pn) {

		while(pn[0] == ' ') ++pn;
		if(pn[0] == '*') ++pn;

		const char *uname="";
		if(!print_users) {
			uname = pn;
			pn = "";
		}

		struct ps_arg arg = {cs,0,0,uname,pn,exact_match,NULL,NULL,NULL,0};

		arg.ct = turn_time();

		if(print_users) {
			arg.users = ur_string_map_create(NULL);
		}

		ur_map_foreach_arg(adminserver.sessions, (foreachcb_arg_type)print_session, &arg);

		myprintf(cs,"\n");

		if(!print_users && !(cs->f)) {
			if((unsigned long)arg.counter > (unsigned long)cli_max_output_sessions) {
				myprintf(cs,"...\n");
				myprintf(cs,"\n");
			}
		} else if(arg.user_counters && arg.user_names) {
			size_t i;
			for(i=0;i<arg.users_number;++i) {
				if(arg.user_names[i]) {
					myprintf(cs,"    user: <%s>, %lu sessions\n",
						arg.user_names[i],
						(unsigned long)arg.user_counters[i]);
				}
			}
			myprintf(cs,"\n");
		}

		{
			char ts[1025];
			snprintf(ts,sizeof(ts),"  Total sessions");
			if(cs->realm[0]) {
				snprintf(ts+strlen(ts),sizeof(ts)-strlen(ts)," for realm %s",cs->realm);
				if(cs->origin[0])
					snprintf(ts+strlen(ts),sizeof(ts)-strlen(ts)," and for origin %s",cs->origin);
			} else {
				if(cs->origin[0])
					snprintf(ts+strlen(ts),sizeof(ts)-strlen(ts)," for origin %s",cs->origin);
			}
			snprintf(ts+strlen(ts),sizeof(ts)-strlen(ts),": %lu", (unsigned long)arg.counter);
			myprintf(cs,"%s\n", ts);
			myprintf(cs,"\n");
		}

		if(!print_users && !(cs->f)) {
			if((unsigned long)arg.counter > (unsigned long)cli_max_output_sessions) {
				myprintf(cs,"  Warning: too many output sessions, more than the\n");
				myprintf(cs,"  current value of cli-max-output-sessions CLI parameter.\n");
				myprintf(cs,"  Refine your request or increase cli-max-output-sessions value.\n");
				myprintf(cs,"\n");
			}
		}

		if(arg.user_counters)
			turn_free(arg.user_counters,sizeof(size_t)*arg.users_number);
		if(arg.user_names) {
			size_t i;
			for(i=0;i<arg.users_number;++i) {
				if(arg.user_names[i])
					turn_free(arg.user_names[i],strlen(arg.user_names[i])+1);
			}
			turn_free(arg.user_names,sizeof(char*) * arg.users_number);
		}
		if(arg.users)
			ur_string_map_free(&arg.users);
	}
}

static void cli_print_configuration(struct cli_session* cs)
{
	if(cs) {
		myprintf(cs,"\n");

		cli_print_flag(cs,turn_params.verbose,"verbose",0);
		cli_print_flag(cs,turn_params.turn_daemon,"daemon process",0);
		cli_print_flag(cs,turn_params.stale_nonce,"stale-nonce",1);
		cli_print_flag(cs,turn_params.stun_only,"stun-only",1);
		cli_print_flag(cs,turn_params.no_stun,"no-stun",1);
		cli_print_flag(cs,turn_params.secure_stun,"secure-stun",1);
		cli_print_flag(cs,turn_params.do_not_use_config_file,"do-not-use-config-file",0);
		cli_print_flag(cs,turn_params.rfc5780,"RFC5780 support",0);
		cli_print_uint(cs,(unsigned int)turn_params.net_engine_version,"net engine version",0);
		cli_print_str(cs,turn_params.net_engine_version_txt[(int)turn_params.net_engine_version],"net engine",0);
		cli_print_flag(cs,turn_params.fingerprint,"enforce fingerprints",0);
		cli_print_flag(cs,turn_params.mobility,"mobility",1);
		cli_print_flag(cs,turn_params.udp_self_balance,"udp-self-balance",0);
		cli_print_str(cs,turn_params.pidfile,"pidfile",0);
		cli_print_uint(cs,(unsigned long)getuid(),"process user ID",0);
		cli_print_uint(cs,(unsigned long)getgid(),"process group ID",0);

		{
			char wd[1025];
			if(getcwd(wd,sizeof(wd)-1)) {
				cli_print_str(cs,wd,"process dir",0);
			}
		}

		myprintf(cs,"\n");

		if(turn_params.cipher_list[0])
			cli_print_str(cs,turn_params.cipher_list,"cipher-list",0);
		else
			cli_print_str(cs,DEFAULT_CIPHER_LIST,"cipher-list",0);

		cli_print_str(cs,turn_params.ec_curve_name,"ec-curve-name",0);
		{
			if(turn_params.dh_key_size == DH_CUSTOM)
				cli_print_str(cs,turn_params.dh_file,"dh-file",0);
			else {
				unsigned int dh_key_length = 1066;
				if(turn_params.dh_key_size == DH_566)
					dh_key_length = 566;
				else if(turn_params.dh_key_size == DH_2066)
					dh_key_length = 2066;
				cli_print_uint(cs,(unsigned long)dh_key_length,"DH-key-length",0);
			}
		}

		cli_print_str(cs,turn_params.ca_cert_file,"Certificate Authority file",0);
		cli_print_str(cs,turn_params.cert_file,"Certificate file",0);
		cli_print_str(cs,turn_params.pkey_file,"Private Key file",0);

		cli_print_str_array(cs,turn_params.listener.addrs,turn_params.listener.addrs_number,"Listener addr",0);

		if(turn_params.listener_ifname[0])
			cli_print_str(cs,turn_params.listener_ifname,"listener-ifname",0);

		cli_print_flag(cs,turn_params.no_udp,"no-udp",0);
		cli_print_flag(cs,turn_params.no_tcp,"no-tcp",0);
		cli_print_flag(cs,turn_params.no_dtls,"no-dtls",0);
		cli_print_flag(cs,turn_params.no_tls,"no-tls",0);

		cli_print_flag(cs,(!turn_params.no_tlsv1 && !turn_params.no_tls),"TLSv1.0",0);
		cli_print_flag(cs,(!turn_params.no_tlsv1_1 && !turn_params.no_tls),"TLSv1.1",0);
		cli_print_flag(cs,(!turn_params.no_tlsv1_2 && !turn_params.no_tls),"TLSv1.2",0);

		cli_print_uint(cs,(unsigned long)turn_params.listener_port,"listener-port",0);
		cli_print_uint(cs,(unsigned long)turn_params.tls_listener_port,"tls-listener-port",0);
		cli_print_uint(cs,(unsigned long)turn_params.alt_listener_port,"alt-listener-port",0);
		cli_print_uint(cs,(unsigned long)turn_params.alt_tls_listener_port,"alt-tls-listener-port",0);

		cli_print_addr(cs,turn_params.external_ip,0,"External public IP",0);

		myprintf(cs,"\n");

		cli_print_addr_list(cs,&turn_params.aux_servers_list,1,"Aux server",0);
		cli_print_addr_list(cs,&turn_params.alternate_servers_list,1,"Alternate server",0);
		cli_print_addr_list(cs,&turn_params.tls_alternate_servers_list,1,"TLS alternate server",0);

		myprintf(cs,"\n");

		cli_print_str_array(cs,turn_params.relay_addrs,turn_params.relays_number,"Relay addr",0);

		if(turn_params.relay_ifname[0])
			cli_print_str(cs,turn_params.relay_ifname,"relay-ifname",0);

		cli_print_flag(cs,turn_params.server_relay,"server-relay",0);

		cli_print_flag(cs,turn_params.no_udp_relay,"no-udp-relay",1);
		cli_print_flag(cs,turn_params.no_tcp_relay,"no-tcp-relay",1);

		cli_print_uint(cs,(unsigned long)turn_params.min_port,"min-port",0);
		cli_print_uint(cs,(unsigned long)turn_params.max_port,"max-port",0);

		cli_print_ip_range_list(cs,&turn_params.ip_whitelist,"Whitelist IP (static)",0);
		{
			ip_range_list_t* l = get_ip_list("allowed");
			cli_print_ip_range_list(cs,l,"Whitelist IP (dynamic)",0);
			ip_list_free(l);
		}

		cli_print_ip_range_list(cs,&turn_params.ip_blacklist,"Blacklist IP (static)",0);
		{
			ip_range_list_t* l = get_ip_list("denied");
			cli_print_ip_range_list(cs,l,"Blacklist IP (dynamic)",0);
			ip_list_free(l);
		}

		cli_print_flag(cs,turn_params.no_multicast_peers,"no-multicast-peers",1);
		cli_print_flag(cs,turn_params.no_loopback_peers,"no-loopback-peers",1);

		myprintf(cs,"\n");

		if(turn_params.default_users_db.persistent_users_db.userdb[0]) {
			switch(turn_params.default_users_db.userdb_type) {
#if !defined(TURN_NO_SQLITE)
			case TURN_USERDB_TYPE_SQLITE:
				cli_print_str(cs,"SQLite","DB type",0);
				break;
#endif
#if !defined(TURN_NO_PQ)
			case TURN_USERDB_TYPE_PQ:
				cli_print_str(cs,"Postgres","DB type",0);
				break;
#endif
#if !defined(TURN_NO_MYSQL)
			case TURN_USERDB_TYPE_MYSQL:
				cli_print_str(cs,"MySQL/MariaDB","DB type",0);
				break;
#endif
#if !defined(TURN_NO_MONGO)
			case TURN_USERDB_TYPE_MONGO:
				cli_print_str(cs,"MongoDB","DB type",0);
				break;
#endif
#if !defined(TURN_NO_HIREDIS)
			case TURN_USERDB_TYPE_REDIS:
				cli_print_str(cs,"redis","DB type",0);
				break;
#endif
			default:
				cli_print_str(cs,"unknown","DB type",0);
			};
			cli_print_str(cs,turn_params.default_users_db.persistent_users_db.userdb,"DB",0);
		} else {
			cli_print_str(cs,"none","DB type",0);
			cli_print_str(cs,"none","DB",0);
		}

#if !defined(TURN_NO_HIREDIS)
		if(turn_params.use_redis_statsdb && turn_params.redis_statsdb[0])
			cli_print_str(cs,turn_params.redis_statsdb,"Redis Statistics DB",0);
#endif

		myprintf(cs,"\n");


		{
			char * rn = get_realm(NULL)->options.name;
			if(rn[0])
				cli_print_str(cs,rn,"Default realm",0);
		}
		if(cs->realm[0])
			cli_print_str(cs,cs->realm,"CLI session realm",0);
		else
			cli_print_str(cs,get_realm(NULL)->options.name,"CLI session realm",0);
		if(cs->origin[0])
			cli_print_str(cs,cs->origin,"CLI session origin",0);
		if(turn_params.ct == TURN_CREDENTIALS_LONG_TERM)
			cli_print_flag(cs,1,"Long-term authorization mechanism",0);
		else
			cli_print_flag(cs,1,"Anonymous credentials",0);
		cli_print_flag(cs,turn_params.use_auth_secret_with_timestamp,"TURN REST API support",0);
		if(turn_params.use_auth_secret_with_timestamp && turn_params.rest_api_separator)
			cli_print_uint(cs,turn_params.rest_api_separator,"TURN REST API separator ASCII number",0);

		myprintf(cs,"\n");

		cli_print_uint(cs,(unsigned long)cs->rp->status.total_current_allocs,"total-current-allocs",0);

		myprintf(cs,"\n");

		cli_print_uint(cs,(unsigned long)turn_params.total_quota,"Default total-quota",2);
		cli_print_uint(cs,(unsigned long)turn_params.user_quota,"Default user-quota",2);
		cli_print_uint(cs,(unsigned long)get_bps_capacity(),"Total server bps-capacity",2);
		cli_print_uint(cs,(unsigned long)get_bps_capacity_allocated(),"Allocated bps-capacity",0);
		cli_print_uint(cs,(unsigned long)get_max_bps(),"Default max-bps",2);

		myprintf(cs,"\n");

		cli_print_uint(cs,(unsigned long)cs->rp->options.perf_options.total_quota,"current realm total-quota",0);
		cli_print_uint(cs,(unsigned long)cs->rp->options.perf_options.user_quota,"current realm user-quota",0);
		cli_print_uint(cs,(unsigned long)cs->rp->options.perf_options.max_bps,"current realm max-bps",0);

		myprintf(cs,"\n");

		cli_print_uint(cs,(unsigned long)cli_max_output_sessions,"cli-max-output-sessions",2);

		{
		  myprintf(cs,"\n");
		  const char *str="  (Note 1: parameters with (*) are toggleable)";
		  myprintf(cs,"%s\n",str);
		  myprintf(cs,"\n");
		  str="  (Note 2: parameters with (**) are changeable)";
		  myprintf(cs,"%s\n",str);
		  myprintf(cs,"\n");
		}
	}
}

static void close_cli_session(struct cli_session* cs);

static int run_cli_output(struct cli_session* cs, const char *buf, unsigned int len)
{
	if(cs && buf && len) {
		if(bufferevent_write(cs->bev, buf, len)< 0) {
			return -1;
		}
		return 0;
	}
	return -1;
}

static void close_cli_session(struct cli_session* cs)
{
	if(cs) {

		addr_debug_print(adminserver.verbose, &(cs->addr),"CLI session disconnected from");

		if(cs->ts) {
			telnet_free(cs->ts);
			cs->ts = NULL;
		}

		BUFFEREVENT_FREE(cs->bev);

		if(cs->fd>=0) {
			close(cs->fd);
			cs->fd = -1;
		}

		turn_free(cs,sizeof(struct cli_session));
	}
}

static void type_cli_cursor(struct cli_session* cs)
{
	if(cs && (cs->bev)) {
	  myprintf(cs, "%s", CLI_CURSOR);
	}
}

static void cli_add_alternate_server(struct cli_session* cs, const char* pn)
{
	if(cs && cs->ts && pn && *pn) {
		add_alternate_server(pn);
	}
}

static void cli_add_tls_alternate_server(struct cli_session* cs, const char* pn)
{
	if(cs && cs->ts && pn && *pn) {
		add_tls_alternate_server(pn);
	}
}

static void cli_del_alternate_server(struct cli_session* cs, const char* pn)
{
	if(cs && cs->ts && pn && *pn) {
		del_alternate_server(pn);
	}
}

static void cli_del_tls_alternate_server(struct cli_session* cs, const char* pn)
{
	if(cs && cs->ts && pn && *pn) {
		del_tls_alternate_server(pn);
	}
}

static int run_cli_input(struct cli_session* cs, const char *buf0, unsigned int len)
{
	int ret = 0;

	if(cs && buf0 && cs->ts && cs->bev) {

		char *buf = (char*)turn_malloc(len+1);
		ns_bcopy(buf0,buf,len);
		buf[len]=0;

		char *cmd = buf;

		while((cmd[0]==' ') || (cmd[0]=='\t')) ++cmd;

		size_t sl = strlen(cmd);

		while(sl) {
			char c = cmd[sl-1];
			if((c==10)||(c==13)) {
				cmd[sl-1]=0;
				--sl;
			} else {
				break;
			}
		}

		if(sl) {
			cs->cmds += 1;
			if(cli_password[0] && !(cs->auth_completed)) {
				if(check_password(cmd,cli_password)) {
					if(cs->cmds>=CLI_PASSWORD_TRY_NUMBER) {
						addr_debug_print(1, &(cs->addr),"CLI authentication error");
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"CLI authentication error\n");
						close_cli_session(cs);
					} else {
						const char* ipwd="Enter password: ";
						myprintf(cs,"%s\n",ipwd);
					}
				} else {
					cs->auth_completed = 1;
					addr_debug_print(1, &(cs->addr),"CLI authentication success");
					type_cli_cursor(cs);
				}
			} else if((strcmp(cmd,"bye") == 0)||(strcmp(cmd,"quit") == 0)||(strcmp(cmd,"exit") == 0)||(strcmp(cmd,"q") == 0)) {
				const char* str="Bye !";
				myprintf(cs,"%s\n",str);
				close_cli_session(cs);
				ret = -1;
			} else if((strcmp(cmd,"halt") == 0)||(strcmp(cmd,"shutdown") == 0)||(strcmp(cmd,"stop") == 0)) {
				addr_debug_print(1, &(cs->addr),"Shutdown command received from CLI user");
				const char* str="TURN server is shutting down";
				myprintf(cs,"%s\n",str);
				close_cli_session(cs);
				turn_params.stop_turn_server = 1;
				sleep(10);
				exit(0);
			} else if((strcmp(cmd,"?") == 0)||(strcmp(cmd,"h") == 0)||(strcmp(cmd,"help") == 0)) {
				print_str_array(cs, CLI_GREETING_STR);
				print_str_array(cs, CLI_HELP_STR);
				type_cli_cursor(cs);
			} else if(strcmp(cmd,"pc")==0) {
				cli_print_configuration(cs);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"tc ") == cmd) {
				toggle_cli_param(cs,cmd+3);
			} else if(strstr(cmd,"sr ") == cmd) {
				STRCPY(cs->realm,cmd+3);
				cs->rp = get_realm(cs->realm);
				type_cli_cursor(cs);
			} else if(strcmp(cmd,"ur") == 0) {
				cs->realm[0]=0;
				cs->rp = get_realm(NULL);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"so ") == cmd) {
				STRCPY(cs->origin,cmd+3);
				type_cli_cursor(cs);
			} else if(strcmp(cmd,"uo") == 0) {
				cs->origin[0]=0;
				type_cli_cursor(cs);
			} else if(strstr(cmd,"tc") == cmd) {
				toggle_cli_param(cs,cmd+2);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"psp") == cmd) {
				print_sessions(cs,cmd+3,0,0);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"psd") == cmd) {
				cmd += 3;
				while(cmd[0]==' ') ++cmd;
				if(!(cmd[0])) {
					const char* str="You have to provide file name for ps dump\n";
					myprintf(cs,"%s\n",str);
				} else {
					cs->f = fopen(cmd,"w");
					if(!(cs->f)) {
						const char* str="Cannot open file for writing\n";
						myprintf(cs,"%s\n",str);
					} else {
						print_sessions(cs,"",1,0);
						fclose(cs->f);
						cs->f = NULL;
					}
				}
				type_cli_cursor(cs);
			} else if(strstr(cmd,"pu ") == cmd) {
				print_sessions(cs,cmd+3,0,1);
				type_cli_cursor(cs);
			} else if(!strcmp(cmd,"pu")) {
				print_sessions(cs,cmd+2,0,1);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"ps") == cmd) {
				print_sessions(cs,cmd+2,1,0);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"cs ") == cmd) {
				cancel_session(cs,cmd+3);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"lr") == cmd) {
				log_reset(cs);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"cc ") == cmd) {
				change_cli_param(cs,cmd+3);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"cc") == cmd) {
				change_cli_param(cs,cmd+2);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"aas ") == cmd) {
				cli_add_alternate_server(cs,cmd+4);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"atas ") == cmd) {
				cli_add_tls_alternate_server(cs,cmd+5);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"das ") == cmd) {
				cli_del_alternate_server(cs,cmd+4);
				type_cli_cursor(cs);
			} else if(strstr(cmd,"dtas ") == cmd) {
				cli_del_tls_alternate_server(cs,cmd+5);
				type_cli_cursor(cs);
			} else {
				const char* str="Unknown command\n";
				myprintf(cs,"%s\n",str);
				type_cli_cursor(cs);
			}
		} else {
			type_cli_cursor(cs);
		}

		turn_free(buf,len+1);
	}

	return ret;
}

static void cli_socket_input_handler_bev(struct bufferevent *bev, void* arg)
{
	if (bev && arg) {

		struct cli_session* cs = (struct cli_session*) arg;

		if(!(cs->ts))
			return;

		stun_buffer buf;

		if(cs->bev) {

			int len = (int)bufferevent_read(cs->bev, buf.buf, STUN_BUFFER_SIZE-1);
			if(len < 0) {
				close_cli_session(cs);
				return;
			} else if(len == 0) {
				return;
			}

			buf.len = len;
			buf.offset = 0;
			buf.buf[len]=0;

			telnet_recv(cs->ts, (const char *)buf.buf, (unsigned int)(buf.len));
		}
	}
}

static void cli_eventcb_bev(struct bufferevent *bev, short events, void *arg)
{
	UNUSED_ARG(bev);

	if (events & BEV_EVENT_CONNECTED) {
		// Connect okay
	} else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		if (arg) {

			struct cli_session* cs = (struct cli_session*) arg;

			close_cli_session(cs);
		}
	}
}

static void cli_telnet_event_handler(telnet_t *telnet, telnet_event_t *event, void *user_data)
{
	if (user_data && telnet) {

		struct cli_session *cs = (struct cli_session *) user_data;

		switch (event->type){
		case TELNET_EV_DATA:
			run_cli_input(cs, event->data.buffer, event->data.size);
			break;
		case TELNET_EV_SEND:
			run_cli_output(cs, event->data.buffer, event->data.size);
			break;
		case TELNET_EV_ERROR:
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TELNET error: %s", event->error.msg);
			break;
		default:
			;
		};
	}
}

static void cliserver_input_handler(struct evconnlistener *l, evutil_socket_t fd,
				struct sockaddr *sa, int socklen, void *arg)
{
	UNUSED_ARG(l);
	UNUSED_ARG(arg);
	UNUSED_ARG(socklen);

	addr_debug_print(adminserver.verbose, (ioa_addr*)sa,"CLI connected to");

	struct cli_session *clisession = (struct cli_session*)turn_malloc(sizeof(struct cli_session));
	ns_bzero(clisession,sizeof(struct cli_session));

	clisession->rp = get_realm(NULL);

	set_socket_options_fd(fd, TCP_SOCKET, sa->sa_family);

	clisession->fd = fd;

	addr_cpy(&(clisession->addr),(ioa_addr*)sa);

	clisession->bev = bufferevent_socket_new(adminserver.event_base,
					fd,
					TURN_BUFFEREVENTS_OPTIONS);
	debug_ptr_add(clisession->bev);
	bufferevent_setcb(clisession->bev, cli_socket_input_handler_bev, NULL,
			cli_eventcb_bev, clisession);
	bufferevent_setwatermark(clisession->bev, EV_READ|EV_WRITE, 0, BUFFEREVENT_HIGH_WATERMARK);
	bufferevent_enable(clisession->bev, EV_READ); /* Start reading. */

	clisession->ts = telnet_init(cli_telopts, cli_telnet_event_handler, 0, clisession);

	if(!(clisession->ts)) {
		const char *str = "Cannot open telnet session\n";
		addr_debug_print(adminserver.verbose, (ioa_addr*)sa,str);
		close_cli_session(clisession);
	} else {
	  print_str_array(clisession, CLI_GREETING_STR);
	  telnet_printf(clisession->ts,"\n");
	  telnet_printf(clisession->ts,"Type '?' for help\n");
	  if(cli_password[0]) {
	    const char* ipwd="Enter password: ";
	    telnet_printf(clisession->ts,"%s\n",ipwd);
	  } else {
	    type_cli_cursor(clisession);
	  }
	}
}

void setup_admin_thread(void)
{
	adminserver.event_base = turn_event_base_new();
	super_memory_t* sm = new_super_memory_region();
	adminserver.e = create_ioa_engine(sm, adminserver.event_base, turn_params.listener.tp, turn_params.relay_ifname, turn_params.relays_number, turn_params.relay_addrs,
				turn_params.default_relays, turn_params.verbose
	#if !defined(TURN_NO_HIREDIS)
				,turn_params.redis_statsdb
	#endif
		);

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (admin thread): %s\n",event_base_get_method(adminserver.event_base));

	{
		struct bufferevent *pair[2];

		bufferevent_pair_new(adminserver.event_base, TURN_BUFFEREVENTS_OPTIONS, pair);

		adminserver.in_buf = pair[0];
		adminserver.out_buf = pair[1];

		bufferevent_setcb(adminserver.in_buf, admin_server_receive_message, NULL, NULL, &adminserver);
		bufferevent_enable(adminserver.in_buf, EV_READ);
	}

	{
		struct bufferevent *pair[2];

		bufferevent_pair_new(adminserver.event_base, TURN_BUFFEREVENTS_OPTIONS, pair);

		adminserver.https_in_buf = pair[0];
		adminserver.https_out_buf = pair[1];

		bufferevent_setcb(adminserver.https_in_buf, https_admin_server_receive_message, NULL, NULL, &adminserver);
		bufferevent_enable(adminserver.https_in_buf, EV_READ);
	}

	if(use_cli) {
		if(!cli_addr_set) {
			if(make_ioa_addr((const u08bits*)CLI_DEFAULT_IP,0,&cli_addr)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot set cli address %s\n",CLI_DEFAULT_IP);
				return;
			}
		}

		addr_set_port(&cli_addr,cli_port);

		adminserver.listen_fd = socket(cli_addr.ss.sa_family, ADMIN_STREAM_SOCKET_TYPE, ADMIN_STREAM_SOCKET_PROTOCOL);
		if (adminserver.listen_fd < 0) {
			perror("socket");
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot open CLI socket\n");
			return;
		}

		if(addr_bind(adminserver.listen_fd,&cli_addr,1,1,TCP_SOCKET)<0) {
			perror("Cannot bind CLI socket to addr");
			char saddr[129];
			addr_to_string(&cli_addr,(u08bits*)saddr);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot bind CLI listener socket to addr %s\n",saddr);
			socket_closesocket(adminserver.listen_fd);
			return;
		}

		socket_tcp_set_keepalive(adminserver.listen_fd,TCP_SOCKET);

		socket_set_nonblocking(adminserver.listen_fd);

		adminserver.l = evconnlistener_new(adminserver.event_base,
			  cliserver_input_handler, &adminserver,
			  LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
			  1024, adminserver.listen_fd);

		if(!(adminserver.l)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot create CLI listener\n");
			socket_closesocket(adminserver.listen_fd);
			return;
		}

		addr_debug_print(adminserver.verbose, &cli_addr,"CLI listener opened on ");
	}

	adminserver.sessions = ur_map_create();
}

void admin_server_receive_message(struct bufferevent *bev, void *ptr)
{
	UNUSED_ARG(ptr);

	struct turn_session_info *tsi = (struct turn_session_info*)turn_malloc(sizeof(struct turn_session_info));
	turn_session_info_init(tsi);
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);

	while ((n = evbuffer_remove(input, tsi, sizeof(struct turn_session_info))) > 0) {
		if (n != sizeof(struct turn_session_info)) {
			fprintf(stderr,"%s: Weird CLI buffer error: size=%d\n",__FUNCTION__,n);
			continue;
		}

		ur_map_value_type t = 0;
		if (ur_map_get(adminserver.sessions, (ur_map_key_type)tsi->id, &t) && t) {
			struct turn_session_info *old = (struct turn_session_info*)t;
			turn_session_info_clean(old);
			turn_free(old,sizeof(struct turn_session_info));
			ur_map_del(adminserver.sessions, (ur_map_key_type)tsi->id, NULL);
		}

		if(tsi->valid) {
			ur_map_put(adminserver.sessions, (ur_map_key_type)tsi->id, (ur_map_value_type)tsi);
			tsi = (struct turn_session_info*)turn_malloc(sizeof(struct turn_session_info));
			turn_session_info_init(tsi);
		} else {
			turn_session_info_clean(tsi);
		}
	}

	if(tsi) {
		turn_session_info_clean(tsi);
		turn_free(tsi,sizeof(struct turn_session_info));
	}
}

int send_turn_session_info(struct turn_session_info* tsi)
{
	int ret = -1;

	if(tsi) {
		struct evbuffer *output = bufferevent_get_output(adminserver.out_buf);
		if(output) {
			if(evbuffer_add(output,tsi,sizeof(struct turn_session_info))>=0) {
				ret = 0;
			}
		}
	}

	return ret;
}

/////////// HTTPS /////////////

enum _AS_FORM {
	AS_FORM_LOGON,
	AS_FORM_LOGOUT,
	AS_FORM_PC,
	AS_FORM_HOME,
	AS_FORM_TOGGLE,
	AS_FORM_UPDATE,
	AS_FORM_PS,
	AS_FORM_USERS,
	AS_FORM_SS,
	AS_FORM_OS,
	AS_FORM_OAUTH,
	AS_FORM_OAUTH_SHOW_KEYS,
	AS_FORM_UNKNOWN
};

typedef enum _AS_FORM AS_FORM;

#define HR_USERNAME "uname"
#define HR_PASSWORD "pwd"
#define HR_PASSWORD1 "pwd1"
#define HR_REALM "realm"
#define HR_ADD_USER "add_user"
#define HR_ADD_REALM "add_user_realm"
#define HR_ADD_SECRET "add_secret"
#define HR_ADD_ORIGIN "add_origin"
#define HR_CLIENT_PROTOCOL "cprotocol"
#define HR_USER_PATTERN "puser"
#define HR_MAX_SESSIONS "maxsess"
#define HR_CANCEL_SESSION "cs"
#define HR_DELETE_USER "du"
#define HR_DELETE_REALM "dr"
#define HR_DELETE_SECRET "ds"
#define HR_DELETE_ORIGIN "do"
#define HR_DELETE_IP "dip"
#define HR_DELETE_IP_REALM "dipr"
#define HR_DELETE_IP_KIND "dipk"
#define HR_ADD_IP "aip"
#define HR_ADD_IP_REALM "aipr"
#define HR_ADD_IP_KIND "aipk"
#define HR_UPDATE_PARAMETER "togglepar"
#define HR_ADD_OAUTH_KID "oauth_kid"
#define HR_ADD_OAUTH_REALM "oauth_realm"
#define HR_ADD_OAUTH_TS "oauth_ts"
#define HR_ADD_OAUTH_LT "oauth_lt"
#define HR_ADD_OAUTH_IKM "oauth_ikm"
#define HR_ADD_OAUTH_TEA "oauth_tea"
#define HR_DELETE_OAUTH_KID "oauth_kid_del"
#define HR_OAUTH_KID "kid"

struct form_name {
	AS_FORM form;
	const char* name;
};

static struct form_name form_names[] = {
				{AS_FORM_LOGON,"/logon"},
				{AS_FORM_LOGOUT,"/logout"},
				{AS_FORM_PC,"/pc"},
				{AS_FORM_HOME,"/home"},
				{AS_FORM_TOGGLE,"/toggle"},
				{AS_FORM_UPDATE,"/update"},
				{AS_FORM_PS,"/ps"},
				{AS_FORM_USERS,"/us"},
				{AS_FORM_SS,"/ss"},
				{AS_FORM_OS,"/os"},
				{AS_FORM_OAUTH,"/oauth"},
				{AS_FORM_OAUTH_SHOW_KEYS,"/oauth_show_keys"},
				{AS_FORM_UNKNOWN,NULL}
};

#define admin_title "TURN Server (https admin connection)"
#define __bold_admin_title "<b>TURN Server</b><br><i>https admin connection</i><br>\r\n"
#define bold_admin_title get_bold_admin_title()

static ioa_socket_handle current_socket = NULL;

static char *get_bold_admin_title(void)
{
	static char sbat[1025];
	STRCPY(sbat,__bold_admin_title);
	if(current_socket && current_socket->special_session) {
		struct admin_session* as = (struct admin_session*)current_socket->special_session;
		if(as->as_ok) {
			if(as->as_login[0]) {
				char *dst=sbat+strlen(sbat);
				snprintf(dst,ADMIN_USER_MAX_LENGTH*2," admin user: <b><i>%s</i></b><br>\r\n",as->as_login);
			}
			if(as->as_realm[0]) {
				char *dst=sbat+strlen(sbat);
				snprintf(dst,STUN_MAX_REALM_SIZE*2," admin session realm: <b><i>%s</i></b><br>\r\n",as->as_realm);
			} else if(as->as_eff_realm[0]) {
				char *dst=sbat+strlen(sbat);
				snprintf(dst,STUN_MAX_REALM_SIZE*2," admin session realm: <b><i>%s</i></b><br>\r\n",as->as_eff_realm);
			}
		}
	}
	return sbat;
}

static int wrong_html_name(const char* s)
{
	int ret = 0;
	if(s) {
		char* v=evhttp_encode_uri(s);
		ret = strcmp(v,s);
		free(v);
	}
	return ret;
}

static int is_as_ok(ioa_socket_handle s) {
	return (s && s->special_session &&
			((struct admin_session*)s->special_session)->as_ok);
}

static int is_superuser(void) {
	return (is_as_ok(current_socket) &&
			(!((struct admin_session*)current_socket->special_session)->as_realm[0]));
}

static char* current_realm(void) {
	if(current_socket && current_socket->special_session && ((struct admin_session*)current_socket->special_session)->as_ok) {
		return ((struct admin_session*)current_socket->special_session)->as_realm;
	} else {
		static char bad_realm[1025] = "_ERROR:UNKNOWN_REALM__";
		return bad_realm;
	}
}

static char* current_eff_realm(void) {
	char* r = current_realm();
	if(r && r[0]) return r;
	else if(current_socket && current_socket->special_session && ((struct admin_session*)current_socket->special_session)->as_ok) {
		return ((struct admin_session*)current_socket->special_session)->as_eff_realm;
	} else {
		static char bad_eff_realm[1025] = "_ERROR:UNKNOWN_REALM__";
		return bad_eff_realm;
	}
}

static size_t current_max_output_sessions(void) {
	if(current_socket && current_socket->special_session && ((struct admin_session*)current_socket->special_session)->as_ok) {
		return ((struct admin_session*)current_socket->special_session)->number_of_user_sessions;
	}
	return DEFAULT_CLI_MAX_OUTPUT_SESSIONS;
}

static void set_current_max_output_sessions(size_t value) {
	if(current_socket && current_socket->special_session && ((struct admin_session*)current_socket->special_session)->as_ok) {
		((struct admin_session*)current_socket->special_session)->number_of_user_sessions = value;
	}
}

static void https_cancel_session(const char* ssid)
{
	if(ssid && *ssid) {
		turnsession_id sid = (turnsession_id)strtoull(ssid,NULL,10);
		send_session_cancellation_to_relay(sid);
	}
}

static void https_print_top_page_header(struct str_buffer *sb)
{
	str_buffer_append(sb,"<!DOCTYPE html>\r\n<html>\r\n  <head>\r\n    <title>");
	str_buffer_append(sb,admin_title);
	str_buffer_append(sb,"</title>\r\n <style> table, th, td { border: 1px solid black; border-collapse: collapse; text-align: left; padding: 5px;} table#msg th { color: red; background-color: white; } </style> </head>\r\n  <body>\r\n    ");
	str_buffer_append(sb,bold_admin_title);
}

static void https_print_page_header(struct str_buffer *sb)
{
	https_print_top_page_header(sb);
	str_buffer_append(sb,"<br><a href=\"/home?");
	str_buffer_append(sb,HR_REALM);
	str_buffer_append(sb,"=");
	str_buffer_append(sb,current_eff_realm());
	str_buffer_append(sb,"\">home page</a><br>\r\n<br><a href=\"/logout\">logout</a><br>\r\n");
	str_buffer_append(sb,"<br>\r\n");
}

static void https_finish_page(struct str_buffer *sb, ioa_socket_handle s, int cclose)
{
	str_buffer_append(sb,"</body>\r\n</html>\r\n");

	send_str_from_ioa_socket_tcp(s,"HTTP/1.1 200 OK\r\nServer: ");
	send_str_from_ioa_socket_tcp(s,TURN_SOFTWARE);
	send_str_from_ioa_socket_tcp(s,"\r\n");
	send_str_from_ioa_socket_tcp(s,get_http_date_header());
	if(cclose) {
		send_str_from_ioa_socket_tcp(s,"Connection: close");
	}
	send_str_from_ioa_socket_tcp(s,"Content-Type: text/html; charset=UTF-8\r\nContent-Length: ");

	send_ulong_from_ioa_socket_tcp(s,str_buffer_get_str_len(sb));

	send_str_from_ioa_socket_tcp(s,"\r\n\r\n");
	send_str_from_ioa_socket_tcp(s,str_buffer_get_str(sb));

	str_buffer_free(sb);
}

static AS_FORM get_form(const char* path) {
	if(path) {
		size_t i = 0;
		while(form_names[i].name) {
			if(!strcmp(form_names[i].name,path))
				return form_names[i].form;
			++i;
		}
	}
	return AS_FORM_UNKNOWN;
}

static void write_https_logon_page(ioa_socket_handle s)
{
	if(s && !ioa_socket_tobeclosed(s)) {

		struct str_buffer* sb = str_buffer_new();

		https_print_top_page_header(sb);

		int we_have_admin_users = 0;
		const turn_dbdriver_t * dbd = get_dbdriver();
		if (dbd && dbd->list_admin_users) {
			int ausers = dbd->list_admin_users(1);
			if(ausers>0) {
				we_have_admin_users = 1;
			}
		}

		if(!we_have_admin_users) {
			str_buffer_append(sb,"<br>To use the HTTPS admin connection, you have to set the database table <b><i>admin_user</i></b> with the admin user accounts.<br>\r\n");
		} else {
			str_buffer_append(sb,"<br><br>\r\n");
			str_buffer_append(sb,"<form action=\"");
			str_buffer_append(sb,form_names[AS_FORM_LOGON].name);
			str_buffer_append(sb,"\" method=\"POST\">\r\n");
			str_buffer_append(sb,"  <fieldset><legend>Admin user information:</legend>  user name:<br><input required type=\"text\" name=\"");
			str_buffer_append(sb,HR_USERNAME);
			str_buffer_append(sb,"\" value=\"\"><br>password:<br><input required type=\"password\" name=\"");
			str_buffer_append(sb,HR_PASSWORD);
			str_buffer_append(sb,"\" value=\"\"><br><br><input type=\"submit\" value=\"Login\"></fieldset>\r\n");
			str_buffer_append(sb,"</form>\r\n");
		}

		https_finish_page(sb,s,!we_have_admin_users);
	}
}

static void write_https_home_page(ioa_socket_handle s)
{
	if(s && !ioa_socket_tobeclosed(s)) {

		if(!is_as_ok(s)) {
			write_https_logon_page(s);
		} else {

			struct str_buffer* sb = str_buffer_new();

			https_print_page_header(sb);

			str_buffer_append(sb,"<form action=\"");
			str_buffer_append(sb,form_names[AS_FORM_HOME].name);
			str_buffer_append(sb,"\" method=\"POST\">\r\n");
			str_buffer_append(sb,"  <fieldset><legend>Actions:</legend>\r\n");

			str_buffer_append(sb,"  Realm name: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"\"");
			if(!is_superuser()) {
			  str_buffer_append(sb," disabled >");
			} else {
			  str_buffer_append(sb,"> <input type=\"submit\" value=\"Set Admin Session Realm\" >");
			}

			str_buffer_append(sb,"<br>");

			str_buffer_append(sb,"<br><a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_PC].name);
			str_buffer_append(sb,"?");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"\">Configuration Parameters</a>");

			str_buffer_append(sb,"<br><a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_PS].name);
			str_buffer_append(sb,"?");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"&");
			str_buffer_append(sb,HR_MAX_SESSIONS);
			str_buffer_append(sb,"=");
			str_buffer_append_sz(sb,current_max_output_sessions());
			str_buffer_append(sb,"\">TURN Sessions</a>");

			str_buffer_append(sb,"<br><a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_USERS].name);
			str_buffer_append(sb,"?");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"\">Users</a>");

			str_buffer_append(sb,"<br><a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_SS].name);
			str_buffer_append(sb,"?");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"\">Shared Secrets (for TURN REST API)</a>");

			str_buffer_append(sb,"<br><a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_OS].name);
			str_buffer_append(sb,"?");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"\">Origins</a>");

			if(is_superuser()) {
			  if(ENC_ALG_NUM>0) {
			  	str_buffer_append(sb,"<br><a href=\"");
			  	str_buffer_append(sb,form_names[AS_FORM_OAUTH].name);
			  	str_buffer_append(sb,"?");
			  	str_buffer_append(sb,HR_REALM);
			  	str_buffer_append(sb,"=");
			  	str_buffer_append(sb,current_eff_realm());
			  	str_buffer_append(sb,"\">oAuth keys</a>");
			  }
			}

			str_buffer_append(sb,"</fieldset>\r\n");
			str_buffer_append(sb,"</form>\r\n");

			https_finish_page(sb,s,0);
		}
	}
}

static void sbprintf(struct str_buffer *sb, const char *format, ...)
{
	if(sb && format) {
		va_list args;
		va_start (args, format);
		char s[1025]="\0";
		vsnprintf(s,sizeof(s)-1,format, args);
		str_buffer_append(sb,s);
		va_end (args);
	}
}

static void https_print_flag(struct str_buffer* sb, int flag, const char* name, const char* param_name)
{
	if(sb && name) {
		if(!is_superuser())
			param_name = 0;
		if(!param_name) {
			sbprintf(sb,"<tr><td>%s</td><td>%s</td></tr>\r\n",name,get_flag(flag));
		} else {
			sbprintf(sb,"<tr><td>%s</td><td><a href=\"/toggle?%s=%s\">%s</a></td></tr>\r\n",name,HR_UPDATE_PARAMETER,param_name,get_flag(flag));
		}
	}
}

static void https_print_uint(struct str_buffer* sb, unsigned long value, const char* name, const char* param_name)
{
	if(sb && name) {
		if(!is_superuser())
			param_name = 0;
		if(!param_name) {
			if(value) {
				sbprintf(sb,"<tr><td>%s</td><td>%lu</td></tr>\r\n",name,value);
			} else {
				sbprintf(sb,"<tr><td>%s</td><td> </td></tr>\r\n",name);
			}
		} else {
			if(value) {
				sbprintf(sb,"<tr><td>%s</td><td> <form action=\"%s?%s=%s\" method=\"POST\"><input type=\"text\" name=\"%s\" value=\"%lu\"><input type=\"submit\" value=\"Update\"></form> </td></tr>\r\n",name,form_names[AS_FORM_UPDATE].name,HR_UPDATE_PARAMETER,param_name,param_name,value);
			} else {
				sbprintf(sb,"<tr><td>%s</td><td> <form action=\"%s?%s=%s\" method=\"POST\"><input type=\"text\" name=\"%s\" value=\"\"><input type=\"submit\" value=\"Update\"></form> </td></tr>\r\n",name,form_names[AS_FORM_UPDATE].name,HR_UPDATE_PARAMETER,param_name,param_name);
			}
		}
	}
}

static void https_print_str(struct str_buffer* sb, const char *value, const char* name, const char* param_name)
{
	if(sb && name && value) {
		if(!is_superuser())
			param_name = 0;
		if(!param_name) {
			sbprintf(sb,"<tr><td>%s</td><td>%s</td></tr>\r\n",name,value);
		} else {
			sbprintf(sb,"<tr><td>%s</td><td> <form action=\"%s?%s=%s\" method=\"POST\"><input type=\"text\" name=\"%s\" value=\"%s\"><input type=\"submit\" value=\"Update\"></form> </td></tr>\r\n",name,form_names[AS_FORM_UPDATE].name,HR_UPDATE_PARAMETER,param_name,param_name,value);
		}
	}
}

static void https_print_str_array(struct str_buffer* sb, char **value, size_t sz, const char* name)
{
	if(sb && name && value && sz) {
		size_t i;
		for(i=0;i<sz;i++) {
			if(value[i]) {
				sbprintf(sb,"<tr><td>  %s</td><td> %s</td></tr>\r\n",name,value[i]);
			}
		}
	}
}

static void https_print_addr(struct str_buffer* sb, ioa_addr *value, int use_port, const char* name)
{
	if(sb && name && value) {
		char s[256];
		if(!use_port)
			addr_to_string_no_port(value,(u08bits*)s);
		else
			addr_to_string(value,(u08bits*)s);
		sbprintf(sb,"<tr><td>  %s</td><td> %s</td></tr>\r\n",name,s);
	}
}

static size_t https_print_addr_list(struct str_buffer* sb, turn_server_addrs_list_t *value, int use_port, const char* name)
{
	if(sb && name && value && value->size && value->addrs) {
		char s[256];
		size_t i;
		for(i=0;i<value->size;i++) {
			if(!use_port)
				addr_to_string_no_port(&(value->addrs[i]),(u08bits*)s);
			else
				addr_to_string(&(value->addrs[i]),(u08bits*)s);
			sbprintf(sb,"</tr><td>  %s</td><td> %s</td></tr>\r\n",name,s);
		}
		return i;
	}
	return 0;
}

static const char* change_ip_addr_html(int dynamic,const char* kind,const char* ip,const char *realm, char *buffer, size_t sz)
{
	if(!buffer || !sz) {
		return "";
	} else {
		buffer[0]=0;
		if(dynamic && kind && ip) {

			if(!realm) realm="";

			if(current_realm()[0] && strcmp(current_realm(),realm)) {
				//delete forbidden
			} else {
				char *eip = evhttp_encode_uri(ip);
				snprintf(buffer,sz-1,"<a href=\"%s?%s=%s&%s=%s&%s=%s\">delete</a>",form_names[AS_FORM_UPDATE].name,HR_DELETE_IP_KIND,kind,HR_DELETE_IP_REALM,realm,HR_DELETE_IP,eip);
				free(eip);
			}
		}
		return buffer;
	}
}

static void https_print_ip_range_list(struct str_buffer* sb, ip_range_list_t *value, const char* name, const char* kind, int dynamic)
{
	if(sb && name) {
		if(value && value->rs) {
			size_t i;
			char buffer[1025];
			for(i=0;i<value->ranges_number;++i) {
				if(value->rs[i].realm[0]) {
					if(current_eff_realm()[0] && strcmp(current_eff_realm(),value->rs[i].realm)) {
						continue;
					} else {
						sbprintf(sb,"<tr><td>  %s</td><td> %s [%s] %s</td></tr>\r\n",name,value->rs[i].str,value->rs[i].realm, change_ip_addr_html(dynamic,kind,value->rs[i].str,value->rs[i].realm,buffer,sizeof(buffer)));
					}
				} else {
					sbprintf(sb,"<tr><td>  %s</td><td> %s %s</td></tr>\r\n",name,value->rs[i].str, change_ip_addr_html(dynamic,kind,value->rs[i].str,value->rs[i].realm,buffer,sizeof(buffer)));
				}
			}
		}

		if(dynamic) {
			sbprintf(sb,"<tr><td> Add %s</td><td>",name);
			sbprintf(sb,"<form action=\"%s?%s=%s\" method=\"POST\">IP range:<input required type=\"text\" name=\"%s\" value=\"\" >",form_names[AS_FORM_UPDATE].name,HR_ADD_IP_KIND,kind,HR_ADD_IP);
			sbprintf(sb,"Realm: <input type=\"text\" name=\"%s\" value=\"%s\" ",HR_ADD_IP_REALM,current_eff_realm());
			if(!is_superuser()) {
				sbprintf(sb," disabled ");
			}
			sbprintf(sb,">");
			sbprintf(sb,"<input type=\"submit\" value=\"Add IP\"></form> </td></tr>\r\n");
		}
	}
}

static void toggle_param(const char* pn)
{
	if(is_superuser()) {
		if(pn) {
			int i=0;
			while(tcmds[i].cmd && tcmds[i].data) {
				if(strcmp(tcmds[i].cmd,pn) == 0) {
					*(tcmds[i].data) = !(*(tcmds[i].data));
					return;
				}
				++i;
			}
		}
	}
}

static void update_param(const char* pn, const char *value)
{
	if(pn) {
		if(!value)
			value = "0";
		if(is_superuser()) {
			if(strstr(pn,"total-quota")==pn) {
				turn_params.total_quota = atoi(value);
			} else if(strstr(pn,"user-quota")==pn) {
				turn_params.user_quota = atoi(value);
			} else if(strstr(pn,"max-bps")==pn) {
				set_max_bps((band_limit_t)strtoul(value,NULL,10));
			} else if(strstr(pn,"bps-capacity")==pn) {
				set_bps_capacity((band_limit_t)strtoul(value,NULL,10));
			}
		}
		{
			realm_params_t *rp = get_realm(current_eff_realm());
			if(!rp) rp = get_realm(NULL);

			const turn_dbdriver_t * dbd = get_dbdriver();
			if (dbd && dbd->set_realm_option_one) {
				if(strstr(pn,"cr-total-quota")==pn) {
					rp->options.perf_options.total_quota = atoi(value);
					dbd->set_realm_option_one((u08bits*)rp->options.name,rp->options.perf_options.total_quota,"total-quota");
				} else if(strstr(pn,"cr-user-quota")==pn) {
					rp->options.perf_options.user_quota = atoi(value);
					dbd->set_realm_option_one((u08bits*)rp->options.name,rp->options.perf_options.user_quota,"user-quota");
				} else if(strstr(pn,"cr-max-bps")==pn) {
					rp->options.perf_options.max_bps = (band_limit_t)strtoul(value,NULL,10);
					dbd->set_realm_option_one((u08bits*)rp->options.name,rp->options.perf_options.max_bps,"max-bps");
				}
			}
		}
	}
}

static void https_print_empty_row(struct str_buffer* sb, size_t span)
{
	str_buffer_append(sb,"<tr><td colspan=");
	str_buffer_append_sz(sb,span);
	str_buffer_append(sb,"><br></td></tr>");
}

static void write_pc_page(ioa_socket_handle s)
{
	if(s && !ioa_socket_tobeclosed(s)) {

		if(!is_as_ok(s)) {
			write_https_logon_page(s);
		} else {

			struct str_buffer* sb = str_buffer_new();

			https_print_page_header(sb);

			str_buffer_append(sb,"<br>\r\n");
			str_buffer_append(sb,"<b>Configuration Parameters:</b><br><br><table  style=\"width:100%\">\r\n");
			str_buffer_append(sb,"<tr><th>Parameter</th><th>Value</th></tr>\r\n");

			{
				https_print_flag(sb,turn_params.verbose,"verbose",0);
				https_print_flag(sb,turn_params.turn_daemon,"daemon process",0);
				https_print_flag(sb,turn_params.stale_nonce,"stale-nonce","stale-nonce");
				https_print_flag(sb,turn_params.stun_only,"stun-only","stun-only");
				https_print_flag(sb,turn_params.no_stun,"no-stun","no-stun");
				https_print_flag(sb,turn_params.secure_stun,"secure-stun","secure-stun");
				https_print_flag(sb,turn_params.do_not_use_config_file,"do-not-use-config-file",0);
				https_print_flag(sb,turn_params.rfc5780,"RFC5780 support",0);
				https_print_uint(sb,(unsigned int)turn_params.net_engine_version,"net engine version",0);
				https_print_str(sb,turn_params.net_engine_version_txt[(int)turn_params.net_engine_version],"net engine",0);
				https_print_flag(sb,turn_params.fingerprint,"enforce fingerprints",0);
				https_print_flag(sb,turn_params.mobility,"mobility","mobility");
				https_print_flag(sb,turn_params.udp_self_balance,"udp-self-balance",0);
				https_print_str(sb,turn_params.pidfile,"pidfile",0);
				https_print_uint(sb,(unsigned long)getuid(),"process user ID",0);
				https_print_uint(sb,(unsigned long)getgid(),"process group ID",0);

				{
					char wd[1025];
					if(getcwd(wd,sizeof(wd)-1)) {
						https_print_str(sb,wd,"process dir",0);
					}
				}

				https_print_empty_row(sb,2);

				if(turn_params.cipher_list[0])
					https_print_str(sb,turn_params.cipher_list,"cipher-list",0);
				else
					https_print_str(sb,DEFAULT_CIPHER_LIST,"cipher-list",0);

				https_print_str(sb,turn_params.ec_curve_name,"ec-curve-name",0);
				{
					if(turn_params.dh_key_size == DH_CUSTOM)
						https_print_str(sb,turn_params.dh_file,"dh-file",0);
					else {
						unsigned int dh_key_length = 1066;
						if(turn_params.dh_key_size == DH_566)
							dh_key_length = 566;
						else if(turn_params.dh_key_size == DH_2066)
							dh_key_length = 2066;
						https_print_uint(sb,(unsigned long)dh_key_length,"DH-key-length",0);
					}
				}

				https_print_str(sb,turn_params.ca_cert_file,"Certificate Authority file",0);
				https_print_str(sb,turn_params.cert_file,"Certificate file",0);
				https_print_str(sb,turn_params.pkey_file,"Private Key file",0);

				https_print_empty_row(sb,2);

				https_print_str_array(sb,turn_params.listener.addrs,turn_params.listener.addrs_number,"Listener addr");

				if(turn_params.listener_ifname[0])
					https_print_str(sb,turn_params.listener_ifname,"listener-ifname",0);

				https_print_flag(sb,turn_params.no_udp,"no-udp",0);
				https_print_flag(sb,turn_params.no_tcp,"no-tcp",0);
				https_print_flag(sb,turn_params.no_dtls,"no-dtls",0);
				https_print_flag(sb,turn_params.no_tls,"no-tls",0);

				https_print_flag(sb,(!turn_params.no_tlsv1 && !turn_params.no_tls),"TLSv1.0",0);
				https_print_flag(sb,(!turn_params.no_tlsv1_1 && !turn_params.no_tls),"TLSv1.1",0);
				https_print_flag(sb,(!turn_params.no_tlsv1_2 && !turn_params.no_tls),"TLSv1.2",0);

				https_print_uint(sb,(unsigned long)turn_params.listener_port,"listener-port",0);
				https_print_uint(sb,(unsigned long)turn_params.tls_listener_port,"tls-listener-port",0);
				https_print_uint(sb,(unsigned long)turn_params.alt_listener_port,"alt-listener-port",0);
				https_print_uint(sb,(unsigned long)turn_params.alt_tls_listener_port,"alt-tls-listener-port",0);

				https_print_addr(sb,turn_params.external_ip,0,"External public IP");

				https_print_empty_row(sb,2);

				{
					size_t an = https_print_addr_list(sb,&turn_params.aux_servers_list,1,"Aux server");
					an += https_print_addr_list(sb,&turn_params.alternate_servers_list,1,"Alternate server");
					an += https_print_addr_list(sb,&turn_params.tls_alternate_servers_list,1,"TLS alternate server");

					if(an) {
						https_print_empty_row(sb,2);
					}
				}

				https_print_str_array(sb,turn_params.relay_addrs,turn_params.relays_number,"Relay addr");

				if(turn_params.relay_ifname[0])
					https_print_str(sb,turn_params.relay_ifname,"relay-ifname",0);

				https_print_flag(sb,turn_params.server_relay,"server-relay",0);

				https_print_flag(sb,turn_params.no_udp_relay,"no-udp-relay","no-udp-relay");
				https_print_flag(sb,turn_params.no_tcp_relay,"no-tcp-relay","no-tcp-relay");

				https_print_uint(sb,(unsigned long)turn_params.min_port,"min-port",0);
				https_print_uint(sb,(unsigned long)turn_params.max_port,"max-port",0);

				https_print_flag(sb,turn_params.no_multicast_peers,"no-multicast-peers","no-multicast-peers");
				https_print_flag(sb,turn_params.no_loopback_peers,"no-loopback-peers","no-loopback-peers");

				https_print_empty_row(sb,2);

				if(turn_params.default_users_db.persistent_users_db.userdb[0]) {
					switch(turn_params.default_users_db.userdb_type) {
#if !defined(TURN_NO_SQLITE)
					case TURN_USERDB_TYPE_SQLITE:
						https_print_str(sb,"SQLite","DB type",0);
						break;
#endif
#if !defined(TURN_NO_PQ)
					case TURN_USERDB_TYPE_PQ:
						https_print_str(sb,"Postgres","DB type",0);
						break;
#endif
#if !defined(TURN_NO_MYSQL)
					case TURN_USERDB_TYPE_MYSQL:
						https_print_str(sb,"MySQL/MariaDB","DB type",0);
						break;
#endif
#if !defined(TURN_NO_MONGO)
					case TURN_USERDB_TYPE_MONGO:
						https_print_str(sb,"MongoDB","DB type",0);
						break;
#endif
#if !defined(TURN_NO_HIREDIS)
					case TURN_USERDB_TYPE_REDIS:
						https_print_str(sb,"redis","DB type",0);
						break;
#endif
					default:
						https_print_str(sb,"unknown","DB type",0);
					};
					if(is_superuser()) {
						https_print_str(sb,turn_params.default_users_db.persistent_users_db.userdb,"DB",0);
					}
				} else {
					https_print_str(sb,"none","DB type",0);
					https_print_str(sb,"none","DB",0);
				}

#if !defined(TURN_NO_HIREDIS)
				if(is_superuser()) {
					if(turn_params.use_redis_statsdb && turn_params.redis_statsdb[0]) {
						https_print_str(sb,turn_params.redis_statsdb,"Redis Statistics DB",0);
					}
				}
#endif

				https_print_empty_row(sb,2);

				if(turn_params.ct == TURN_CREDENTIALS_LONG_TERM)
					https_print_flag(sb,1,"Long-term authorization mechanism",0);
				else
					https_print_flag(sb,1,"Anonymous credentials",0);
				https_print_flag(sb,turn_params.use_auth_secret_with_timestamp,"TURN REST API support",0);
				if(turn_params.use_auth_secret_with_timestamp) {

					if(!turn_params.rest_api_separator || ((unsigned int)turn_params.rest_api_separator == (unsigned int)':')) {
						https_print_str(sb,":","TURN REST API separator",0);
					} else {
						https_print_uint(sb,turn_params.rest_api_separator,"TURN REST API separator ASCII number",0);
					}
				}

				https_print_empty_row(sb,2);

				if(is_superuser()) {
					char * rn = get_realm(NULL)->options.name;
					if(rn[0])
						https_print_str(sb,rn,"Default realm",0);
				}

				realm_params_t *rp = get_realm(current_eff_realm());
				if(!rp) rp = get_realm(NULL);

				https_print_str(sb,rp->options.name,"Admin session (current) realm",0);

				https_print_uint(sb,(unsigned long)rp->options.perf_options.total_quota,"current realm max number of sessions (total-quota)","cr-total-quota");
				https_print_uint(sb,(unsigned long)rp->options.perf_options.user_quota,"current realm max sessions per user (user-quota)","cr-user-quota");
				https_print_uint(sb,(unsigned long)rp->options.perf_options.max_bps,"current realm max-bps (per session)","cr-max-bps");

				https_print_empty_row(sb,2);

				https_print_uint(sb,(unsigned long)rp->status.total_current_allocs,"total-current-allocs",0);

				https_print_empty_row(sb,2);

				https_print_uint(sb,(unsigned long)turn_params.total_quota,"Default total-quota (per realm)","total-quota");
				https_print_uint(sb,(unsigned long)turn_params.user_quota,"Default user-quota (per realm)","user-quota");
				https_print_uint(sb,(unsigned long)get_bps_capacity(),"Total bps-capacity (per server)","bps-capacity");
				https_print_uint(sb,(unsigned long)get_bps_capacity_allocated(),"Allocated bps-capacity (per server)",0);
				https_print_uint(sb,(unsigned long)get_max_bps(),"Default max-bps (per session)","max-bps");

				https_print_empty_row(sb,2);

				https_print_ip_range_list(sb,&turn_params.ip_whitelist,"Whitelist IP (static)",NULL,0);
				{
					ip_range_list_t* l = get_ip_list("allowed");
					https_print_ip_range_list(sb,l,"Whitelist IP (dynamic)","allowed",1);
					ip_list_free(l);
				}

				https_print_empty_row(sb,2);

				https_print_ip_range_list(sb,&turn_params.ip_blacklist,"Blacklist IP (static)", NULL, 0);
				{
					ip_range_list_t* l = get_ip_list("denied");
					https_print_ip_range_list(sb,l,"Blacklist IP (dynamic)", "denied", 1);
					ip_list_free(l);
				}
			}

			str_buffer_append(sb,"\r\n</table>\r\n");

			https_finish_page(sb,s,0);
		}
	}
}

struct https_ps_arg {
	struct str_buffer* sb;
	size_t counter;
	turn_time_t ct;
	const char* client_protocol;
	const char* user_pattern;
	size_t max_sessions;
	turnsession_id cs;
};

static int https_print_session(ur_map_key_type key, ur_map_value_type value, void *arg)
{
	if(key && value && arg) {
		struct https_ps_arg *csarg = (struct https_ps_arg*)arg;
		struct str_buffer* sb = csarg->sb;
		struct turn_session_info *tsi = (struct turn_session_info *)value;

		if(current_eff_realm()[0] && strcmp(current_eff_realm(),tsi->realm))
			return 0;

		if(csarg->user_pattern[0]) {
			if(!strstr((char*)tsi->username,csarg->user_pattern)) {
				return 0;
			}
		}

		if(csarg->cs == tsi->id) {
			return 0;
		}

		{
			const char *pn=csarg->client_protocol;
			if(pn[0]) {
				if(!strcmp(pn,"TLS") || !strcmp(pn,"tls") || !strcmp(pn,"Tls")) {
					if((tsi->client_protocol != TLS_SOCKET)||(tsi->client_protocol != TLS_SCTP_SOCKET))
						return 0;
					} else if(!strcmp(pn,"DTLS") || !strcmp(pn,"dtls") || !strcmp(pn,"Dtls")) {
						if(tsi->client_protocol != DTLS_SOCKET)
							return 0;
					} else if(!strcmp(pn,"TCP") || !strcmp(pn,"tcp") || !strcmp(pn,"Tcp")) {
						if((tsi->client_protocol != TCP_SOCKET)||(tsi->client_protocol != SCTP_SOCKET))
							return 0;
					} else if(!strcmp(pn,"UDP") || !strcmp(pn,"udp") || !strcmp(pn,"Udp")) {
						if(tsi->client_protocol != UDP_SOCKET)
							return 0;
					} else {
						return 0;
					}
				}
		}

		if((unsigned long)csarg->counter<(unsigned long)csarg->max_sessions) {
			str_buffer_append(sb,"<tr><td>");
			str_buffer_append_sz(sb,(size_t)(csarg->counter+1));
			str_buffer_append(sb,"</td><td>");
			str_buffer_append_sid(sb,tsi->id);
			str_buffer_append(sb,"<br><a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_PS].name);
			str_buffer_append(sb,"?cs=");
			str_buffer_append_sid(sb,tsi->id);
			str_buffer_append(sb,"\">cancel</a>");
			str_buffer_append(sb,"</td><td>");
			str_buffer_append(sb,(char*)tsi->username);
			str_buffer_append(sb,"</td><td>");
			str_buffer_append(sb,tsi->realm);
			str_buffer_append(sb,"</td><td>");
			str_buffer_append(sb,tsi->origin);
			str_buffer_append(sb,"</td><td>");
			if(turn_time_before(csarg->ct, tsi->start_time)) {
				str_buffer_append(sb,"undefined time\n");
			} else {
				str_buffer_append_sz(sb,(size_t)(csarg->ct - tsi->start_time));
			}
			str_buffer_append(sb,"</td><td>");
			if(turn_time_before(tsi->expiration_time,csarg->ct)) {
				str_buffer_append(sb,"expired");
			} else {
				str_buffer_append_sz(sb,(size_t)(tsi->expiration_time - csarg->ct));
			}
			str_buffer_append(sb,"</td><td>");
			str_buffer_append(sb,socket_type_name(tsi->client_protocol));
			str_buffer_append(sb,"</td><td>");
			str_buffer_append(sb,socket_type_name(tsi->peer_protocol));
			str_buffer_append(sb,"</td><td>");
			{
				if(!tsi->local_addr_data.saddr[0])
					addr_to_string(&(tsi->local_addr_data.addr),(u08bits*)tsi->local_addr_data.saddr);
				if(!tsi->remote_addr_data.saddr[0])
					addr_to_string(&(tsi->remote_addr_data.addr),(u08bits*)tsi->remote_addr_data.saddr);
				if(!tsi->relay_addr_data_ipv4.saddr[0])
					addr_to_string(&(tsi->relay_addr_data_ipv4.addr),(u08bits*)tsi->relay_addr_data_ipv4.saddr);
				if(!tsi->relay_addr_data_ipv6.saddr[0])
					addr_to_string(&(tsi->relay_addr_data_ipv6.addr),(u08bits*)tsi->relay_addr_data_ipv6.saddr);
				str_buffer_append(sb,tsi->remote_addr_data.saddr);
				str_buffer_append(sb,"</td><td>");
				str_buffer_append(sb,tsi->local_addr_data.saddr);
				str_buffer_append(sb,"</td><td>");
				str_buffer_append(sb,tsi->relay_addr_data_ipv4.saddr);
				str_buffer_append(sb,"</td><td>");
				str_buffer_append(sb,tsi->relay_addr_data_ipv6.saddr);
				str_buffer_append(sb,"</td><td>");
				str_buffer_append(sb,get_flag(tsi->enforce_fingerprints));
				str_buffer_append(sb,"</td><td>");
				str_buffer_append(sb,get_flag(tsi->is_mobile));
				str_buffer_append(sb,"</td><td>");
				str_buffer_append(sb,tsi->tls_method);
				str_buffer_append(sb,"</td><td>");
				str_buffer_append(sb,tsi->tls_cipher);
				str_buffer_append(sb,"</td><td>");
				str_buffer_append_sz(sb,(size_t)tsi->bps);
				str_buffer_append(sb,"</td><td>");
				{
					char str[1025];
					snprintf(str,sizeof(str)-1,"rp=%lu, rb=%lu, sp=%lu, sb=%lu\n",(unsigned long)(tsi->received_packets), (unsigned long)(tsi->received_bytes),(unsigned long)(tsi->sent_packets),(unsigned long)(tsi->sent_bytes));
					str_buffer_append(sb,str);
					str_buffer_append(sb,"</td><td>");
				}
				{
					char str[1025];
					snprintf(str,sizeof(str)-1,"r=%lu, s=%lu, total=%lu (bytes per sec)\n",(unsigned long)(tsi->received_rate), (unsigned long)(tsi->sent_rate),(unsigned long)(tsi->total_rate));
					str_buffer_append(sb,str);
					str_buffer_append(sb,"</td><td>");
				}

				if(tsi->main_peers_size) {
					size_t i;
					for(i=0;i<tsi->main_peers_size;++i) {
						if(!(tsi->main_peers_data[i].saddr[0]))
							addr_to_string(&(tsi->main_peers_data[i].addr),(u08bits*)tsi->main_peers_data[i].saddr);
						str_buffer_append(sb," ");
						str_buffer_append(sb,tsi->main_peers_data[i].saddr);
						str_buffer_append(sb," ");
					}
					if(tsi->extra_peers_size && tsi->extra_peers_data) {
						for(i=0;i<tsi->extra_peers_size;++i) {
							if(!(tsi->extra_peers_data[i].saddr[0]))
								addr_to_string(&(tsi->extra_peers_data[i].addr),(u08bits*)tsi->extra_peers_data[i].saddr);
							str_buffer_append(sb," ");
							str_buffer_append(sb,tsi->extra_peers_data[i].saddr);
							str_buffer_append(sb," ");
						}
					}
				}
				str_buffer_append(sb,"</td>");
			}
		}

		csarg->counter += 1;
	}
	return 0;
}

static size_t https_print_sessions(struct str_buffer* sb, const char* client_protocol, const char* user_pattern, size_t max_sessions, turnsession_id cs)
{
	struct https_ps_arg arg = {sb,0,0,client_protocol,user_pattern,max_sessions,cs};

	arg.ct = turn_time();

	ur_map_foreach_arg(adminserver.sessions, (foreachcb_arg_type)https_print_session, &arg);

	return arg.counter;
}

static void write_ps_page(ioa_socket_handle s, const char* client_protocol, const char* user_pattern, size_t max_sessions, turnsession_id cs)
{
	if(s && !ioa_socket_tobeclosed(s)) {

		if(!is_as_ok(s)) {
			write_https_logon_page(s);
		} else {

			struct str_buffer* sb = str_buffer_new();

			https_print_page_header(sb);

			str_buffer_append(sb,"<form action=\"");
			str_buffer_append(sb,form_names[AS_FORM_PS].name);
			str_buffer_append(sb,"\" method=\"POST\">\r\n");
			str_buffer_append(sb,"  <fieldset><legend>Filter:</legend>\r\n");

			str_buffer_append(sb,"  <br>Realm name: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"\"");
			if(!is_superuser()) {
				str_buffer_append(sb," disabled ");
			}
			str_buffer_append(sb,">");

			str_buffer_append(sb,"  Client protocol: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_CLIENT_PROTOCOL);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,client_protocol);
			str_buffer_append(sb,"\"");
			str_buffer_append(sb,">");

			str_buffer_append(sb,"  User name contains: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_USER_PATTERN);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,user_pattern);
			str_buffer_append(sb,"\"");
			str_buffer_append(sb,"><br><br>");

			str_buffer_append(sb,"  Max number of output sessions in the page: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_MAX_SESSIONS);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append_sz(sb,max_sessions);
			str_buffer_append(sb,"\"");
			str_buffer_append(sb,"><br>");

			str_buffer_append(sb,"<br><input type=\"submit\" value=\"Filter\">");

			str_buffer_append(sb,"</fieldset>\r\n");
			str_buffer_append(sb,"</form>\r\n");

			str_buffer_append(sb,"<br><b>TURN Sessions:</b><br><br><table>\r\n");
			str_buffer_append(sb,"<tr><th>N</th><th>Session ID</th><th>User</th><th>Realm</th><th>Origin</th><th>Age, secs</th><th>Expires, secs</th><th>Client protocol</th><th>Relay protocol</th><th>Client addr</th><th>Server addr</th><th>Relay addr (IPv4)</th><th>Relay addr (IPv6)</th><th>Fingerprints</th><th>Mobile</th><th>TLS method</th><th>TLS cipher</th><th>BPS (allocated)</th><th>Packets</th><th>Rate</th><th>Peers</th></tr>\r\n");

			size_t total_sz = https_print_sessions(sb,client_protocol,user_pattern,max_sessions,cs);

			str_buffer_append(sb,"\r\n</table>\r\n");

			str_buffer_append(sb,"<br>Total sessions = ");
			str_buffer_append_sz(sb,total_sz);
			str_buffer_append(sb,"<br>\r\n");

			https_finish_page(sb,s,0);
		}
	}
}

static size_t https_print_users(struct str_buffer* sb)
{
	size_t ret = 0;
	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->list_users) {
		secrets_list_t users,realms;
		init_secrets_list(&users);
		init_secrets_list(&realms);
		dbd->list_users((u08bits*)current_eff_realm(),&users,&realms);

		size_t sz = get_secrets_list_size(&users);
		size_t i;
		for(i=0;i<sz;++i) {
			str_buffer_append(sb,"<tr><td>");
			str_buffer_append_sz(sb,i+1);
			str_buffer_append(sb,"</td>");
			str_buffer_append(sb,"<td>");
			str_buffer_append(sb,get_secrets_list_elem(&users,i));
			str_buffer_append(sb,"</td>");
			if(!current_eff_realm()[0]) {
				str_buffer_append(sb,"<td>");
				str_buffer_append(sb,get_secrets_list_elem(&realms,i));
				str_buffer_append(sb,"</td>");
			}
			str_buffer_append(sb,"<td> <a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_USERS].name);
			str_buffer_append(sb,"?");
			str_buffer_append(sb,HR_DELETE_USER);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,get_secrets_list_elem(&users,i));
			str_buffer_append(sb,"&");
			str_buffer_append(sb,HR_DELETE_REALM);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,get_secrets_list_elem(&realms,i));
			str_buffer_append(sb,"\">delete</a>");
			str_buffer_append(sb,"</td>");
			str_buffer_append(sb,"</tr>");
			++ret;
		}

		clean_secrets_list(&users);
		clean_secrets_list(&realms);
	}

	return ret;
}

static void write_users_page(ioa_socket_handle s, const u08bits *add_user, const u08bits *add_realm, const char* msg)
{
	if(s && !ioa_socket_tobeclosed(s)) {

		if(!is_as_ok(s)) {
			write_https_logon_page(s);
		} else {

			struct str_buffer* sb = str_buffer_new();

			https_print_page_header(sb);

			str_buffer_append(sb,"<form action=\"");
			str_buffer_append(sb,form_names[AS_FORM_USERS].name);
			str_buffer_append(sb,"\" method=\"POST\">\r\n");
			str_buffer_append(sb,"  <fieldset><legend>Filter:</legend>\r\n");

			str_buffer_append(sb,"  <br>Realm name: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"\"");
			if(!is_superuser()) {
				str_buffer_append(sb," disabled ");
			}
			str_buffer_append(sb,">");

			str_buffer_append(sb,"<br><input type=\"submit\" value=\"Filter\">");

			str_buffer_append(sb,"</fieldset>\r\n");
			str_buffer_append(sb,"</form>\r\n");

			str_buffer_append(sb,"<form action=\"");
			str_buffer_append(sb,form_names[AS_FORM_USERS].name);
			str_buffer_append(sb,"\" method=\"POST\">\r\n");
			str_buffer_append(sb,"  <fieldset><legend>User:</legend>\r\n");

			if(msg && msg[0]) {
				str_buffer_append(sb,"<br><table id=\"msg\"><th>");
				str_buffer_append(sb,msg);
				str_buffer_append(sb,"</th></table><br>");
			}

			str_buffer_append(sb,"  <br>Realm name: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_ADD_REALM);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,(const char*)add_realm);
			str_buffer_append(sb,"\"");
			if(!is_superuser()) {
				str_buffer_append(sb," disabled ");
			}
			str_buffer_append(sb,"><br>\r\n");

			str_buffer_append(sb,"  <br>User name: <input required type=\"text\" name=\"");
			str_buffer_append(sb,HR_ADD_USER);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,(const char*)add_user);
			str_buffer_append(sb,"\"");
			str_buffer_append(sb,"><br>\r\n");

			str_buffer_append(sb,"  <br>Password: <input required type=\"password\" name=\"");
			str_buffer_append(sb,HR_PASSWORD);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,"");
			str_buffer_append(sb,"\"");
			str_buffer_append(sb,"><br>\r\n");

			str_buffer_append(sb,"  <br>Confirm password: <input required type=\"password\" name=\"");
			str_buffer_append(sb,HR_PASSWORD1);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,"");
			str_buffer_append(sb,"\"");
			str_buffer_append(sb,"><br><br>\r\n");

			str_buffer_append(sb,"<br><input type=\"submit\" value=\"Add user\">");

			str_buffer_append(sb,"</fieldset>\r\n");
			str_buffer_append(sb,"</form>\r\n");

			str_buffer_append(sb,"<br><b>Users:</b><br><br>\r\n");
			str_buffer_append(sb,"<table>\r\n");
			str_buffer_append(sb,"<tr><th>N</th><th>Name</th>");
			if(!current_eff_realm()[0]) {
				str_buffer_append(sb,"<th>Realm</th>");
			}
			str_buffer_append(sb,"<th> </th>");
			str_buffer_append(sb,"</tr>\r\n");

			size_t total_sz = https_print_users(sb);

			str_buffer_append(sb,"\r\n</table>\r\n");

			str_buffer_append(sb,"<br>Total users = ");
			str_buffer_append_sz(sb,total_sz);
			str_buffer_append(sb,"<br>\r\n");

			https_finish_page(sb,s,0);
		}
	}
}

static size_t https_print_secrets(struct str_buffer* sb)
{
	size_t ret = 0;
	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->list_secrets) {
		secrets_list_t secrets,realms;
		init_secrets_list(&secrets);
		init_secrets_list(&realms);
		dbd->list_secrets((u08bits*)current_eff_realm(),&secrets,&realms);

		size_t sz = get_secrets_list_size(&secrets);
		size_t i;
		for(i=0;i<sz;++i) {
			str_buffer_append(sb,"<tr><td>");
			str_buffer_append_sz(sb,i+1);
			str_buffer_append(sb,"</td>");
			str_buffer_append(sb,"<td>");
			str_buffer_append(sb,get_secrets_list_elem(&secrets,i));
			str_buffer_append(sb,"</td>");
			if(!current_eff_realm()[0]) {
				str_buffer_append(sb,"<td>");
				str_buffer_append(sb,get_secrets_list_elem(&realms,i));
				str_buffer_append(sb,"</td>");
			}
			str_buffer_append(sb,"<td> <a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_SS].name);
			str_buffer_append(sb,"?");
			str_buffer_append(sb,HR_DELETE_SECRET);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,get_secrets_list_elem(&secrets,i));
			str_buffer_append(sb,"&");
			str_buffer_append(sb,HR_DELETE_REALM);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,get_secrets_list_elem(&realms,i));
			str_buffer_append(sb,"\">delete</a>");
			str_buffer_append(sb,"</td>");
			str_buffer_append(sb,"</tr>");
			++ret;
		}

		clean_secrets_list(&secrets);
		clean_secrets_list(&realms);
	}

	return ret;
}

static void write_shared_secrets_page(ioa_socket_handle s, const char* add_secret, const char* add_realm, const char* msg)
{
	if(s && !ioa_socket_tobeclosed(s)) {

		if(!is_as_ok(s)) {
			write_https_logon_page(s);
		} else {

			struct str_buffer* sb = str_buffer_new();

			https_print_page_header(sb);

			str_buffer_append(sb,"<form action=\"");
			str_buffer_append(sb,form_names[AS_FORM_SS].name);
			str_buffer_append(sb,"\" method=\"POST\">\r\n");
			str_buffer_append(sb,"  <fieldset><legend>Filter:</legend>\r\n");

			str_buffer_append(sb,"  <br>Realm name: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"\"");
			if(!is_superuser()) {
				str_buffer_append(sb," disabled ");
			}
			str_buffer_append(sb,">");

			str_buffer_append(sb,"<br><input type=\"submit\" value=\"Filter\">");

			str_buffer_append(sb,"</fieldset>\r\n");
			str_buffer_append(sb,"</form>\r\n");

			str_buffer_append(sb,"<form action=\"");
			str_buffer_append(sb,form_names[AS_FORM_SS].name);
			str_buffer_append(sb,"\" method=\"POST\">\r\n");
			str_buffer_append(sb,"  <fieldset><legend>Secret:</legend>\r\n");

			if(msg && msg[0]) {
				str_buffer_append(sb,"<br><table id=\"msg\"><th>");
				str_buffer_append(sb,msg);
				str_buffer_append(sb,"</th></table><br>");
			}

			str_buffer_append(sb,"  <br>Realm name: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_ADD_REALM);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,(const char*)add_realm);
			str_buffer_append(sb,"\"");
			if(!is_superuser()) {
				str_buffer_append(sb," disabled ");
			}
			str_buffer_append(sb,"><br>\r\n");

			str_buffer_append(sb,"  <br>Secret: <input required type=\"text\" name=\"");
			str_buffer_append(sb,HR_ADD_SECRET);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,(const char*)add_secret);
			str_buffer_append(sb,"\"");
			str_buffer_append(sb,"><br>\r\n");

			str_buffer_append(sb,"<br><input type=\"submit\" value=\"Add secret\">");

			str_buffer_append(sb,"</fieldset>\r\n");
			str_buffer_append(sb,"</form>\r\n");

			str_buffer_append(sb,"<br><b>Shared secrets:</b><br><br>\r\n");
			str_buffer_append(sb,"<table>\r\n");
			str_buffer_append(sb,"<tr><th>N</th><th>Value</th>");
			if(!current_eff_realm()[0]) {
				str_buffer_append(sb,"<th>Realm</th>");
			}
			str_buffer_append(sb,"<th> </th>");
			str_buffer_append(sb,"</tr>\r\n");

			size_t total_sz = https_print_secrets(sb);

			str_buffer_append(sb,"\r\n</table>\r\n");

			str_buffer_append(sb,"<br>Total secrets = ");
			str_buffer_append_sz(sb,total_sz);
			str_buffer_append(sb,"<br>\r\n");

			https_finish_page(sb,s,0);
		}
	}
}

static size_t https_print_origins(struct str_buffer* sb)
{
	size_t ret = 0;
	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->list_origins) {
		secrets_list_t origins,realms;
		init_secrets_list(&origins);
		init_secrets_list(&realms);
		dbd->list_origins((u08bits*)current_eff_realm(),&origins,&realms);

		size_t sz = get_secrets_list_size(&origins);
		size_t i;
		for(i=0;i<sz;++i) {
			str_buffer_append(sb,"<tr><td>");
			str_buffer_append_sz(sb,i+1);
			str_buffer_append(sb,"</td>");
			str_buffer_append(sb,"<td>");
			str_buffer_append(sb,get_secrets_list_elem(&origins,i));
			str_buffer_append(sb,"</td>");
			if(!current_eff_realm()[0]) {
				str_buffer_append(sb,"<td>");
				str_buffer_append(sb,get_secrets_list_elem(&realms,i));
				str_buffer_append(sb,"</td>");
			}
			if(is_superuser()) {
				str_buffer_append(sb,"<td> <a href=\"");
				str_buffer_append(sb,form_names[AS_FORM_OS].name);
				str_buffer_append(sb,"?");
				str_buffer_append(sb,HR_DELETE_ORIGIN);
				str_buffer_append(sb,"=");
				str_buffer_append(sb,get_secrets_list_elem(&origins,i));
				str_buffer_append(sb,"\">delete</a>");
				str_buffer_append(sb,"</td>");
			}
			str_buffer_append(sb,"</tr>");
			++ret;
		}

		clean_secrets_list(&origins);
		clean_secrets_list(&realms);
	}

	return ret;
}

static void write_origins_page(ioa_socket_handle s, const char* add_origin, const char* add_realm, const char* msg)
{
	if(s && !ioa_socket_tobeclosed(s)) {

		if(!is_as_ok(s)) {
			write_https_logon_page(s);
		} else {

			struct str_buffer* sb = str_buffer_new();

			https_print_page_header(sb);

			str_buffer_append(sb,"<form action=\"");
			str_buffer_append(sb,form_names[AS_FORM_OS].name);
			str_buffer_append(sb,"\" method=\"POST\">\r\n");
			str_buffer_append(sb,"  <fieldset><legend>Filter:</legend>\r\n");

			str_buffer_append(sb,"  <br>Realm name: <input type=\"text\" name=\"");
			str_buffer_append(sb,HR_REALM);
			str_buffer_append(sb,"\" value=\"");
			str_buffer_append(sb,current_eff_realm());
			str_buffer_append(sb,"\"");
			if(!is_superuser()) {
				str_buffer_append(sb," disabled ");
			}
			str_buffer_append(sb,">");

			str_buffer_append(sb,"<br><input type=\"submit\" value=\"Filter\">");

			str_buffer_append(sb,"</fieldset>\r\n");
			str_buffer_append(sb,"</form>\r\n");

			if(is_superuser()) {
				str_buffer_append(sb,"<form action=\"");
				str_buffer_append(sb,form_names[AS_FORM_OS].name);
				str_buffer_append(sb,"\" method=\"POST\">\r\n");
				str_buffer_append(sb,"  <fieldset><legend>Origin:</legend>\r\n");

				if(msg && msg[0]) {
					str_buffer_append(sb,"<br><table id=\"msg\"><th>");
					str_buffer_append(sb,msg);
					str_buffer_append(sb,"</th></table><br>");
				}

				str_buffer_append(sb,"  <br>Realm name: <input required type=\"text\" name=\"");
				str_buffer_append(sb,HR_ADD_REALM);
				str_buffer_append(sb,"\" value=\"");
				str_buffer_append(sb,(const char*)add_realm);
				str_buffer_append(sb,"\"");
				str_buffer_append(sb,"><br>\r\n");

				str_buffer_append(sb,"  <br>Origin: <input required type=\"text\" name=\"");
				str_buffer_append(sb,HR_ADD_ORIGIN);
				str_buffer_append(sb,"\" value=\"");
				str_buffer_append(sb,(const char*)add_origin);
				str_buffer_append(sb,"\"");
				str_buffer_append(sb,"><br>\r\n");

				str_buffer_append(sb,"<br><input type=\"submit\" value=\"Add origin\">");

				str_buffer_append(sb,"</fieldset>\r\n");
				str_buffer_append(sb,"</form>\r\n");
			}

			str_buffer_append(sb,"<br><b>Origins:</b><br><br>\r\n");
			str_buffer_append(sb,"<table>\r\n");
			str_buffer_append(sb,"<tr><th>N</th><th>Value</th>");
			if(!current_eff_realm()[0]) {
				str_buffer_append(sb,"<th>Realm</th>");
			}
			if(is_superuser()) {
				str_buffer_append(sb,"<th> </th>");
			}
			str_buffer_append(sb,"</tr>\r\n");

			size_t total_sz = https_print_origins(sb);

			str_buffer_append(sb,"\r\n</table>\r\n");

			str_buffer_append(sb,"<br>Total origins = ");
			str_buffer_append_sz(sb,total_sz);
			str_buffer_append(sb,"<br>\r\n");

			https_finish_page(sb,s,0);
		}
	}
}

static size_t https_print_oauth_keys(struct str_buffer* sb)
{
	size_t ret = 0;
	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->list_oauth_keys) {
		secrets_list_t kids,teas,tss,lts,realms;
		init_secrets_list(&kids);
		init_secrets_list(&teas);
		init_secrets_list(&tss);
		init_secrets_list(&lts);
		init_secrets_list(&realms);
		dbd->list_oauth_keys(&kids,&teas,&tss,&lts,&realms);

		size_t sz = get_secrets_list_size(&kids);
		size_t i;
		for(i=0;i<sz;++i) {
			str_buffer_append(sb,"<tr><td>");
			str_buffer_append_sz(sb,i+1);
			str_buffer_append(sb,"</td>");
			str_buffer_append(sb,"<td>");
			str_buffer_append(sb,get_secrets_list_elem(&kids,i));
			str_buffer_append(sb,"</td>");

			str_buffer_append(sb,"<td><a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_OAUTH_SHOW_KEYS].name);
			str_buffer_append(sb,"?");
			str_buffer_append(sb,HR_OAUTH_KID);
			str_buffer_append(sb,"=");
			str_buffer_append(sb,get_secrets_list_elem(&kids,i));
			str_buffer_append(sb,"\"> show </a></td>");

			str_buffer_append(sb,"<td>");
			str_buffer_append(sb,get_secrets_list_elem(&tss,i));
			str_buffer_append(sb,"</td>");
			str_buffer_append(sb,"<td>");
			str_buffer_append(sb,get_secrets_list_elem(&lts,i));
			str_buffer_append(sb,"</td>");
			str_buffer_append(sb,"<td>");
			str_buffer_append(sb,get_secrets_list_elem(&teas,i));
			str_buffer_append(sb,"</td>");
			str_buffer_append(sb,"<td>");
			str_buffer_append(sb,get_secrets_list_elem(&realms,i));
			str_buffer_append(sb,"</td>");

			{
				str_buffer_append(sb,"<td> <a href=\"");
				str_buffer_append(sb,form_names[AS_FORM_OAUTH].name);
				str_buffer_append(sb,"?");
				str_buffer_append(sb,HR_DELETE_OAUTH_KID);
				str_buffer_append(sb,"=");
				str_buffer_append(sb,get_secrets_list_elem(&kids,i));
				str_buffer_append(sb,"\">delete</a>");
				str_buffer_append(sb,"</td>");
			}
			str_buffer_append(sb,"</tr>");
			++ret;
		}

		clean_secrets_list(&kids);
		clean_secrets_list(&teas);
		clean_secrets_list(&tss);
		clean_secrets_list(&lts);
		clean_secrets_list(&realms);
	}

	return ret;
}

static void write_https_oauth_show_keys(ioa_socket_handle s, const char* kid)
{
	if(s && !ioa_socket_tobeclosed(s)) {

		if(!is_as_ok(s)) {
			write_https_logon_page(s);
		} else if(!is_superuser()) {
			write_https_home_page(s);
		} else {

			struct str_buffer* sb = str_buffer_new();

			https_print_page_header(sb);

			str_buffer_append(sb,"<a href=\"");
			str_buffer_append(sb,form_names[AS_FORM_OAUTH].name);
			str_buffer_append(sb,"\">back to oauth list</a><br><br>\r\n");

			if(kid && kid[0]) {
				const turn_dbdriver_t * dbd = get_dbdriver();
				if (dbd && dbd->get_oauth_key) {
					oauth_key_data_raw key;
					if((*dbd->get_oauth_key)((const u08bits*)kid,&key)<0) {
						str_buffer_append(sb,"data retrieval error");
					} else {

						oauth_key_data okd;
						ns_bzero(&okd,sizeof(okd));

						convert_oauth_key_data_raw(&key, &okd);

						char err_msg[1025] = "\0";
						size_t err_msg_size = sizeof(err_msg) - 1;

						oauth_key okey;
						ns_bzero(&okey,sizeof(okey));

						if (convert_oauth_key_data(&okd, &okey, err_msg, err_msg_size) < 0) {
							str_buffer_append(sb,err_msg);
						} else {

							str_buffer_append(sb,"<table>\r\n");

							if(key.ikm_key[0]) {
								str_buffer_append(sb,"<tr><td>Base64-encoded key:</td><td>");
								str_buffer_append(sb,key.ikm_key);
								str_buffer_append(sb,"</td></tr>\r\n");
							}

							str_buffer_append(sb,"</table>\r\n");
						}
					}
				}
			}

			https_finish_page(sb,s,0);
		}
	}
}

static void write_https_oauth_page(ioa_socket_handle s,
				const char* add_kid,
				const char* add_ikm,
				const char* add_tea,
				const char *add_ts,
				const char* add_lt,
				const char* add_realm,
				const char* msg)
{
	if(s && !ioa_socket_tobeclosed(s)) {

		if(!is_as_ok(s)) {
			write_https_logon_page(s);
		} else if(!is_superuser()) {
			write_https_home_page(s);
		} else {

			struct str_buffer* sb = str_buffer_new();

			https_print_page_header(sb);

			{
				str_buffer_append(sb,"<form action=\"");
				str_buffer_append(sb,form_names[AS_FORM_OAUTH].name);
				str_buffer_append(sb,"\" method=\"POST\">\r\n");
				str_buffer_append(sb,"  <fieldset><legend>oAuth key:</legend>\r\n");

				if(msg && msg[0]) {
					str_buffer_append(sb,"<br><table id=\"msg\"><th>");
					str_buffer_append(sb,msg);
					str_buffer_append(sb,"</th></table><br>");
				}

				str_buffer_append(sb,"<table><tr><td>");

				{
					if(!add_kid) add_kid="";

					str_buffer_append(sb,"  <br>KID (required): <input required type=\"text\" name=\"");
					str_buffer_append(sb,HR_ADD_OAUTH_KID);
					str_buffer_append(sb,"\" value=\"");
					str_buffer_append(sb,(const char*)add_kid);
					str_buffer_append(sb,"\"><br>\r\n");
				}

				str_buffer_append(sb,"</td><td>");

				{
					if(!add_ts) add_ts="";

					str_buffer_append(sb,"  <br>Timestamp, secs (optional): <input type=\"number\" min=\"0\" name=\"");
					str_buffer_append(sb,HR_ADD_OAUTH_TS);
					str_buffer_append(sb,"\" value=\"");
					str_buffer_append(sb,(const char*)add_ts);
					str_buffer_append(sb,"\"><br>\r\n");
				}

				str_buffer_append(sb,"</td><td>");

				{
					if(!add_lt) add_lt="";

					str_buffer_append(sb,"  <br>Lifetime, secs (optional): <input type=\"number\" min=\"0\" name=\"");
					str_buffer_append(sb,HR_ADD_OAUTH_LT);
					str_buffer_append(sb,"\" value=\"");
					str_buffer_append(sb,(const char*)add_lt);
					str_buffer_append(sb,"\"><br>\r\n");
				}

				str_buffer_append(sb,"</td></tr>\r\n");

				str_buffer_append(sb,"<tr><td colspan=\"1\">");

				{
					if(!add_ikm) add_ikm = "";

					str_buffer_append(sb,"  <br>Base64-encoded input keying material (required):<br><textarea wrap=\"soft\" cols=40 rows=4 name=\"");
					str_buffer_append(sb,HR_ADD_OAUTH_IKM);
					str_buffer_append(sb,"\" maxLength=256 >");
					str_buffer_append(sb,(const char*)add_ikm);
					str_buffer_append(sb,"</textarea>");
					str_buffer_append(sb,"<br>\r\n");
				}

				str_buffer_append(sb,"</td><td>");

				{
					if(!add_realm) add_realm = "";

					str_buffer_append(sb,"  <br>Realm (optional): <input type=\"text\" name=\"");
					str_buffer_append(sb,HR_ADD_OAUTH_REALM);
					str_buffer_append(sb,"\" value=\"");
					str_buffer_append(sb,(const char*)add_realm);
					str_buffer_append(sb,"\"><br>\r\n");
				}

				str_buffer_append(sb,"</td><td>");

				{
					str_buffer_append(sb,"<br>Token encryption algorithm (required):<br>\r\n");

					if(!add_tea || !add_tea[0])
						add_tea = "A256GCM";

					str_buffer_append(sb,"<input type=\"radio\" name=\"");
					str_buffer_append(sb,HR_ADD_OAUTH_TEA);
					str_buffer_append(sb,"\" value=\"A128GCM\" ");
					if(!strcmp("A128GCM",add_tea)) {
						str_buffer_append(sb," checked ");
					}
					str_buffer_append(sb,">A128GCM\r\n<br>\r\n");

					str_buffer_append(sb,"<input type=\"radio\" name=\"");
					str_buffer_append(sb,HR_ADD_OAUTH_TEA);
					str_buffer_append(sb,"\" value=\"A256GCM\" ");
					if(!strcmp("A256GCM",add_tea)) {
						str_buffer_append(sb," checked ");
					}
					str_buffer_append(sb,">A256GCM\r\n<br>\r\n");
				}

				str_buffer_append(sb,"</td></tr>\r\n</table>\r\n");

				str_buffer_append(sb,"<br><input type=\"submit\" value=\"Add key\">");

				str_buffer_append(sb,"</fieldset>\r\n");
				str_buffer_append(sb,"</form>\r\n");
			}

			str_buffer_append(sb,"<br><b>OAuth keys:</b><br><br>\r\n");
			str_buffer_append(sb,"<table>\r\n");
			str_buffer_append(sb,"<tr><th>N</th><th>KID</th><th>keys</th>");
			str_buffer_append(sb,"<th>Timestamp, secs</th>");
			str_buffer_append(sb,"<th>Lifetime,secs</th>");
			str_buffer_append(sb,"<th>Token encryption algorithm</th>");
			str_buffer_append(sb,"<th>Realm</th>");
			str_buffer_append(sb,"<th> </th>");
			str_buffer_append(sb,"</tr>\r\n");

			size_t total_sz = https_print_oauth_keys(sb);

			str_buffer_append(sb,"\r\n</table>\r\n");

			str_buffer_append(sb,"<br>Total oAuth keys = ");
			str_buffer_append_sz(sb,total_sz);
			str_buffer_append(sb,"<br>\r\n");

			https_finish_page(sb,s,0);
		}
	}
}

static void handle_toggle_request(ioa_socket_handle s, struct http_request* hr)
{
	if(s && hr) {
		const char *param = get_http_header_value(hr, HR_UPDATE_PARAMETER, NULL);
		toggle_param(param);
	}
}

static void handle_update_request(ioa_socket_handle s, struct http_request* hr)
{
	if(s && hr) {
		{
			const char *param = get_http_header_value(hr, HR_UPDATE_PARAMETER, NULL);
			if(param) {
				update_param(param,get_http_header_value(hr,param,""));
			}
		}

		{
			const char* eip = get_http_header_value(hr, HR_DELETE_IP, NULL);
			if(eip && eip[0]) {
				char* ip = evhttp_decode_uri(eip);
				const char* r = get_http_header_value(hr, HR_DELETE_IP_REALM,"");
				const char* kind = get_http_header_value(hr, HR_DELETE_IP_KIND,"");

				const turn_dbdriver_t * dbd = get_dbdriver();
				if (dbd && dbd->set_permission_ip) {

					if(!r || !r[0]) {
						r = current_realm();
					}

					if(current_realm()[0] && strcmp(current_realm(),r)) {
						//forbidden
					} else {

						u08bits realm[STUN_MAX_REALM_SIZE+1]="\0";
						STRCPY(realm,r);

						dbd->set_permission_ip(kind, realm, ip, 1);
					}
				}
				free(ip);
			}
		}

		{
			const char* eip = get_http_header_value(hr, HR_ADD_IP,NULL);
			if(eip && eip[0]) {
				char* ip = evhttp_decode_uri(eip);

				if(check_ip_list_range(ip)<0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong address range format: %s\n", ip);
				} else {

					const char* r = get_http_header_value(hr, HR_ADD_IP_REALM,"");
					const char* kind = get_http_header_value(hr, HR_ADD_IP_KIND,"");

					const turn_dbdriver_t * dbd = get_dbdriver();
					if (dbd && dbd->set_permission_ip) {

						if(!r || !r[0]) {
							r = current_realm();
						}

						if(current_realm()[0] && strcmp(current_realm(),r)) {
							//forbidden
						} else {

							u08bits realm[STUN_MAX_REALM_SIZE+1]="\0";
							STRCPY(realm,r);

							dbd->set_permission_ip(kind, realm, ip, 0);
						}
					}
				}
				free(ip);
			}
		}
	}
}

static void handle_logon_request(ioa_socket_handle s, struct http_request* hr)
{
	if(s && hr) {
		const char *uname = get_http_header_value(hr, HR_USERNAME, NULL);
		const char *pwd = get_http_header_value(hr, HR_PASSWORD, NULL);

		struct admin_session* as = (struct admin_session*)s->special_session;
		if(!as) {
			as = (struct admin_session*)turn_malloc(sizeof(struct admin_session));
			ns_bzero(as,sizeof(struct admin_session));
			s->special_session = as;
			s->special_session_size = sizeof(struct admin_session);
		}

		if(!(as->as_ok) && uname && pwd) {
			const turn_dbdriver_t * dbd = get_dbdriver();
			if (dbd && dbd->get_admin_user) {
				password_t password;
				char realm[STUN_MAX_REALM_SIZE+1]="\0";
				if((*(dbd->get_admin_user))((const u08bits*)uname,(u08bits*)realm,password)>=0) {
					if(!check_password(pwd,(char*)password)) {
						STRCPY(as->as_login,uname);
						STRCPY(as->as_realm,realm);
						as->as_eff_realm[0]=0;
						as->as_ok = 1;
						as->number_of_user_sessions = DEFAULT_CLI_MAX_OUTPUT_SESSIONS;
					}
				}
			}
		}
	}
}

static void handle_logout_request(ioa_socket_handle s, struct http_request* hr)
{
	UNUSED_ARG(hr);
	if(s) {
		struct admin_session* as = (struct admin_session*)s->special_session;
		if(as) {
			as->as_login[0] = 0;
			as->as_ok = 0;
			as->as_realm[0] = 0;
			as->as_eff_realm[0] = 0;
		}
	}
}

static void handle_https(ioa_socket_handle s, ioa_network_buffer_handle nbh)
{
	current_socket = s;

	if(turn_params.verbose) {
		if(nbh) {
			((char*)ioa_network_buffer_data(nbh))[ioa_network_buffer_get_size(nbh)] = 0;
			if(!strstr((char*)ioa_network_buffer_data(nbh),"pwd")) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: HTTPS connection input: %s\n", __FUNCTION__, (char*)ioa_network_buffer_data(nbh));
			}
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: HTTPS connection initial input\n", __FUNCTION__);
		}
	}

	if(!nbh) {
		write_https_logon_page(s);
	} else {
		((char*)ioa_network_buffer_data(nbh))[ioa_network_buffer_get_size(nbh)] = 0;
		struct http_request* hr = parse_http_request((char*)ioa_network_buffer_data(nbh));
		if(!hr) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: wrong HTTPS request (I cannot parse it)\n", __FUNCTION__);
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: HTTPS request, path %s\n", __FUNCTION__,hr->path);

			AS_FORM form = get_form(hr->path);

			switch(form) {
			case AS_FORM_PC: {
				if(is_as_ok(s)) {
					const char *realm0 = get_http_header_value(hr, HR_REALM, current_realm());
					if(!is_superuser())
						realm0 = current_realm();
					strncpy(current_eff_realm(),realm0,STUN_MAX_REALM_SIZE);
					write_pc_page(s);
				} else {
					write_https_logon_page(s);
				}
				break;
			}
			case AS_FORM_PS: {
				if(is_as_ok(s)) {
					const char *realm0 = get_http_header_value(hr, HR_REALM, current_realm());
					if(!is_superuser())
						realm0 = current_realm();
					strncpy(current_eff_realm(),realm0,STUN_MAX_REALM_SIZE);

					const char* client_protocol = get_http_header_value(hr, HR_CLIENT_PROTOCOL, "");

					const char* user_pattern = get_http_header_value(hr, HR_USER_PATTERN, "");

					turnsession_id csid=0;
					const char* ssid = get_http_header_value(hr, HR_CANCEL_SESSION, NULL);
					if(ssid) {
						https_cancel_session(ssid);
						csid = (turnsession_id)strtoull(ssid,NULL,10);
					}

					size_t max_sessions = current_max_output_sessions();
					const char* s_max_sessions = get_http_header_value(hr, HR_MAX_SESSIONS,NULL);
					if(s_max_sessions) {
						max_sessions=strtoul(s_max_sessions,NULL,10);
						if(!max_sessions) max_sessions = current_max_output_sessions();
						set_current_max_output_sessions(max_sessions);
					}

					if(!max_sessions) max_sessions = DEFAULT_CLI_MAX_OUTPUT_SESSIONS;

					write_ps_page(s,client_protocol,user_pattern,max_sessions,csid);
				} else {
					write_https_logon_page(s);
				}
				break;
			}
			case AS_FORM_USERS: {
				if(is_as_ok(s)) {
					{
						const char *realm0 = get_http_header_value(hr, HR_REALM, current_realm());
						if(!is_superuser())
							realm0 = current_realm();
						strncpy(current_eff_realm(),realm0,STUN_MAX_REALM_SIZE);
					}

					{
						const u08bits *user = (const u08bits*)get_http_header_value(hr, HR_DELETE_USER, NULL);
						if(user && user[0]) {
							const u08bits *realm = (const u08bits*)get_http_header_value(hr, HR_DELETE_REALM, "");
							if(!is_superuser()) {
								realm = (const u08bits*)current_realm();
							}
							if(realm && realm[0]) {
								const turn_dbdriver_t * dbd = get_dbdriver();
								if (dbd && dbd->del_user) {
									u08bits u[STUN_MAX_USERNAME_SIZE+1];
									u08bits r[STUN_MAX_REALM_SIZE+1];
									STRCPY(u,user);
									STRCPY(r,realm);
									dbd->del_user(u,r);
								}
							}
						}
					}

					const u08bits *add_realm = (const u08bits*)current_eff_realm();
					const u08bits *add_user = (const u08bits*)get_http_header_value(hr, HR_ADD_USER,"");
					const char* msg = "";
					if(wrong_html_name((const char*)add_user)) {
						msg = "Error: wrong user name";
						add_user = (const u08bits*)"";
					}
					if(add_user[0]) {
						add_realm = (const u08bits*)get_http_header_value(hr, HR_ADD_REALM, current_realm());
						if(!is_superuser()) {
							add_realm = (const u08bits*)current_realm();
						}
						if(!add_realm[0]) {
							add_realm=(const u08bits*)current_eff_realm();
						}
						if(!add_realm[0]) {
							add_realm = (const u08bits*)get_realm(NULL)->options.name;
						}
						if(wrong_html_name((const char*)add_realm)) {
							msg = "Error: wrong realm name";
							add_realm = (const u08bits*)"";
						}
						if(add_realm[0]) {
							const u08bits *pwd = (const u08bits*)get_http_header_value(hr, HR_PASSWORD, NULL);
							const u08bits *pwd1 = (const u08bits*)get_http_header_value(hr, HR_PASSWORD1, NULL);
							if(pwd && pwd1 && pwd[0] && pwd1[0] && !strcmp((const char*)pwd,(const char*)pwd1)) {

								const turn_dbdriver_t * dbd = get_dbdriver();
								if (dbd && dbd->set_user_key) {

									hmackey_t key;
									char skey[sizeof(hmackey_t) * 2 + 1];

									{
										u08bits u[STUN_MAX_USERNAME_SIZE+1];
										u08bits r[STUN_MAX_REALM_SIZE+1];
										u08bits p[STUN_MAX_PWD_SIZE+1];
										STRCPY(u,add_user);
										STRCPY(r,add_realm);
										STRCPY(p,pwd);
										stun_produce_integrity_key_str(u, r, p, key, SHATYPE_DEFAULT);
										size_t i = 0;
										size_t sz = get_hmackey_size(SHATYPE_DEFAULT);
										int maxsz = (int) (sz * 2) + 1;
										char *s = skey;
										for (i = 0; (i < sz) && (maxsz > 2); i++) {
											snprintf(s, (size_t) (sz * 2), "%02x", (unsigned int) key[i]);
											maxsz -= 2;
											s += 2;
										}
										skey[sz * 2] = 0;

										(*dbd->set_user_key)(u, r, skey);
									}

									add_realm=(const u08bits*)"";
									add_user=(const u08bits*)"";
								}
							} else {
								msg = "Error: wrong password";
							}
						}
					}

					write_users_page(s,add_user,add_realm,msg);

				} else {
					write_https_logon_page(s);
				}
				break;
			}
			case AS_FORM_SS: {
				if(is_as_ok(s)) {
					{
						const char *realm0 = get_http_header_value(hr, HR_REALM, current_realm());
						if(!is_superuser())
							realm0 = current_realm();
						strncpy(current_eff_realm(),realm0,STUN_MAX_REALM_SIZE);
					}

					{
						const u08bits *secret = (const u08bits*)get_http_header_value(hr, HR_DELETE_SECRET, NULL);
						if(secret && secret[0]) {
							const u08bits *realm = (const u08bits*)get_http_header_value(hr, HR_DELETE_REALM, NULL);
							if(!is_superuser()) {
								realm = (const u08bits*)current_realm();
							}
							if(realm && realm[0]) {
								const turn_dbdriver_t * dbd = get_dbdriver();
								if (dbd && dbd->del_secret) {
									u08bits ss[AUTH_SECRET_SIZE+1];
									u08bits r[STUN_MAX_REALM_SIZE+1];
									STRCPY(ss,secret);
									STRCPY(r,realm);
									dbd->del_secret(ss,r);
								}
							}
						}
					}

					const u08bits *add_realm = (const u08bits*)current_eff_realm();
					const u08bits *add_secret = (const u08bits*)get_http_header_value(hr, HR_ADD_SECRET, "");
					const char* msg = "";
					if(wrong_html_name((const char*)add_secret)) {
						msg = "Error: wrong secret value";
						add_secret = (const u08bits*)"";
					}
					if(add_secret[0]) {
						add_realm = (const u08bits*)get_http_header_value(hr, HR_ADD_REALM, current_realm());
						if(!is_superuser()) {
							add_realm = (const u08bits*)current_realm();
						}
						if(!add_realm[0]) {
							add_realm=(const u08bits*)current_eff_realm();
						}
						if(!add_realm[0]) {
							add_realm = (const u08bits*)get_realm(NULL)->options.name;
						}
						if(wrong_html_name((const char*)add_realm)) {
							msg = "Error: wrong realm name";
							add_realm = (const u08bits*)"";
						}
						if(add_realm[0]) {
							const turn_dbdriver_t * dbd = get_dbdriver();
							if (dbd && dbd->set_secret) {
								u08bits ss[AUTH_SECRET_SIZE+1];
								u08bits r[STUN_MAX_REALM_SIZE+1];
								STRCPY(ss,add_secret);
								STRCPY(r,add_realm);
								(*dbd->set_secret)(ss, r);
							}

							add_secret=(const u08bits*)"";
							add_realm=(const u08bits*)"";
						}
					}

					write_shared_secrets_page(s,(const char*)add_secret,(const char*)add_realm,msg);

				} else {
					write_https_logon_page(s);
				}
				break;
			}
			case AS_FORM_OS: {
				if(is_as_ok(s)) {
					{
						const char *realm0 = get_http_header_value(hr, HR_REALM, current_realm());
						if(!is_superuser())
							realm0 = current_realm();
						strncpy(current_eff_realm(),realm0,STUN_MAX_REALM_SIZE);
					}

					if(is_superuser()) {
						const u08bits *origin = (const u08bits*)get_http_header_value(hr, HR_DELETE_ORIGIN, NULL);
						if(origin && origin[0]) {
							const turn_dbdriver_t * dbd = get_dbdriver();
							if (dbd && dbd->del_origin) {
								u08bits o[STUN_MAX_ORIGIN_SIZE+1];
								STRCPY(o,origin);
								dbd->del_origin(o);
								u08bits corigin[STUN_MAX_ORIGIN_SIZE+1];
								get_canonic_origin((const char *)origin, (char *)corigin, sizeof(corigin)-1);
								dbd->del_origin(corigin);
							}
						}
					}

					const u08bits *add_realm = (const u08bits*)current_eff_realm();
					const u08bits *add_origin = (const u08bits*)get_http_header_value(hr, HR_ADD_ORIGIN, "");
					const char* msg = "";
					u08bits corigin[STUN_MAX_ORIGIN_SIZE+1];
					get_canonic_origin((const char *)add_origin, (char *)corigin, sizeof(corigin)-1);
					if(corigin[0]) {
						add_realm = (const u08bits*)get_http_header_value(hr, HR_ADD_REALM, current_realm());
						if(!is_superuser()) {
							add_realm = (const u08bits*)current_realm();
						}
						if(!add_realm[0]) {
							add_realm=(const u08bits*)current_eff_realm();
						}
						if(!add_realm[0]) {
							add_realm = (const u08bits*)get_realm(NULL)->options.name;
						}
						if(add_realm[0]) {
							const turn_dbdriver_t * dbd = get_dbdriver();
							if (dbd && dbd->add_origin) {
								u08bits o[STUN_MAX_ORIGIN_SIZE+1];
								u08bits r[STUN_MAX_REALM_SIZE+1];
								STRCPY(o,corigin);
								STRCPY(r,add_realm);
								(*dbd->add_origin)(o, r);
							}

							add_origin=(const u08bits*)"";
							add_realm=(const u08bits*)"";
						}
					}

					write_origins_page(s,(const char*)add_origin,(const char*)add_realm,msg);

				} else {
					write_https_logon_page(s);
				}
				break;
			}
			case AS_FORM_OAUTH_SHOW_KEYS: {
				if(!is_as_ok(s)) {
					write_https_logon_page(s);
				} else if(!is_superuser()) {
					write_https_home_page(s);
				} else {
						const char* kid = get_http_header_value(hr,HR_OAUTH_KID,"");
						write_https_oauth_show_keys(s,kid);
				}
				break;
			}
			case AS_FORM_OAUTH: {
				if(!is_as_ok(s)) {
					write_https_logon_page(s);
				} else if(!is_superuser()) {
					write_https_home_page(s);
				} else {

					{
						const char* del_kid = get_http_header_value(hr,HR_DELETE_OAUTH_KID,"");
						if(del_kid[0]) {
							const turn_dbdriver_t * dbd = get_dbdriver();
							if (dbd && dbd->del_oauth_key) {
								(*dbd->del_oauth_key)((const u08bits*)del_kid);
							}
						}
					}

					const char* add_kid = "";
					const char* add_ts = "0";
					const char* add_lt = "0";
					const char* add_ikm = "";
					const char* add_tea = "";
					const char* add_realm = "";
					const char* msg = "";

					add_kid = get_http_header_value(hr,HR_ADD_OAUTH_KID,"");
					if(add_kid[0]) {
						add_ikm = get_http_header_value(hr,HR_ADD_OAUTH_IKM,"");
						add_ts = get_http_header_value(hr,HR_ADD_OAUTH_TS,"");
						add_lt = get_http_header_value(hr,HR_ADD_OAUTH_LT,"");
						add_tea = get_http_header_value(hr,HR_ADD_OAUTH_TEA,"");
						add_realm = get_http_header_value(hr,HR_ADD_OAUTH_REALM,"");

						int keys_ok = (add_ikm[0] != 0);
						if(!keys_ok) {
							msg = "You must enter the key value.";
						} else {
							oauth_key_data_raw key;
							ns_bzero(&key,sizeof(key));
							STRCPY(key.kid,add_kid);

							if(add_lt && add_lt[0]) {
								key.lifetime = (u32bits)strtoul(add_lt,NULL,10);
								if(key.lifetime) {
									if(add_ts && add_ts[0]) {
										key.timestamp = (u64bits)strtoull(add_ts,NULL,10);
									}
									if(!key.timestamp) {
										key.timestamp = (u64bits)time(NULL);
									}
								}
							} else if(add_ts && add_ts[0]) {
								key.timestamp = (u64bits)strtoull(add_ts,NULL,10);
							}

							if(add_realm && add_realm[0]) STRCPY(key.realm,add_realm);

							STRCPY(key.ikm_key,add_ikm);
							STRCPY(key.as_rs_alg,add_tea);

							const turn_dbdriver_t * dbd = get_dbdriver();
							if (dbd && dbd->set_oauth_key) {
								if((*dbd->set_oauth_key)(&key)<0) {
									msg = "Cannot insert oAuth key into the database";
								} else {
									add_kid = "";
									add_ts = "0";
									add_lt = "0";
									add_ikm = "";
									add_tea = "";
									add_realm = "";
								}
							}
						}
					}

					write_https_oauth_page(s,add_kid,add_ikm,add_tea,add_ts,add_lt,add_realm,msg);
				}
				break;
			}
			case AS_FORM_TOGGLE:
				if(is_as_ok(s)) {
					handle_toggle_request(s,hr);
					write_pc_page(s);
				} else {
					write_https_logon_page(s);
				}
				break;
			case AS_FORM_UPDATE:
				if(is_as_ok(s)) {
					handle_update_request(s,hr);
					write_pc_page(s);
				} else {
					write_https_logon_page(s);
				}
				break;
			case AS_FORM_LOGON:
				if(!is_as_ok(s)) {
					handle_logon_request(s,hr);
					if(is_as_ok(s)) {
						write_https_home_page(s);
					} else {
						write_https_logon_page(s);
					}
				} else {
					write_https_home_page(s);
				}
				break;
			case AS_FORM_LOGOUT:
				handle_logout_request(s,hr);
				write_https_logon_page(s);
				break;
			default: {
			  const char *realm0 = get_http_header_value(hr, HR_REALM, current_realm());
			  if(!is_superuser())
			    realm0 = current_realm();
			  strncpy(current_eff_realm(),realm0,STUN_MAX_REALM_SIZE);
			  write_https_home_page(s);
			}
			};
			free_http_request(hr);
		}
	}

	current_socket = NULL;
}

static void https_input_handler(ioa_socket_handle s, int event_type, ioa_net_data *data, void *arg, int can_resume) {

	UNUSED_ARG(arg);
	UNUSED_ARG(s);
	UNUSED_ARG(event_type);
	UNUSED_ARG(can_resume);

	handle_https(s,data->nbh);

	ioa_network_buffer_delete(adminserver.e, data->nbh);
	data->nbh = NULL;
}

void https_admin_server_receive_message(struct bufferevent *bev, void *ptr)
{
	UNUSED_ARG(ptr);

	ioa_socket_handle s= NULL;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);

	while ((n = evbuffer_remove(input, &s, sizeof(s))) > 0) {
		if (n != sizeof(s)) {
			fprintf(stderr,"%s: Weird HTTPS CLI buffer error: size=%d\n",__FUNCTION__,n);
			continue;
		}

		register_callback_on_ioa_socket(adminserver.e, s, IOA_EV_READ, https_input_handler, NULL, 0);

		handle_https(s,NULL);
	}
}

void send_https_socket(ioa_socket_handle s) {
	struct evbuffer *output = bufferevent_get_output(adminserver.https_out_buf);
	if(output) {
		evbuffer_add(output,&s,sizeof(s));
	}
}

///////////////////////////////
