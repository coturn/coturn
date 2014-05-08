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

#include "ns_turn_utils.h"
#include "udpserver.h"
#include "apputils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

//////////////// local definitions /////////////////

static char Usage[] =
  "Usage: server [options]\n"
  "Options:\n"
  "        -p      Listening UDP port (Default: 3480)\n"
  "        -d      Listening interface device (optional)\n"
  "        -L      Listening address\n"
  "        -v      verbose\n";


//////////////////////////////////////////////////

int main(int argc, char **argv)
{
	int port = PEER_DEFAULT_PORT;
	char **local_addr_list=NULL;
	size_t las = 0;
	int verbose = TURN_VERBOSE_NONE;
	int c;
	char ifname[1025] = "\0";

	IS_TURN_SERVER = 1;

	set_logfile("stdout");
	set_system_parameters(0);

	while ((c = getopt(argc, argv, "d:p:L:v")) != -1)
		switch (c){
		case 'd':
			STRCPY(ifname, optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'L':
		  local_addr_list = (char**)realloc(local_addr_list,++las*sizeof(char*));
		  local_addr_list[las-1]=strdup(optarg);
		  break;
		case 'v':
			verbose = TURN_VERBOSE_NORMAL;
			break;
		default:
			fprintf(stderr, "%s\n", Usage);
			exit(1);
		}

	if(las<1) {
	  local_addr_list = (char**)realloc(local_addr_list,++las*sizeof(char*));
	  local_addr_list[las-1]=strdup("0.0.0.0");
	  local_addr_list = (char**)realloc(local_addr_list,++las*sizeof(char*));
	  local_addr_list[las-1]=strdup("::");
	}


	server_type* server = start_udp_server(verbose, ifname, local_addr_list, las, port);
	run_udp_server(server);
	clean_udp_server(server);

	return 0;
}

