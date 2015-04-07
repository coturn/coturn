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

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ns_turn_utils.h"
#include "apputils.h"
#include "stun_buffer.h"

#ifdef __cplusplus
#include "TurnMsgLib.h"
#endif

////////////////////////////////////////////////////

static int udp_fd = -1;
static ioa_addr real_local_addr;
static int counter = 0;

#ifdef __cplusplus

static int run_stunclient(const char* rip, int rport, int *port, int *rfc5780, int response_port, int change_ip, int change_port, int padding)
{

	ioa_addr remote_addr;
	int new_udp_fd = -1;

	memset((void *) &remote_addr, 0, sizeof(ioa_addr));
	if (make_ioa_addr((const u08bits*) rip, rport, &remote_addr) < 0)
		err(-1, NULL);

	if (udp_fd < 0) {
		udp_fd = socket(remote_addr.ss.sa_family, SOCK_DGRAM, 0);
		if (udp_fd < 0)
			err(-1, NULL);

		if (!addr_any(&real_local_addr)) {
			if (addr_bind(udp_fd, &real_local_addr,0,1,UDP_SOCKET) < 0)
				err(-1, NULL);
		}
	}

	if (response_port >= 0) {

		new_udp_fd = socket(remote_addr.ss.sa_family, SOCK_DGRAM, 0);
		if (new_udp_fd < 0)
			err(-1, NULL);

		addr_set_port(&real_local_addr, response_port);

		if (addr_bind(new_udp_fd, &real_local_addr, 0, 1, UDP_SOCKET) < 0)
			err(-1, NULL);
	}

	turn::StunMsgRequest req(STUN_METHOD_BINDING);

	req.constructBindingRequest();

	if (response_port >= 0) {
	  turn::StunAttrResponsePort rpa;
		rpa.setResponsePort((u16bits)response_port);
		try {
			req.addAttr(rpa);
		} catch(turn::WrongStunAttrFormatException &ex1) {
			printf("Wrong rp attr format\n");
			exit(-1);
		} catch(turn::WrongStunBufferFormatException &ex2) {
			printf("Wrong stun buffer format (1)\n");
			exit(-1);
		} catch(...) {
			printf("Wrong something (1)\n");
			exit(-1);
		}
	}
	if (change_ip || change_port) {
		turn::StunAttrChangeRequest cra;
		cra.setChangeIp(change_ip);
		cra.setChangePort(change_port);
		try {
			req.addAttr(cra);
		} catch(turn::WrongStunAttrFormatException &ex1) {
			printf("Wrong cr attr format\n");
			exit(-1);
		} catch(turn::WrongStunBufferFormatException &ex2) {
			printf("Wrong stun buffer format (2)\n");
			exit(-1);
		} catch(...) {
			printf("Wrong something (2)\n");
			exit(-1);
		}
	}
	if (padding) {
		turn::StunAttrPadding pa;
		pa.setPadding(1500);
		try {
			req.addAttr(pa);
		} catch(turn::WrongStunAttrFormatException &ex1) {
			printf("Wrong p attr format\n");
			exit(-1);
		} catch(turn::WrongStunBufferFormatException &ex2) {
			printf("Wrong stun buffer format (3)\n");
			exit(-1);
		} catch(...) {
			printf("Wrong something (3)\n");
			exit(-1);
		}
	}

	{
		int len = 0;
		int slen = get_ioa_addr_len(&remote_addr);

		do {
			len = sendto(udp_fd, req.getRawBuffer(), req.getSize(), 0, (struct sockaddr*) &remote_addr, (socklen_t) slen);
		} while (len < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno == EAGAIN)));

		if (len < 0)
			err(-1, NULL);

	}

	if (addr_get_from_sock(udp_fd, &real_local_addr) < 0) {
		printf("%s: Cannot get address from local socket\n", __FUNCTION__);
	} else {
		*port = addr_get_port(&real_local_addr);
	}

	{
		if(new_udp_fd >= 0) {
			close(udp_fd);
			udp_fd = new_udp_fd;
			new_udp_fd = -1;
		}
	}

	{
		int len = 0;
		stun_buffer buf;
		u08bits *ptr = buf.buf;
		int recvd = 0;
		const int to_recv = sizeof(buf.buf);

		do {
			len = recv(udp_fd, ptr, to_recv - recvd, 0);
			if (len > 0) {
				recvd += len;
				ptr += len;
				break;
			}
		} while (len < 0 && (errno == EINTR));

		if (recvd > 0)
			len = recvd;
		buf.len = len;

		try {
			turn::StunMsgResponse res(buf.buf, sizeof(buf.buf), (size_t)buf.len, true);

			if (res.isCommand()) {

				if(res.isSuccess()) {

					if (res.isBindingResponse()) {

						ioa_addr reflexive_addr;
						addr_set_any(&reflexive_addr);
						turn::StunAttrIterator iter(res,STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS);
						if (!iter.eof()) {

							turn::StunAttrAddr addr(iter);
							addr.getAddr(reflexive_addr);

							turn::StunAttrIterator iter1(res,STUN_ATTRIBUTE_OTHER_ADDRESS);
							if (!iter1.eof()) {
								*rfc5780 = 1;
								printf("\n========================================\n");
								printf("RFC 5780 response %d\n",++counter);
								ioa_addr other_addr;
								turn::StunAttrAddr addr1(iter1);
								addr1.getAddr(other_addr);
								turn::StunAttrIterator iter2(res,STUN_ATTRIBUTE_RESPONSE_ORIGIN);
								if (!iter2.eof()) {
									ioa_addr response_origin;
									turn::StunAttrAddr addr2(iter2);
									addr2.getAddr(response_origin);
									addr_debug_print(1, &response_origin, "Response origin: ");
								}
								addr_debug_print(1, &other_addr, "Other addr: ");
							}
							addr_debug_print(1, &reflexive_addr, "UDP reflexive addr");

						} else {
							printf("Cannot read the response\n");
						}
					} else {
						printf("Wrong type of response\n");
					}
				} else {
					int err_code = res.getError();
					std::string reason = res.getReason();

					printf("The response is an error %d (%s)\n", err_code, reason.c_str());
				}
			} else {
				printf("The response is not a reponse message\n");
			}
		} catch(...) {
			printf("The response is not a well formed STUN message\n");
		}
	}

	return 0;
}

#else

static int run_stunclient(const char* rip, int rport, int *port, int *rfc5780, int response_port, int change_ip, int change_port, int padding)
{

	ioa_addr remote_addr;
	int new_udp_fd = -1;
	stun_buffer buf;

	ns_bzero(&remote_addr, sizeof(remote_addr));
	if (make_ioa_addr((const u08bits*) rip, rport, &remote_addr) < 0)
		err(-1, NULL);

	if (udp_fd < 0) {
		udp_fd = socket(remote_addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
		if (udp_fd < 0)
			err(-1, NULL);

		if (!addr_any(&real_local_addr)) {
			if (addr_bind(udp_fd, &real_local_addr,0,1,UDP_SOCKET) < 0)
				err(-1, NULL);
		}
	}

	if (response_port >= 0) {

		new_udp_fd = socket(remote_addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
		if (new_udp_fd < 0)
			err(-1, NULL);

		addr_set_port(&real_local_addr, response_port);

		if (addr_bind(new_udp_fd, &real_local_addr,0,1,UDP_SOCKET) < 0)
			err(-1, NULL);
	}

	stun_prepare_binding_request(&buf);

	if (response_port >= 0) {
		stun_attr_add_response_port_str((u08bits*) (buf.buf), (size_t*) &(buf.len), (u16bits) response_port);
	}
	if (change_ip || change_port) {
		stun_attr_add_change_request_str((u08bits*) buf.buf, (size_t*) &(buf.len), change_ip, change_port);
	}
	if (padding) {
		if(stun_attr_add_padding_str((u08bits*) buf.buf, (size_t*) &(buf.len), 1500)<0) {
			printf("%s: ERROR: Cannot add padding\n",__FUNCTION__);
		}
	}

	{
		int len = 0;
		int slen = get_ioa_addr_len(&remote_addr);

		do {
			len = sendto(udp_fd, buf.buf, buf.len, 0, (struct sockaddr*) &remote_addr, (socklen_t) slen);
		} while (len < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno == EAGAIN)));

		if (len < 0)
			err(-1, NULL);

	}

	if (addr_get_from_sock(udp_fd, &real_local_addr) < 0) {
		printf("%s: Cannot get address from local socket\n", __FUNCTION__);
	} else {
		*port = addr_get_port(&real_local_addr);
	}

	{
		if(new_udp_fd >= 0) {
			socket_closesocket(udp_fd);
			udp_fd = new_udp_fd;
			new_udp_fd = -1;
		}
	}

	{
		int len = 0;
		u08bits *ptr = buf.buf;
		int recvd = 0;
		const int to_recv = sizeof(buf.buf);

		do {
			len = recv(udp_fd, ptr, to_recv - recvd, 0);
			if (len > 0) {
				recvd += len;
				ptr += len;
				break;
			}
		} while (len < 0 && ((errno == EINTR) || (errno == EAGAIN)));

		if (recvd > 0)
			len = recvd;
		buf.len = len;

		if (stun_is_command_message(&buf)) {

			if (stun_is_response(&buf)) {

				if (stun_is_success_response(&buf)) {

					if (stun_is_binding_response(&buf)) {

						ioa_addr reflexive_addr;
						addr_set_any(&reflexive_addr);
						if (stun_attr_get_first_addr(&buf, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &reflexive_addr, NULL) >= 0) {

							stun_attr_ref sar = stun_attr_get_first_by_type_str(buf.buf, buf.len, STUN_ATTRIBUTE_OTHER_ADDRESS);
							if (sar) {
								*rfc5780 = 1;
								printf("\n========================================\n");
								printf("RFC 5780 response %d\n",++counter);
								ioa_addr other_addr;
								stun_attr_get_addr_str((u08bits *) buf.buf, (size_t) buf.len, sar, &other_addr, NULL);
								sar = stun_attr_get_first_by_type_str(buf.buf, buf.len, STUN_ATTRIBUTE_RESPONSE_ORIGIN);
								if (sar) {
									ioa_addr response_origin;
									stun_attr_get_addr_str((u08bits *) buf.buf, (size_t) buf.len, sar, &response_origin, NULL);
									addr_debug_print(1, &response_origin, "Response origin: ");
								}
								addr_debug_print(1, &other_addr, "Other addr: ");
							}
							addr_debug_print(1, &reflexive_addr, "UDP reflexive addr");

						} else {
							printf("Cannot read the response\n");
						}
					} else {
						printf("Wrong type of response\n");
					}
				} else {
					int err_code = 0;
					u08bits err_msg[1025] = "\0";
					size_t err_msg_size = sizeof(err_msg);
					if (stun_is_error_response(&buf, &err_code, err_msg, err_msg_size)) {
						printf("The response is an error %d (%s)\n", err_code, (char*) err_msg);
					} else {
						printf("The response is an unrecognized error\n");
					}
				}
			} else {
				printf("The response is not a reponse message\n");
			}
		} else {
			printf("The response is not a STUN message\n");
		}
	}

	return 0;
}
#endif

//////////////// local definitions /////////////////

static char Usage[] =
  "Usage: stunclient [options] address\n"
  "Options:\n"
  "        -p      STUN server port (Default: 3478)\n"
  "        -L      Local address to use (optional)\n"
  "        -f      Force RFC 5780 processing\n";

//////////////////////////////////////////////////

int main(int argc, char **argv)
{
  int port = DEFAULT_STUN_PORT;
  char local_addr[256]="\0";
  int c=0;
  int forceRfc5780 = 0;

  set_logfile("stdout");
  set_system_parameters(0);
  
  ns_bzero(local_addr, sizeof(local_addr));

  while ((c = getopt(argc, argv, "p:L:f")) != -1) {
    switch(c) {
    case 'f':
	    forceRfc5780 = 1;
	    break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'L':
      STRCPY(local_addr, optarg);
      break;
    default:
      fprintf(stderr,"%s\n", Usage);
      exit(1);
    }
  }

  if(optind>=argc) {
    fprintf(stderr, "%s\n", Usage);
    exit(-1);
  }

  addr_set_any(&real_local_addr);

  if(local_addr[0]) {
      if(make_ioa_addr((const u08bits*)local_addr, 0, &real_local_addr)<0) {
        err(-1,NULL);
      }
  }

  int local_port = -1;
  int rfc5780 = 0;

  run_stunclient(argv[optind], port, &local_port, &rfc5780,-1,0,0,0);

  if(rfc5780 || forceRfc5780) {
	  run_stunclient(argv[optind], port, &local_port, &rfc5780,local_port+1,1,1,0);
	  run_stunclient(argv[optind], port, &local_port, &rfc5780,-1,1,1,1);
  }

  socket_closesocket(udp_fd);

  return 0;
}
