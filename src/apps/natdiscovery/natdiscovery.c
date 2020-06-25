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
static int udp_fd2 = -1;

static int counter = 0;

#ifdef __cplusplus


static int init_socket(int *socketfd, ioa_addr *local_addr, int local_port, ioa_addr *remote_addr){
	int ret=0;

	if (local_port >= 0) {
		addr_set_port(local_addr, local_port);
	}

	*socketfd = socket(remote_addr->ss.sa_family, SOCK_DGRAM, 0);
	if (udp_fd < 0)
	err(-1, NULL);

	if (!addr_any(local_addr)) {
		if (addr_bind(*socketfd, local_addr,0,1,UDP_SOCKET) < 0)
		err(-1, NULL);
	}

	return ret;
}


static int stunclient_send(int sockfd, ioa_addr *local_addr, int *local_port, ioa_addr *remote_addr, int change_ip, int change_port, int padding, int response_port){
	int ret=0;

	turn::StunMsgRequest req(STUN_METHOD_BINDING);

	req.constructBindingRequest();

	if (response_port >= 0) {
		turn::StunAttrResponsePort rpa;
		rpa.setResponsePort((uint16_t)response_port);
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
		int slen = get_ioa_addr_len(remote_addr);

		do {
			len = sendto(sockfd, req.getRawBuffer(), req.getSize(), 0, (struct sockaddr*) remote_addr, (socklen_t) slen);
		} while (len < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno == EAGAIN)));

		if (len < 0)
		err(-1, NULL);

	}

	if (addr_get_from_sock(sockfd, local_addr) < 0) {
		printf("%s: Cannot get address from local socket\n", __FUNCTION__);
	} else {
		*local_port = addr_get_port(local_addr);
	}

	return ret;
}


static int stunclient_receive(int sockfd, ioa_addr *local_addr, ioa_addr *reflexive_addr, ioa_addr *other_addr, int *rfc5780){
	int ret=0;


	{
		int len = 0;
		stun_buffer buf;
		uint8_t *ptr = buf.buf;
		int recvd = 0;
		const int to_recv = sizeof(buf.buf);
		struct timeval tv;

		tv.tv_sec = 3;  /* 3 Secs Timeout */
		tv.tv_usec = 0;  // Not init'ing this can cause strange errors

		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

		do {
			len = recv(sockfd, ptr, to_recv - recvd, 0);
			if (len > 0) {
				recvd += len;
				ptr += len;
				break;
			}
		} while (len < 0 && (errno == EINTR));

		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
			printf("STUN receive timeout..\n");
			ret = 1;
			return ret;
		}
		if (recvd > 0)
		len = recvd;
		buf.len = len;

		try {
			turn::StunMsgResponse res(buf.buf, sizeof(buf.buf), (size_t)buf.len, true);

			if (res.isCommand()) {
				if(res.isSuccess()) {

					if (res.isBindingResponse()) {

						turn::StunAttrIterator iter(res,STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS);
						if (!iter.eof()) {

							turn::StunAttrAddr addr(iter);
							addr.getAddr(*reflexive_addr);

							turn::StunAttrIterator iter1(res,STUN_ATTRIBUTE_OTHER_ADDRESS);
							if (!iter1.eof()) {
								*rfc5780 = 1;
								printf("\n========================================\n");
								printf("RFC 5780 response %d\n",++counter);
								turn::StunAttrIterator iter2(res,STUN_ATTRIBUTE_MAPPED_ADDRESS);
								if (!iter2.eof()) {
									ioa_addr mapped_addr;
									addr_set_any(&mapped_addr);
									turn::StunAttrAddr addr2(iter2);
									addr2.getAddr(mapped_addr);
									if (!addr_eq(&mapped_addr,reflexive_addr)){
										printf("-= ALG detected! Mapped and XOR-Mapped differ! =-\n");
										addr_debug_print(1, &mapped_addr, "Mapped Address: ");
									} else {
										printf("No ALG: Mapped == XOR-Mapped\n");
									}
								} else {
									printf("Not received mapped address attribute!\n");
								}									turn::StunAttrAddr addr1(iter1);
								addr1.getAddr(*other_addr);
								turn::StunAttrIterator iter3(res,STUN_ATTRIBUTE_RESPONSE_ORIGIN);
								if (!iter3.eof()) {
									ioa_addr response_origin;
									turn::StunAttrAddr addr3(iter3);
									addr3.getAddr(response_origin);
									addr_debug_print(1, &response_origin, "Response origin: ");
								}
								addr_debug_print(1, other_addr, "Other addr: ");
							}
							addr_debug_print(1, reflexive_addr, "UDP reflexive addr");
							addr_debug_print(1, local_addr, "Local addr: ");
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
				printf("The response is not a response message\n");
			}
		} catch(...) {
			turn::StunMsgRequest msg(buf.buf, sizeof(buf.buf), (size_t)buf.len, true);
			if (msg.isRequest(buf.buf,(size_t)buf.len)) {
				printf("Received a request (maybe a successful hairpinning)\n");
				return ret;
			} else {
				printf("The response is not a well formed STUN message\n");
			}
			ret=1;
		}
	}

	return ret;
}


static int run_stunclient(ioa_addr *local_addr, ioa_addr *remote_addr, ioa_addr *reflexive_addr, ioa_addr *other_addr, int *local_port, int *rfc5780,	int change_ip, int change_port, int padding){
	int ret=0;

	ret=init_socket(&udp_fd, local_addr, *local_port, remote_addr);
	ret=stunclient_send(udp_fd, local_addr, local_port, remote_addr, change_ip, change_port, padding, -1);
	ret=stunclient_receive(udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);
	close(udp_fd);

	return ret;
}


static int run_stunclient_hairpinning(ioa_addr *local_addr, ioa_addr *remote_addr, ioa_addr *reflexive_addr, ioa_addr *other_addr, int *local_port, int *rfc5780,	int change_ip, int change_port, int padding){
	int ret=0;

	init_socket(&udp_fd,local_addr,*local_port,remote_addr);

	ret=stunclient_send(udp_fd, local_addr, local_port, remote_addr, change_ip, change_port, padding, -1);
	ret=stunclient_receive(udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);


	addr_cpy(remote_addr,reflexive_addr);
	addr_set_port(local_addr, 0);

	init_socket(&udp_fd2,local_addr,0,remote_addr);

	ret=stunclient_send(udp_fd2, local_addr, local_port, remote_addr, change_ip, change_port, padding, -1);
	ret=stunclient_receive(udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);

	if(ret){
		ret=stunclient_receive(udp_fd2, local_addr, reflexive_addr, other_addr, rfc5780);
	}
	close(udp_fd);
	close(udp_fd2);

	return ret;
}

static int run_stunclient_lifetime(int timer,ioa_addr *local_addr, ioa_addr *remote_addr, ioa_addr *reflexive_addr, ioa_addr *other_addr, int *local_port, int *rfc5780, int change_ip, int change_port, int padding){
	int ret=0;
	int response_port;

	init_socket(&udp_fd, local_addr, *local_port, remote_addr);

	ret=stunclient_send(udp_fd, local_addr, local_port, remote_addr, change_ip, change_port, padding, -1);
	ret=stunclient_receive(udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);

	addr_set_port(local_addr, 0);
	sleep(timer);

	init_socket(&udp_fd2,local_addr,0,remote_addr);
	response_port=addr_get_port(reflexive_addr);

	ret=stunclient_send(udp_fd2, local_addr, local_port, remote_addr, change_ip, change_port, padding, response_port);
	ret=stunclient_receive(udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);

	socket_closesocket(udp_fd);
	socket_closesocket(udp_fd2);

	return ret;
}

#else

static int init_socket(int *socketfd, ioa_addr *local_addr, int local_port, ioa_addr *remote_addr){
	int ret=0;

	*socketfd = socket(remote_addr->ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
	if (udp_fd < 0)
	err(-1, NULL);

	if (local_port >= 0) {
		addr_set_port(local_addr, local_port);
	}
	if (!addr_any(local_addr)) {
		if (addr_bind(*socketfd, local_addr,0,1,UDP_SOCKET) < 0) {
			err(-1, NULL);
		}
	}

	return ret;
}

static int stunclient_send(stun_buffer *buf, int sockfd, ioa_addr *local_addr, int *local_port, ioa_addr *remote_addr, int change_ip, int change_port, int padding, int response_port){
	int ret=0;

	stun_prepare_binding_request(buf);

	if (response_port >= 0) {
		stun_attr_add_response_port_str((uint8_t*) (buf->buf), (size_t*) &(buf->len), (uint16_t) response_port);
	}
	if (change_ip || change_port) {
		stun_attr_add_change_request_str((uint8_t*) buf->buf, (size_t*) &(buf->len), change_ip, change_port);
	}
	if (padding) {
		if(stun_attr_add_padding_str((uint8_t*) buf->buf, (size_t*) &(buf->len), 1500)<0) {
			printf("%s: ERROR: Cannot add padding\n",__FUNCTION__);
		}
	}

	{
		int len = 0;
		int slen = get_ioa_addr_len(remote_addr);

		do {
			len = sendto(sockfd, buf->buf, buf->len, 0, (struct sockaddr*) remote_addr, (socklen_t) slen);
		} while (len < 0 && ((errno == EINTR) || (errno == ENOBUFS) || (errno == EAGAIN)));

		if (len < 0)
		err(-1, NULL);

	}

	if (addr_get_from_sock(sockfd, local_addr) < 0) {
		printf("%s: Cannot get address from local socket\n", __FUNCTION__);
	} else {
		*local_port = addr_get_port(local_addr);
	}

	return ret;
}


static int stunclient_receive(stun_buffer *buf, int sockfd, ioa_addr *local_addr, ioa_addr *reflexive_addr, ioa_addr *other_addr, int *rfc5780){
	int ret=0;


	{
		int len = 0;
		uint8_t *ptr = buf->buf;
		int recvd = 0;
		const int to_recv = sizeof(buf->buf);
		struct timeval tv;

		tv.tv_sec = 3;  /* 3 Secs Timeout */
		tv.tv_usec = 0;  // Not init'ing this can cause strange errors

		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

		do {
			len = recv(sockfd, ptr, to_recv - recvd, 0);
			if (len > 0) {
				recvd += len;
				ptr += len;
				break;
			}
		} while (len < 0 && (errno == EINTR));

		if (recvd > 0)
		len = recvd;
		buf->len = len;

		if (stun_is_command_message(buf)) {

			if (stun_is_response(buf)) {

				if (stun_is_success_response(buf)) {

					if (stun_is_binding_response(buf)) {

						addr_set_any(reflexive_addr);
						if (stun_attr_get_first_addr(buf, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, reflexive_addr, NULL) >= 0) {

							stun_attr_ref sar = stun_attr_get_first_by_type_str(buf->buf, buf->len, STUN_ATTRIBUTE_OTHER_ADDRESS);
							if (sar) {
								*rfc5780 = 1;
								printf("\n========================================\n");
								printf("RFC 5780 response %d\n",++counter);
								ioa_addr mapped_addr;
								addr_set_any(&mapped_addr);
								if (stun_attr_get_first_addr(buf, STUN_ATTRIBUTE_MAPPED_ADDRESS, &mapped_addr, NULL) >= 0) {
									if (!addr_eq(&mapped_addr,reflexive_addr)){
										printf("-= ALG detected! Mapped and XOR-Mapped differ! =-\n");
										addr_debug_print(1, &mapped_addr, "Mapped Address: ");
									}else {
										printf("No ALG: Mapped == XOR-Mapped\n");
									}
								} else {
									printf("Not received mapped address attribute.\n");
								}
								stun_attr_get_addr_str((uint8_t *) buf->buf, (size_t) buf->len, sar, other_addr, NULL);
								sar = stun_attr_get_first_by_type_str(buf->buf, buf->len, STUN_ATTRIBUTE_RESPONSE_ORIGIN);
								if (sar) {
									ioa_addr response_origin;
									stun_attr_get_addr_str((uint8_t *) buf->buf, (size_t) buf->len, sar, &response_origin, NULL);
									addr_debug_print(1, &response_origin, "Response origin: ");
								}
								addr_debug_print(1, other_addr, "Other addr: ");
							}
							addr_debug_print(1, reflexive_addr, "UDP reflexive addr");
							addr_debug_print(1, local_addr, "Local addr: ");
						} else {
							printf("Cannot read the response\n");
						}
					} else {
						printf("Wrong type of response\n");
					}
				} else {
					int err_code = 0;
					uint8_t err_msg[1025] = "\0";
					size_t err_msg_size = sizeof(err_msg);
					if (stun_is_error_response(buf, &err_code, err_msg, err_msg_size)) {
						printf("The response is an error %d (%s)\n", err_code, (char*) err_msg);
					} else {
						printf("The response is an unrecognized error\n");
					}
				}
			} else if (stun_is_request(buf)) {
				printf("Received a request (maybe a successful hairpinning)\n");
			} else {
				printf("The response is not a response message\n");
				ret=1;
			}
		} else {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				printf("STUN receive timeout..\n");
			}else{
				printf("The response is not a STUN message\n");
			}
			ret=1;
		}
	}

	return ret;
}


static int run_stunclient(ioa_addr *local_addr, ioa_addr *remote_addr, ioa_addr *reflexive_addr, ioa_addr *other_addr, int *local_port, int *rfc5780, int change_ip, int change_port, int padding){
	int ret=0;
	stun_buffer buf;

	init_socket(&udp_fd, local_addr, *local_port, remote_addr);

	ret=stunclient_send(&buf, udp_fd, local_addr, local_port, remote_addr, change_ip, change_port, padding, -1);
	ret=stunclient_receive(&buf, udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);

	socket_closesocket(udp_fd);

	return ret;
}

static int run_stunclient_hairpinning(ioa_addr *local_addr, ioa_addr *remote_addr, ioa_addr *reflexive_addr, ioa_addr *other_addr, int *local_port, int *rfc5780, int change_ip, int change_port, int padding){
	int ret=0;
	stun_buffer buf;
	stun_buffer buf2;

	init_socket(&udp_fd, local_addr, *local_port, remote_addr);

	ret=stunclient_send(&buf, udp_fd, local_addr, local_port, remote_addr, change_ip, change_port, padding, -1);
	ret=stunclient_receive(&buf, udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);


	addr_cpy(remote_addr,reflexive_addr);
	addr_set_port(local_addr, 0);

	init_socket(&udp_fd2,local_addr,0,remote_addr);

	ret=stunclient_send(&buf2, udp_fd2, local_addr, local_port, remote_addr, change_ip, change_port, padding, -1);
	ret=stunclient_receive(&buf, udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);

	if(ret){
		ret=stunclient_receive(&buf2, udp_fd2, local_addr, reflexive_addr, other_addr, rfc5780);
	}

	socket_closesocket(udp_fd);
	socket_closesocket(udp_fd2);

	return ret;
}


static int run_stunclient_lifetime(int timer,ioa_addr *local_addr, ioa_addr *remote_addr, ioa_addr *reflexive_addr, ioa_addr *other_addr, int *local_port, int *rfc5780, int change_ip, int change_port, int padding){
	int ret=0;
	stun_buffer buf;
	stun_buffer buf2;
	int response_port;

	init_socket(&udp_fd, local_addr, *local_port, remote_addr);

	ret=stunclient_send(&buf, udp_fd, local_addr, local_port, remote_addr, change_ip, change_port, padding, -1);
	ret=stunclient_receive(&buf, udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);

	addr_set_port(local_addr, 0);
	sleep(timer);

	init_socket(&udp_fd2,local_addr,0,remote_addr);
	response_port=addr_get_port(reflexive_addr);

	ret=stunclient_send(&buf2, udp_fd2, local_addr, local_port, remote_addr, change_ip, change_port, padding, response_port);
	ret=stunclient_receive(&buf, udp_fd, local_addr, reflexive_addr, other_addr, rfc5780);

	socket_closesocket(udp_fd);
	socket_closesocket(udp_fd2);

	return ret;
}

#endif

//////////////// local definitions /////////////////

static char Usage[] =
"Usage: natdiscovery [options] address\n"
"Options:\n"
"        -m      NAT mapping behavior discovery\n"
"        -f      NAT filtering behavior discovery\n"
"        -t      NAT mapping lifetime behavior discovery\n"
"                Requires a timer (-T)\n"
"        -c      NAT collision behavior discovery\n"
"                Requires an alternative IP address (-A)\n"
"        -H      NAT hairpinning behavior discovery\n"
"        -P      Add 1500 byte Padding to the behavior discovery\n"
"                Applicable with all except NAT mapping Lifetime discovery\n"
"        -p      STUN server port (Default: 3478)\n"
"        -L      Local address to use (optional)\n"
"        -l      Local port to use (use with -L)\n"
"        -A      Local alrernative address to use\n"
"                Used by collision behavior discovery\n"
"        -T      Mapping lifetime timer (sec)\n"
"                Used by mapping lifetime behavior discovery\n";

//////////////////////////////////////////////////

static void init(int first, ioa_addr *local_addr, ioa_addr *remote_addr, int *local_port, int port, int *rfc5780, char* local_addr_string, char* remote_param)
{
	addr_set_any(local_addr);

	if(local_addr_string[0]) {
		if(make_ioa_addr((const uint8_t*)local_addr_string, 0, local_addr)<0) {
			err(-1,NULL);
		}
	}
	if (!first) *local_port=-1;
	*rfc5780 = 0;

	if (make_ioa_addr((const uint8_t*)remote_param, port, remote_addr) < 0)
	err(-1, NULL);
}

static void discoveryresult(const char *decision){
	printf("\n========================================\n");
	printf("%s",decision);
	printf("\n========================================\n");
}

int main(int argc, char **argv)
{
	int remote_port = DEFAULT_STUN_PORT;
	char local_addr_string[256]="\0";
	char local2_addr_string[256]="\0";
	int c=0;
	int mapping = 0;
	int filtering = 0;
	int lifetime=0;
	int timer=-1;
	int collision = 0;
	int padding = 0;
	int hairpinning = 0;
	int local_port=-1;
	int rfc5780;
	int first=1;
	ioa_addr other_addr, reflexive_addr, tmp_addr, remote_addr, local_addr, local2_addr;


	set_logfile("stdout");
	set_system_parameters(0);

	bzero(local_addr_string, sizeof(local_addr_string));
	bzero(local2_addr_string, sizeof(local2_addr_string));
	addr_set_any(&remote_addr);
	addr_set_any(&other_addr);
	addr_set_any(&reflexive_addr);
	addr_set_any(&tmp_addr);

	while ((c = getopt(argc, argv, "mftcPHp:L:l:A:T:")) != -1) {
		switch(c) {
			case 'm':
			mapping=1;
			break;
			case 'f':
			filtering=1;
			break;
			case 't':
			lifetime=1;
			break;
			case 'c':
			collision=1;
			break;
			case 'H':
			hairpinning=1;
			break;
			case 'P':
			padding=1;
			break;
			case 'p':
			remote_port = atoi(optarg);
			break;
			case 'L':
			STRCPY(local_addr_string, optarg);
			break;
			case 'l':
			local_port = atoi(optarg);
			break;
			case 'A':
			STRCPY(local2_addr_string, optarg);
			break;
			case 'T':
			timer = atoi(optarg);
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

	if(collision && !strcmp(local2_addr_string,"\0")){
		fprintf(stderr, "Use \"-A\" to add an Alternative local IP address.\n");
		fprintf(stderr, "It is mandatory with \"-c\" collision behavior detection..\n");
		exit(-1);
	}

	if(lifetime && timer==-1){
		fprintf(stderr, "Use \"-T\" to add a timer value (in sec).\n");
		fprintf(stderr, "It is mandatory with \"-b\" mapping lifetime behavior detection..\n");
		exit(-1);
	}

	if(local_port>=0 && !strcmp(local_addr_string,"\0")){
		fprintf(stderr, "To use local port please specify local address \"-L\"!\n");
		fprintf(stderr, "We need to know the address familly to set the port.\n");
		exit(-1);
	}


	if(lifetime) {
		printf("\n-= Mapping Lifetime Behavior Discovery =-\n");
		init(first, &local_addr, &remote_addr, &local_port, remote_port, &rfc5780, local_addr_string, argv[optind]);
		first=0;
		run_stunclient_lifetime(timer, &local_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,0,0,padding);
	}

	if(hairpinning) {
		printf("\n-= Hairpinning Behavior Discovery =-\n");
		init(first, &local_addr, &remote_addr, &local_port, remote_port, &rfc5780, local_addr_string, argv[optind]);
		first=0;
		run_stunclient_hairpinning(&local_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,0,0,padding);
	}


	if(mapping) {
		printf("\n-= Mapping Behavior Discovery =-\n");
		init(first,&local_addr, &remote_addr, &local_port, remote_port, &rfc5780, local_addr_string, argv[optind]);
		first=0;

		run_stunclient(&local_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,0,0,padding);
		if (addr_eq(&local_addr,&reflexive_addr)){
			discoveryresult("No NAT! (Endpoint Independent Mapping)");
		}
		if(rfc5780) {
			if(!addr_any(&other_addr)){
				addr_cpy(&tmp_addr, &reflexive_addr);

				addr_cpy(&remote_addr, &other_addr);
				addr_set_port(&remote_addr, remote_port);

				run_stunclient(&local_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,0,0,padding);

				if(addr_eq(&tmp_addr,&reflexive_addr)){
					discoveryresult("NAT with Endpoint Independent Mapping!");
				} else {
					addr_cpy(&tmp_addr, &reflexive_addr);
					addr_cpy(&remote_addr, &other_addr);
					run_stunclient(&local_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,0,0,padding);
					if(addr_eq(&tmp_addr,&reflexive_addr)){
						discoveryresult("NAT with Address Dependent Mapping!");
					} else {
						discoveryresult("NAT with Address and Port Dependent Mapping!");
					}
				}
			}
		}
	}


	if(filtering) {
		printf("\n-= Filtering Behavior Discovery =-\n");
		init(first,&local_addr, &remote_addr, &local_port, remote_port, &rfc5780, local_addr_string, argv[optind]);
		first=0;

		run_stunclient(&local_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,0,0,padding);
		if(addr_eq(&local_addr, &reflexive_addr)){
			discoveryresult("No NAT! (Endpoint Independent Mapping)");
		}
		if(rfc5780) {
			if(!addr_any(&other_addr)){
				int res=0;
				res=run_stunclient(&local_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,1,1,padding);
				if (!res) {
					discoveryresult("NAT with Endpoint Independent Filtering!");
				} else {
					res=0;
					res=run_stunclient(&local_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,0,1,padding);
					if(!res){
						discoveryresult("NAT with Address Dependent Filtering!");
					} else {
						discoveryresult("NAT with Address and Port Dependent Filtering!");
					}
				}
			}
		}
	}



	if(collision) {
		printf("\n-= Collision Behavior Discovery =-\n");
		init(first,&local_addr, &remote_addr, &local_port, remote_port, &rfc5780, local_addr_string, argv[optind]);
		first=0;

		addr_set_any(&local2_addr);

		if(local2_addr_string[0]) {
			if(make_ioa_addr((const uint8_t*)local2_addr_string, 0, &local2_addr)<0) {
				err(-1,NULL);
			}
		}

		run_stunclient(&local_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,0,0,padding);
		addr_set_port(&local2_addr,addr_get_port(&local_addr));
		run_stunclient(&local2_addr, &remote_addr, &reflexive_addr, &other_addr, &local_port, &rfc5780,0,0,padding);
	}

	if (!filtering && !mapping && !collision && !hairpinning && !lifetime) {
		printf("Please use either -f or -m or -c or -t or -H parameter for Filtering or Mapping behavior discovery.\n");
	}
	socket_closesocket(udp_fd);
	socket_closesocket(udp_fd2);

	return 0;
}
