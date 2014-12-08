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

#include "ns_ioalib_impl.h"

void write_http_echo(ioa_socket_handle s)
{
	if(s && !ioa_socket_tobeclosed(s)) {
		SOCKET_APP_TYPE sat = get_ioa_socket_app_type(s);
		if((sat == HTTP_CLIENT_SOCKET) || (sat == HTTPS_CLIENT_SOCKET)) {
			ioa_network_buffer_handle nbh_http = ioa_network_buffer_allocate(s->e);
			size_t len_http = ioa_network_buffer_get_size(nbh_http);
			u08bits *data = ioa_network_buffer_data(nbh_http);
			char data_http[1025];
			char content_http[1025];
			const char* title = "TURN Server";
			snprintf(content_http,sizeof(content_http)-1,"<!DOCTYPE html>\r\n<html>\r\n  <head>\r\n    <title>%s</title>\r\n  </head>\r\n  <body>\r\n    %s\r\n  </body>\r\n</html>\r\n",title,title);
			snprintf(data_http,sizeof(data_http)-1,"HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s",TURN_SOFTWARE,(int)strlen(content_http),content_http);
			len_http = strlen(data_http);
			ns_bcopy(data_http,data,len_http);
			ioa_network_buffer_set_size(nbh_http,len_http);
			send_data_from_ioa_socket_nbh(s, NULL, nbh_http, TTL_IGNORE, TOS_IGNORE);
		}
	}
}

void handle_https(ioa_socket_handle s, ioa_network_buffer_handle nbh) {
	//TODO
	UNUSED_ARG(nbh);
	write_http_echo(s);
}
