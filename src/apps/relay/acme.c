
/*
 * Copyright (C) 2011, 2012, 2013, 2014 Citrix Systems
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

#include "acme.h"
#include "ns_ioalib_impl.h"

static int is_acme_req(char *req, size_t len) {
	static const char *A = "                                             -  0123456789       ABCDEFGHIJKLMNOPQRSTUVWXYZ    _ abcdefghijklmnopqrstuvwxyz     ";
	int c, i, k;

	// Check first request line. Should be like: GET path HTTP/1.x
	if (strncmp(req, "GET /.well-known/acme-challenge/", 32))
		return -1;
	// Usually (for LE) the "method path" is 32 + 43 = 55 chars. But other
	// implementations may choose longer pathes. We define PATHMAX = 127 chars
	// to be prepared for "DoS" attacks (STUN msg size max. is ~ 64K).
	len =- 21;					// min size of trailing headers
	if (len > 131)
		len = 131;
	for (i=32; i < (int) len; i++) {
		// find the end of the path
		if (req[i] != ' ')
			continue;
		// consider path < 10 chars invalid. Also we wanna see a "trailer".
		if (i < 42 || strncmp(req + i, " HTTP/1.", 8))
			return -2;
		// finally check for allowed chars
		for (k=32; k < i; k++) {
			c = req[k];
			if ((c > 127) || (A[c] == ' '))
				return -3;
		}
		// all checks passed: sufficient for us to answer with a redirect
		return i;
	}
	return -4;		// end of path not found
}

int try_acme_redirect(char *req, size_t len, const char *url,
	ioa_socket_handle s)
{
	static const char *HTML = 
		"<html><head><title>301 Moved Permanently</title></head>\
		<body><h1>301 Moved Permanently</h1></body></html>";
	char http_response[1024];
	char req_url[600];
	char *req_url_end_space, *req_url_end_tab;
	int path_length;
	strcpy(req_url, req + GET_WELLKNOWN_ACMECHALLANGE_URL_PREFIX_LENGTH);
	req_url_end_space=strchr(req_url,' ');
	req_url_end_tab=strchr(req_url,'\t');
	if (req_url_end_space != NULL && req_url_end_tab != NULL) {
		if (req_url_end_space - req_url_end_tab > 0 ){
			path_length=req_url_end_space - req_url;
			req_url[path_length]='\0';
		} else {
			path_length=req_url_end_tab - req_url;
			req_url[req_url_end_tab - req_url]='\0';
		}
	} else if(req_url_end_space != NULL) {
		path_length=req_url_end_space - req_url;
		req_url[path_length]='\0';
	}
	else if(req_url_end_tab != NULL) {
		path_length=req_url_end_tab - req_url;
		req_url[path_length]='\0';
	}

	size_t plen, rlen;

	if (url == NULL || url[0] == '\0' || req == NULL || s == 0 )
		return 1;
	if (len < 64 || len > 512 || (plen = is_acme_req(req, len)) < 33)
		return 2;

	snprintf(http_response, sizeof(http_response) - 1,
		"HTTP/1.1 301 Moved Permanently\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %ld\r\n"
		"Connection: close\r\n"
		"Location: %s%s\r\n"
		"\r\n%s", strlen(HTML), url, req_url, HTML);

	rlen = strlen(http_response);

	ioa_network_buffer_handle nbh_acme = ioa_network_buffer_allocate(s->e);
	uint8_t *data = ioa_network_buffer_data(nbh_acme);
	bcopy(http_response, data, rlen);
	ioa_network_buffer_set_size(nbh_acme, rlen);
	send_data_from_ioa_socket_nbh(s, NULL, nbh_acme, TTL_IGNORE, TOS_IGNORE, NULL);

	return 0;
}
