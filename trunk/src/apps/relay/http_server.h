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

#ifndef __TURN_HTTP_SERVER__
#define __TURN_HTTP_SERVER__

#include "ns_turn_utils.h"
#include "ns_turn_server.h"
#include "apputils.h"

#include <stdlib.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/////////  HTTP REQUEST //////////

enum _HTTP_REQUEST_TYPE {
	HRT_UNKNOWN=0,
	HRT_GET,
	HRT_HEAD,
	HRT_POST,
	HRT_PUT,
	HRT_DELETE
};

typedef enum _HTTP_REQUEST_TYPE HTTP_REQUEST_TYPE;

struct http_headers;

struct http_request {
	HTTP_REQUEST_TYPE rtype;
	char *path;
	struct http_headers *headers;
};

struct http_request* parse_http_request(char* request);
const char *get_http_header_value(const struct http_request *request, const char* key, const char* def);
void free_http_request(struct http_request *request);

const char* get_http_date_header(void);

////////////////////////////////////////////

struct str_buffer;

struct str_buffer* str_buffer_new(void);
void str_buffer_append(struct str_buffer* sb, const char* str);
void str_buffer_append_sz(struct str_buffer* sb, size_t sz);
void str_buffer_append_sid(struct str_buffer* sb, turnsession_id sid);
const char* str_buffer_get_str(const struct str_buffer *sb);
size_t str_buffer_get_str_len(const struct str_buffer *sb);
void str_buffer_free(struct str_buffer *sb);

////////////////////////////////////////////

void handle_http_echo(ioa_socket_handle s);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif
/// __TURN_HTTP_SERVER__///

