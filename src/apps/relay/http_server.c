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

#include "ns_ioalib_impl.h"

#include "http_server.h"

#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include <time.h>

//////////////////////////////////////

struct headers_list {
	size_t n;
	char **keys;
	char **values;
};

struct http_headers {
	struct evkeyvalq *uri_headers;
	struct headers_list *post_headers;
};

//////////////////////////////////////

static void write_http_echo(ioa_socket_handle s)
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
			snprintf(content_http,sizeof(content_http)-1,"<!DOCTYPE html>\r\n<html>\r\n  <head>\r\n    <title>%s</title>\r\n  </head>\r\n  <body>\r\n    <b>%s</b> <br> <b><i>use https connection for the admin session</i></b>\r\n  </body>\r\n</html>\r\n",title,title);
			snprintf(data_http,sizeof(data_http)-1,"HTTP/1.0 200 OK\r\nServer: %s\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s",TURN_SOFTWARE,(int)strlen(content_http),content_http);
			len_http = strlen(data_http);
			ns_bcopy(data_http,data,len_http);
			ioa_network_buffer_set_size(nbh_http,len_http);
			send_data_from_ioa_socket_nbh(s, NULL, nbh_http, TTL_IGNORE, TOS_IGNORE,NULL);
		}
	}
}

void handle_http_echo(ioa_socket_handle s) {
	write_http_echo(s);
}

const char* get_http_date_header()
{
	static char buffer_date[256];
	static char buffer_header[1025];
	static const char* wds[]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	static const char* mons[]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

	time_t now = time(NULL);
	struct tm *gmtm = gmtime(&now);

	buffer_header[0]=0;
	buffer_date[0]=0;
	if(gmtm) {
		snprintf(buffer_date,sizeof(buffer_date)-1,"%s, %d %s %d %d:%d:%d GMT",wds[gmtm->tm_wday], gmtm->tm_mday, mons[gmtm->tm_mon], gmtm->tm_year+1900, gmtm->tm_hour, gmtm->tm_min, gmtm->tm_sec);
		buffer_date[sizeof(buffer_date)-1]=0;
		snprintf(buffer_header,sizeof(buffer_header)-1,"Date: %s\r\n",buffer_date);
		buffer_header[sizeof(buffer_header)-1]=0;
	}

	return buffer_header;
}

///////////////////////////////////////////////

static struct headers_list * post_parse(char *data, size_t data_len)
{
	while((*data=='\r')||(*data=='\n')) ++data;
	char *post_data = (char*)calloc(data_len + 1, sizeof(char));
	memcpy(post_data, data, data_len);
	char *fmarker = NULL;
	char *fsplit = strtok_r(post_data, "&", &fmarker);
	struct headers_list *list = (struct headers_list*)malloc(sizeof(struct headers_list));
	ns_bzero(list,sizeof(struct headers_list));
	while (fsplit != NULL) {
		char *vmarker = NULL;
		char *key = strtok_r(fsplit, "=", &vmarker);
		char *value = strtok_r(NULL, "=", &vmarker);
		char empty[1];
		empty[0]=0;
		value = value ? value : empty;
		value = evhttp_decode_uri(value);
		char *p = value;
		while (*p) {
			if (*p == '+')
				*p = ' ';
			p++;
		}
		list->keys = (char**)realloc(list->keys,sizeof(char*)*(list->n+1));
		list->keys[list->n] = strdup(key);
		list->values = (char**)realloc(list->values,sizeof(char*)*(list->n+1));
		list->values[list->n] = value;
		++(list->n);
		fsplit = strtok_r(NULL, "&", &fmarker);
	}
	free(post_data);
	return list;
}

static struct http_request* parse_http_request_1(struct http_request* ret, char* request, int parse_post)
{

	if(ret && request) {

		char* s = strstr(request," HTTP/");
		if(!s) {
			free(ret);
			ret = NULL;
		} else {
			*s = 0;

			struct evhttp_uri *uri = evhttp_uri_parse(request);
			if(!uri) {
				free(ret);
				ret = NULL;
			} else {

				const char *query = evhttp_uri_get_query(uri);
				if(query) {
					struct evkeyvalq* kv = (struct evkeyvalq*)malloc(sizeof(struct evkeyvalq));
					ns_bzero(kv,sizeof(struct evkeyvalq));
					if(evhttp_parse_query_str(query, kv)<0) {
						free(ret);
						ret = NULL;
					} else {
						ret->headers = (struct http_headers*)malloc(sizeof(struct http_headers));
						ns_bzero(ret->headers,sizeof(struct http_headers));
						ret->headers->uri_headers = kv;
					}
				}

				const char *path = evhttp_uri_get_path(uri);
				if(path)
					ret->path = strdup(path);

				evhttp_uri_free(uri);

				if(parse_post) {
					char *body = strstr(s+1,"\r\n\r\n");
					if(body && body[0]) {
						if(!ret->headers) {
							ret->headers = (struct http_headers*)malloc(sizeof(struct http_headers));
							ns_bzero(ret->headers,sizeof(struct http_headers));
						}
						ret->headers->post_headers = post_parse(body,strlen(body));
					}
				}
			}

			*s = ' ';
		}
	}

	return ret;
}

struct http_request* parse_http_request(char* request) {

	struct http_request* ret = NULL;

	if(request) {

		ret = (struct http_request*)malloc(sizeof(struct http_request));
		ns_bzero(ret,sizeof(struct http_request));

		if(strstr(request,"GET ") == request) {
			ret->rtype = HRT_GET;
			ret = parse_http_request_1(ret,request+4,0);
		} else if(strstr(request,"HEAD ") == request) {
			ret->rtype = HRT_HEAD;
			ret = parse_http_request_1(ret,request+5,0);
		} else if(strstr(request,"POST ") == request) {
			ret->rtype = HRT_POST;
			ret = parse_http_request_1(ret,request+5,1);
		} else if(strstr(request,"PUT ") == request) {
			ret->rtype = HRT_PUT;
			ret = parse_http_request_1(ret,request+4,1);
		} else if(strstr(request,"DELETE ") == request) {
			ret->rtype = HRT_DELETE;
			ret = parse_http_request_1(ret,request+7,1);
		} else {
			free(ret);
			ret = NULL;
		}
	}

	return ret;
}

static const char * get_headers_list_value(struct headers_list *h, const char* key) {
	const char* ret = NULL;
	if(h && h->keys && h->values && key && key[0]) {
		size_t i = 0;
		for(i=0;i<h->n;++i) {
			if(h->keys[i] && !strcmp(key,h->keys[i]) && h->values[i]) {
				ret = h->values[i];
				break;
			}
		}
	}
	return ret;
}

static void free_headers_list(struct headers_list *h) {
	if(h) {
		if(h->keys) {
			size_t i = 0;
			for(i=0;i<h->n;++i) {
				if(h->keys[i]) {
					free(h->keys[i]);
					h->keys[i]=NULL;
				}
			}
			free(h->keys);
			h->keys = NULL;
		}
		if(h->values) {
			size_t i = 0;
			for(i=0;i<h->n;++i) {
				if(h->values[i]) {
					free(h->values[i]);
					h->values[i]=NULL;
				}
			}
			free(h->values);
			h->values = NULL;
		}
		h->n = 0;
		free(h);
	}
}

const char *get_http_header_value(const struct http_request *request, const char* key, const char* default_value) {
	const char *ret = NULL;
	if(key && key[0] && request && request->headers) {
		if(request->headers->uri_headers) {
			ret = evhttp_find_header(request->headers->uri_headers,key);
		}
		if(!ret && request->headers->post_headers) {
			ret = get_headers_list_value(request->headers->post_headers,key);
		}
	}
	if(!ret) {
		ret = default_value;
	}
	return ret;
}

void free_http_request(struct http_request *request) {
	if(request) {
		if(request->path) {
			free(request->path);
			request->path = NULL;
		}
		if(request->headers) {
			if(request->headers->uri_headers) {
				evhttp_clear_headers(request->headers->uri_headers);
				free(request->headers->uri_headers);
				request->headers->uri_headers = NULL;
			}
			if(request->headers->post_headers) {
				free_headers_list(request->headers->post_headers);
				request->headers->post_headers = NULL;
			}
			free(request->headers);
			request->headers = NULL;
		}
		free(request);
	}
}

////////////////////////////////////////////

struct str_buffer {
	size_t capacity;
	size_t sz;
	char* buffer;
};

struct str_buffer* str_buffer_new(void)
{
	struct str_buffer* ret = (struct str_buffer*)malloc(sizeof(struct str_buffer));
	ns_bzero(ret,sizeof(struct str_buffer));
	ret->buffer = (char*)malloc(1);
	ret->buffer[0] = 0;
	ret->capacity = 1;
	return ret;
}

void str_buffer_append(struct str_buffer* sb, const char* str)
{
	if(sb && str && str[0]) {
		size_t len = strlen(str);
		while(sb->sz + len + 1 > sb->capacity) {
			sb->capacity += len + 1024;
			sb->buffer = (char*)realloc(sb->buffer,sb->capacity);
		}
		ns_bcopy(str,sb->buffer+sb->sz,len+1);
		sb->sz += len;
	}
}

void str_buffer_append_sz(struct str_buffer* sb, size_t sz)
{
	char ssz[129];
	snprintf(ssz,sizeof(ssz)-1,"%lu",(unsigned long)sz);
	str_buffer_append(sb,ssz);
}

void str_buffer_append_sid(struct str_buffer* sb, turnsession_id sid)
{
	char ssz[129];
	snprintf(ssz,sizeof(ssz)-1,"%018llu",(unsigned long long)sid);
	str_buffer_append(sb,ssz);
}

const char* str_buffer_get_str(const struct str_buffer *sb)
{
	if(sb) {
		return sb->buffer;
	}
	return NULL;
}

size_t str_buffer_get_str_len(const struct str_buffer *sb)
{
	if(sb) {
		return sb->sz;
	}
	return 0;
}

void str_buffer_free(struct str_buffer *sb)
{
	if(sb) {
		free(sb->buffer);
		free(sb);
	}
}

///////////////////////////////////////////////
