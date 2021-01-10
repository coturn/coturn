
/*
 * Copyright (C) 2020 Jens Elkner.  All rights reserved.
 *
 * License: MIT - see https://opensource.org/licenses/MIT
 */

#include "acme.h"
#include "ns_ioalib_impl.h"

#define GET_ACME_PREFIX "GET /.well-known/acme-challenge/"
#define GET_ACME_PREFIX_LEN 32

static int is_acme_req(char *req, size_t len) {
	static const char *A = "                                             -  0123456789       ABCDEFGHIJKLMNOPQRSTUVWXYZ    _ abcdefghijklmnopqrstuvwxyz     ";
	int c, i, k;

	// Check first request line. Should be like: GET path HTTP/1.x
	if (strncmp(req, GET_ACME_PREFIX, GET_ACME_PREFIX_LEN))
		return -1;
	// Usually (for LE) the "method path" is 32 + 43 = 55 chars. But other
	// implementations may choose longer pathes. We define PATHMAX = 127 chars
	// to be prepared for "DoS" attacks (STUN msg size max. is ~ 64K).
	len -= 21;					// min size of trailing headers
	if (len > 131)
		len = 131;
	for (i=GET_ACME_PREFIX_LEN; i < (int) len; i++) {
		// find the end of the path
		if (req[i] != ' ')
			continue;
		// consider path < 10 chars invalid. Also we wanna see a "trailer".
		if (i < (GET_ACME_PREFIX_LEN + 10) || strncmp(req + i, " HTTP/1.", 8))
			return -2;
		// finally check for allowed chars
		for (k=GET_ACME_PREFIX_LEN; k < i; k++) {
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
	size_t plen, rlen;

	if (url == NULL || url[0] == '\0' || req == NULL || s == 0 )
		return 1;
	if (len < (GET_ACME_PREFIX_LEN + 32) || len > (512 - GET_ACME_PREFIX_LEN)
			|| (plen = is_acme_req(req, len)) < (GET_ACME_PREFIX_LEN + 1))
		return 2;

	req[plen] = '\0';

	snprintf(http_response, sizeof(http_response) - 1,
		"HTTP/1.1 301 Moved Permanently\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %ld\r\n"
		"Connection: close\r\n"
		"Location: %s%s\r\n"
		"\r\n%s", strlen(HTML), url, req + GET_ACME_PREFIX_LEN, HTML);

	rlen = strlen(http_response);

#ifdef LIBEV_OK
	ioa_network_buffer_handle nbh_acme = ioa_network_buffer_allocate(s->e);
	uint8_t *data = ioa_network_buffer_data(nbh_acme);
	bcopy(http_response, data, rlen);
	ioa_network_buffer_set_size(nbh_acme, rlen);
	send_data_from_ioa_socket_nbh(s, NULL, nbh_acme, TTL_IGNORE, TOS_IGNORE, NULL);
#else
	if (write(s->fd, http_response, rlen) == -1) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
			"Sending redirect to '%s%s' failed",url, req + GET_ACME_PREFIX_LEN);
	} else if (((turn_turnserver *)s->session->server)->verbose) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ACME redirected to %s%s\n",
			url, req + GET_ACME_PREFIX_LEN);
	}
#endif

	req[plen] = ' ';

	return 0;
}
