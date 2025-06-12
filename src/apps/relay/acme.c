/*
 * SPDX-License-Identifier: MIT
 *
 * https://opensource.org/license/mit
 *
 * Copyright (C) 2020 Jens Elkner.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the “Software”), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "acme.h"
#include "ns_ioalib_impl.h"

#if !defined(_MSC_VER)
#include <unistd.h>
#endif

#define GET_ACME_PREFIX "GET /.well-known/acme-challenge/"
#define GET_ACME_PREFIX_LEN 32

static int is_acme_req(char *req, size_t len) {
  static const char *A = "                                             -  0123456789       ABCDEFGHIJKLMNOPQRSTUVWXYZ  "
                         "  _ abcdefghijklmnopqrstuvwxyz     ";

  // Check first request line. Should be like: GET path HTTP/1.x
  if (strncmp(req, GET_ACME_PREFIX, GET_ACME_PREFIX_LEN) != 0) {
    return -1;
  }
  // Usually (for LE) the "method path" is 32 + 43 = 55 chars. But other
  // implementations may choose longer pathes. We define PATHMAX = 127 chars
  // to be prepared for "DoS" attacks (STUN msg size max. is ~ 64K).
  len -= 21; // min size of trailing headers
  if (len > 131) {
    len = 131;
  }
  for (size_t i = GET_ACME_PREFIX_LEN; i < len; i++) {
    // find the end of the path
    if (req[i] != ' ') {
      continue;
    }
    // consider path < 10 chars invalid. Also we wanna see a "trailer".
    if (i < (GET_ACME_PREFIX_LEN + 10) || strncmp(req + i, " HTTP/1.", 8) != 0) {
      return -2;
    }
    // finally check for allowed chars
    for (size_t k = GET_ACME_PREFIX_LEN; k < i; k++) {
      const unsigned char c = req[k];
      if ((c > 127) || (A[c] == ' ')) {
        return -3;
      }
    }
    // all checks passed: sufficient for us to answer with a redirect
    return (int)i;
  }
  return -4; // end of path not found
}

int try_acme_redirect(char *req, size_t len, const char *url, ioa_socket_handle s) {
  static const char *HTML = "<html><head><title>301 Moved Permanently</title></head>\
		<body><h1>301 Moved Permanently</h1></body></html>";
  char http_response[1024];

  if (url == NULL || url[0] == '\0' || req == NULL || s == 0) {
    return 1;
  }
  size_t plen;
  if (len < (GET_ACME_PREFIX_LEN + 32) || len > (512 - GET_ACME_PREFIX_LEN) ||
      (plen = is_acme_req(req, len)) < (GET_ACME_PREFIX_LEN + 1)) {
    return 2;
  }

  req[plen] = '\0';

  snprintf(http_response, sizeof(http_response) - 1,
           "HTTP/1.1 301 Moved Permanently\r\n"
           "Content-Type: text/html\r\n"
           "Content-Length: %zu\r\n"
           "Connection: close\r\n"
           "Location: %s%s\r\n"
           "\r\n%s",
           strlen(HTML), url, req + GET_ACME_PREFIX_LEN, HTML);

  size_t rlen = strlen(http_response);

#ifdef LIBEV_OK
  ioa_network_buffer_handle nbh_acme = ioa_network_buffer_allocate(s->e);
  uint8_t *data = ioa_network_buffer_data(nbh_acme);
  memcpy(data, http_response, rlen);
  ioa_network_buffer_set_size(nbh_acme, rlen);
  send_data_from_ioa_socket_nbh(s, NULL, nbh_acme, TTL_IGNORE, TOS_IGNORE, NULL);
#else
  if (write(s->fd, http_response, rlen) == -1) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Sending redirect to '%s%s' failed", url, req + GET_ACME_PREFIX_LEN);
  } else if (((turn_turnserver *)s->session->server)->verbose) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ACME redirected to %s%s\n", url, req + GET_ACME_PREFIX_LEN);
  }
#endif

  req[plen] = ' ';

  return 0;
}
