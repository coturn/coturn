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

#include "apputils.h"
#include "uclient.h"
#include "startuclient.h"
#include "ns_turn_utils.h"
#include "session.h"

#include <unistd.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <sys/select.h>

static int verbose_packets=0;

static size_t current_clients_number = 0;

static int start_full_timer=0;
static u32bits tot_messages=0;
static u32bits tot_send_messages=0;
static u64bits tot_send_bytes = 0;
static u32bits tot_recv_messages=0;
static u64bits tot_recv_bytes = 0;
static u64bits tot_send_dropped = 0;

struct event_base* client_event_base=NULL;

static int client_write(app_ur_session *elem);
static int client_shutdown(app_ur_session *elem);

static u64bits current_time = 0;
static u64bits current_mstime = 0;

static char buffer_to_send[65536]="\0";

static int total_clients = 0;

/* Patch for unlimited number of clients provided by ucudbm@gmail.com */
static app_ur_session** elems = NULL;

#define SLEEP_INTERVAL (234)

#define MAX_LISTENING_CYCLE_NUMBER (7)

int RTP_PACKET_INTERVAL = 20;

static inline s64bits time_minus(u64bits t1, u64bits t2) {
	return ( (s64bits)t1 - (s64bits)t2 );
}

static u64bits total_loss = 0;
static u64bits total_jitter = 0;
static u64bits total_latency = 0;

static u64bits min_latency = 0xFFFFFFFF;
static u64bits max_latency = 0;
static u64bits min_jitter = 0xFFFFFFFF;
static u64bits max_jitter = 0;


static int show_statistics = 0;

///////////////////////////////////////////////////////////////////////////////

static void __turn_getMSTime(void) {
  static u64bits start_sec = 0;
  struct timespec tp={0,0};
#if defined(CLOCK_REALTIME)
  clock_gettime(CLOCK_REALTIME, &tp);
#else
  tp.tv_sec = time(NULL);
#endif
  if(!start_sec)
    start_sec = tp.tv_sec;
  if(current_time != (u64bits)((u64bits)(tp.tv_sec)-start_sec))
    show_statistics = 1;
  current_time = (u64bits)((u64bits)(tp.tv_sec)-start_sec);
  current_mstime = (u64bits)((current_time * 1000) + (tp.tv_nsec/1000000));
}

////////////////////////////////////////////////////////////////////

static int refresh_channel(app_ur_session* elem, u16bits method, uint32_t lt);

//////////////////////// SS ////////////////////////////////////////

static app_ur_session* init_app_session(app_ur_session *ss) {
  if(ss) {
    ns_bzero(ss,sizeof(app_ur_session));
    ss->pinfo.fd=-1;
  }
  return ss;
}

static app_ur_session* create_new_ss(void)
{
	++current_clients_number;
	return init_app_session((app_ur_session*) turn_malloc(sizeof(app_ur_session)));
}

static void uc_delete_session_elem_data(app_ur_session* cdi) {
  if(cdi) {
    EVENT_DEL(cdi->input_ev);
    EVENT_DEL(cdi->input_tcp_data_ev);
    if(cdi->pinfo.tcp_conn) {
      int i = 0;
      for(i=0;i<(int)(cdi->pinfo.tcp_conn_number);++i) {
	if(cdi->pinfo.tcp_conn[i]) {
	  if(cdi->pinfo.tcp_conn[i]->tcp_data_ssl && !(cdi->pinfo.broken)) {
	    if(!(SSL_get_shutdown(cdi->pinfo.tcp_conn[i]->tcp_data_ssl) & SSL_SENT_SHUTDOWN)) {
	      SSL_set_shutdown(cdi->pinfo.tcp_conn[i]->tcp_data_ssl, SSL_RECEIVED_SHUTDOWN);
	      SSL_shutdown(cdi->pinfo.tcp_conn[i]->tcp_data_ssl);
	    }
	    if(cdi->pinfo.tcp_conn[i]->tcp_data_ssl) {
	      SSL_FREE(cdi->pinfo.tcp_conn[i]->tcp_data_ssl);
	    }
	    if(cdi->pinfo.tcp_conn[i]->tcp_data_fd>=0) {
	    	socket_closesocket(cdi->pinfo.tcp_conn[i]->tcp_data_fd);
	      cdi->pinfo.tcp_conn[i]->tcp_data_fd=-1;
	    }
	    turn_free(cdi->pinfo.tcp_conn[i], 111);
	    cdi->pinfo.tcp_conn[i]=NULL;
	  }
	}
      }
      cdi->pinfo.tcp_conn_number=0;
      if(cdi->pinfo.tcp_conn) {
    	  turn_free(cdi->pinfo.tcp_conn, 111);
    	  cdi->pinfo.tcp_conn=NULL;
      }
    }
    if(cdi->pinfo.ssl && !(cdi->pinfo.broken)) {
	    if(!(SSL_get_shutdown(cdi->pinfo.ssl) & SSL_SENT_SHUTDOWN)) {
		    SSL_set_shutdown(cdi->pinfo.ssl, SSL_RECEIVED_SHUTDOWN);
		    SSL_shutdown(cdi->pinfo.ssl);
	    }
    }
    if(cdi->pinfo.ssl) {
	    SSL_FREE(cdi->pinfo.ssl);
    }
    if(cdi->pinfo.fd>=0) {
    	socket_closesocket(cdi->pinfo.fd);
    }
    cdi->pinfo.fd=-1;
  }
}

static int remove_all_from_ss(app_ur_session* ss)
{
	if (ss) {
		uc_delete_session_elem_data(ss);

		--current_clients_number;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

int send_buffer(app_ur_conn_info *clnet_info, stun_buffer* message, int data_connection, app_tcp_conn_info *atc)
{

	int rc = 0;
	int ret = -1;

	char *buffer = (char*) (message->buf);

	if(negative_protocol_test && (message->len>0)) {
		if(random()%10 == 0) {
			int np = (int)((unsigned long)random()%10);
			while(np-->0) {
				int pos = (int)((unsigned long)random()%(unsigned long)message->len);
				int val = (int)((unsigned long)random()%256);
				message->buf[pos]=(u08bits)val;
			}
		}
	}

	SSL *ssl = clnet_info->ssl;
	ioa_socket_raw fd = clnet_info->fd;

	if(data_connection) {
	  if(atc) {
	    ssl = atc->tcp_data_ssl;
	    fd = atc->tcp_data_fd;
	  } else if(is_TCP_relay()){
	    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
			  "trying to send tcp data buffer over unready connection: size=%d\n",(int)(message->len));
	    return -1;
	  }
	}

	if (ssl) {

		int message_sent = 0;
		while (!message_sent) {

			if (SSL_get_shutdown(ssl)) {
				return -1;
			}

			int len = 0;
			do {
				len = SSL_write(ssl, buffer, (int)message->len);
			} while (len < 0 && ((errno == EINTR) || (errno == ENOBUFS)));

			if(len == (int)message->len) {
				if (clnet_verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"buffer sent: size=%d\n",len);
				}

				message_sent = 1;
				ret = len;
			} else {
				switch (SSL_get_error(ssl, len)){
				case SSL_ERROR_NONE:
					/* Try again ? */
					break;
				case SSL_ERROR_WANT_WRITE:
					/* Just try again later */
					break;
				case SSL_ERROR_WANT_READ:
					/* continue with reading */
					break;
				case SSL_ERROR_ZERO_RETURN:
					/* Try again */
					break;
				case SSL_ERROR_SYSCALL:
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Socket write error 111.666: \n");
					if (handle_socket_error())
						break;
				case SSL_ERROR_SSL:
				{
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL write error: \n");
					char buf[1024];
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						"%s (%d)\n",
						ERR_error_string(ERR_get_error(),buf),
						SSL_get_error(ssl, len));
				}
				default:
					clnet_info->broken = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Unexpected error while writing!\n");
					return -1;
				}
			}
		}

	} else if (fd >= 0) {

		size_t left = (size_t) (message->len);

		while (left > 0) {
			do {
				rc = send(fd, buffer, left, 0);
			} while (rc < 0 && ((errno == EINTR) || (errno == ENOBUFS)));
			if (rc > 0) {
				left -= (size_t) rc;
				buffer += rc;
			} else {
				tot_send_dropped+=1;
				break;
			}
		}

		if (left > 0)
			return -1;

		ret = (int) message->len;
	}

	return ret;
}

static int wait_fd(int fd, unsigned int cycle) {

	if(fd>=(int)FD_SETSIZE) {
		return 1;
	} else {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fd,&fds);

		if(dos && cycle==0)
			return 0;

		struct timeval start_time;
		struct timeval ctime;
		gettimeofday(&start_time,NULL);

		ctime.tv_sec = start_time.tv_sec;
		ctime.tv_usec = start_time.tv_usec;

		int rc = 0;

		do {
			struct timeval timeout = {0,0};
			if(cycle == 0) {
				timeout.tv_usec = 500000;
			} else {

				timeout.tv_sec = 1;
				while(--cycle) timeout.tv_sec = timeout.tv_sec + timeout.tv_sec;

				if(ctime.tv_sec > start_time.tv_sec) {
					if(ctime.tv_sec >= start_time.tv_sec + timeout.tv_sec) {
						break;
					} else {
						timeout.tv_sec -= (ctime.tv_sec - start_time.tv_sec);
					}
				}
			}
			rc = select(fd+1,&fds,NULL,NULL,&timeout);
			if((rc<0) && (errno == EINTR)) {
				gettimeofday(&ctime,NULL);
			} else {
				break;
			}
		} while(1);

		return rc;
	}
}

int recv_buffer(app_ur_conn_info *clnet_info, stun_buffer* message, int sync, int data_connection, app_tcp_conn_info *atc, stun_buffer* request_message) {

	int rc = 0;

	stun_tid tid;
	u16bits method = 0;

	if(request_message) {
		stun_tid_from_message(request_message, &tid);
		method = stun_get_method(request_message);
	}

	ioa_socket_raw fd = clnet_info->fd;
	if (atc)
		fd = atc->tcp_data_fd;

	SSL* ssl = clnet_info->ssl;
	if (atc)
		ssl = atc->tcp_data_ssl;

	recv_again:

	if(!use_tcp && sync && request_message && (fd>=0)) {

		unsigned int cycle = 0;
		while(cycle < MAX_LISTENING_CYCLE_NUMBER) {
			int serc = wait_fd(fd,cycle);
			if(serc>0)
				break;
			if(serc<0) {
				return -1;
			}
			if(send_buffer(clnet_info, request_message, data_connection, atc)<=0)
				return -1;
			++cycle;
		}
	}

	if (!use_secure && !use_tcp && fd >= 0) {

		/* Plain UDP */

		do {
			rc = recv(fd, message->buf, sizeof(message->buf) - 1, 0);
			if (rc < 0 && errno == EAGAIN && sync)
				errno = EINTR;
		} while (rc < 0 && (errno == EINTR));

		if (rc < 0) {
			return -1;
		}

		message->len = rc;

	} else if (use_secure && !use_tcp && ssl && !(clnet_info->broken)) {

		/* DTLS */

		int message_received = 0;
		int cycle = 0;
		while (!message_received && cycle++ < 100) {

			if (SSL_get_shutdown(ssl))
				return -1;

			rc = 0;
			do {
				rc = SSL_read(ssl, message->buf, sizeof(message->buf) - 1);
				if (rc < 0 && errno == EAGAIN && sync)
					continue;
			} while (rc < 0 && (errno == EINTR));

			if (rc > 0) {

				if (clnet_verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"response received: size=%d\n", rc);
				}
				message->len = rc;
				message_received = 1;

			} else {

				int sslerr = SSL_get_error(ssl, rc);

				switch (sslerr) {
				case SSL_ERROR_NONE:
					/* Try again ? */
					break;
				case SSL_ERROR_WANT_WRITE:
					/* Just try again later */
					break;
				case SSL_ERROR_WANT_READ:
					/* continue with reading */
					break;
				case SSL_ERROR_ZERO_RETURN:
					/* Try again */
					break;
				case SSL_ERROR_SYSCALL:
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"Socket read error 111.999: \n");
					if (handle_socket_error())
						break;
				case SSL_ERROR_SSL: {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL write error: \n");
					char buf[1024];
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s (%d)\n",
							ERR_error_string(ERR_get_error(), buf),
							SSL_get_error(ssl, rc));
				}
				default:
					clnet_info->broken = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"Unexpected error while reading: rc=%d, sslerr=%d\n",
							rc, sslerr);
					return -1;
				}

				if (!sync)
					break;
			}
		}

	} else if (use_secure && use_tcp && ssl && !(clnet_info->broken)) {

		/* TLS*/

		int message_received = 0;
		int cycle = 0;
		while (!message_received && cycle++ < 100) {

			if (SSL_get_shutdown(ssl))
				return -1;
				rc = 0;
			do {
				rc = SSL_read(ssl, message->buf, sizeof(message->buf) - 1);
				if (rc < 0 && errno == EAGAIN && sync)
					continue;
			} while (rc < 0 && (errno == EINTR));

			if (rc > 0) {

				if (clnet_verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"response received: size=%d\n", rc);
				}
				message->len = rc;
				message_received = 1;

			} else {

			int sslerr = SSL_get_error(ssl, rc);

				switch (sslerr) {
				case SSL_ERROR_NONE:
					/* Try again ? */
					break;
				case SSL_ERROR_WANT_WRITE:
					/* Just try again later */
					break;
				case SSL_ERROR_WANT_READ:
					/* continue with reading */
					break;
				case SSL_ERROR_ZERO_RETURN:
					/* Try again */
					break;
				case SSL_ERROR_SYSCALL:
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"Socket read error 111.999: \n");
					if (handle_socket_error())
						break;
				case SSL_ERROR_SSL: {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL write error: \n");
					char buf[1024];
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s (%d)\n",
							ERR_error_string(ERR_get_error(), buf),
							SSL_get_error(ssl, rc));
				}
				default:
					clnet_info->broken = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"Unexpected error while reading: rc=%d, sslerr=%d\n",
							rc, sslerr);
					return -1;
				}

				if (!sync)
					break;
			}
		}

	} else if (!use_secure && use_tcp && fd >= 0) {

		/* Plain TCP */

		do {
			rc = recv(fd, message->buf, sizeof(message->buf) - 1, MSG_PEEK);
			if ((rc < 0) && (errno == EAGAIN) && sync) {
				errno = EINTR;
			}
		} while (rc < 0 && (errno == EINTR));

		if (rc > 0) {
			int mlen = rc;
			size_t app_msg_len = (size_t) rc;
			if (!atc) {
				mlen = stun_get_message_len_str(message->buf, rc, 1,
						&app_msg_len);
			} else {
				if (!sync)
					mlen = clmessage_length;

				if (mlen > clmessage_length)
					mlen = clmessage_length;

				app_msg_len = (size_t) mlen;
			}

			if (mlen > 0) {

				int rcr = 0;
				int rsf = 0;
				int cycle = 0;
				while (rsf < mlen && cycle++ < 128) {
					do {
						rcr = recv(fd, message->buf + rsf,
								(size_t) mlen - (size_t) rsf, 0);
						if (rcr < 0 && errno == EAGAIN && sync)
							errno = EINTR;
					} while (rcr < 0 && (errno == EINTR));

					if (rcr > 0)
						rsf += rcr;

				}

				if (rsf < 1)
					return -1;

				if (rsf < (int) app_msg_len) {
					if ((size_t) (app_msg_len / (size_t) rsf) * ((size_t) (rsf))
							!= app_msg_len) {
						return -1;
					}
				}

				message->len = app_msg_len;

				rc = app_msg_len;

			} else {
				rc = 0;
			}
		}
	}

	if(rc>0) {
		if(request_message) {

			stun_tid recv_tid;
			u16bits recv_method = 0;

			stun_tid_from_message(message, &recv_tid);
			recv_method = stun_get_method(message);

			if(method != recv_method) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Received wrong response method: 0x%x, expected 0x%x; trying again...\n",(unsigned int)recv_method,(unsigned int)method);
				goto recv_again;
			}

			if(memcmp(tid.tsx_id,recv_tid.tsx_id,STUN_TID_SIZE)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Received wrong response tid; trying again...\n");
				goto recv_again;
			}
		}
	}

	return rc;
}

static int client_read(app_ur_session *elem, int is_tcp_data, app_tcp_conn_info *atc) {

	if (!elem)
		return -1;

	if (elem->state != UR_STATE_READY)
		return -1;

	elem->ctime = current_time;

	app_ur_conn_info *clnet_info = &(elem->pinfo);
	int err_code = 0;
	u08bits err_msg[129];
	int rc = 0;
	int applen = 0;

	if (clnet_verbose && verbose_packets) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "before read ...\n");
	}

	rc = recv_buffer(clnet_info, &(elem->in_buffer), 0, is_tcp_data, atc, NULL);

	if (clnet_verbose && verbose_packets) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "read %d bytes\n", (int) rc);
	}

	if (rc > 0) {

		elem->in_buffer.len = rc;

		uint16_t chnumber = 0;

		const message_info *mi = NULL;

		size_t buffers = 1;

		if(is_tcp_data) {
		   if ((int)elem->in_buffer.len == clmessage_length) {
		     mi = (message_info*)(elem->in_buffer.buf);
		   }
		} else if (stun_is_indication(&(elem->in_buffer))) {

			uint16_t method = stun_get_method(&elem->in_buffer);

			if((method == STUN_METHOD_CONNECTION_ATTEMPT)&& is_TCP_relay()) {
			  stun_attr_ref sar = stun_attr_get_first(&(elem->in_buffer));
			  u32bits cid = 0;
			  while(sar) {
				  int attr_type = stun_attr_get_type(sar);
				  if(attr_type == STUN_ATTRIBUTE_CONNECTION_ID) {
					  cid = *((const u32bits*)stun_attr_get_value(sar));
					  break;
				  }
				  sar = stun_attr_get_next_str(elem->in_buffer.buf,elem->in_buffer.len,sar);
			  }
			  if(negative_test) {
				  tcp_data_connect(elem,(u64bits)random());
			  } else {
				  /* positive test */
				  tcp_data_connect(elem,cid);
			  }
			  return rc;
			} else if (method != STUN_METHOD_DATA) {
				TURN_LOG_FUNC(
						TURN_LOG_LEVEL_INFO,
						"ERROR: received indication message has wrong method: 0x%x\n",
						(int) method);
				return rc;
			} else {

				stun_attr_ref sar = stun_attr_get_first_by_type(&(elem->in_buffer), STUN_ATTRIBUTE_DATA);
				if (!sar) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ERROR: received DATA message has no data, size=%d\n", rc);
					return rc;
				}

				int rlen = stun_attr_get_len(sar);
				applen = rlen;
				if (rlen != clmessage_length) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ERROR: received DATA message has wrong len: %d, must be %d\n", rlen, clmessage_length);
					tot_recv_bytes += applen;
					return rc;
				}

				const u08bits* data = stun_attr_get_value(sar);

				mi = (const message_info*) data;
			}

		} else if (stun_is_success_response(&(elem->in_buffer))) {

			if(elem->pinfo.nonce[0]) {
				if(check_integrity(&(elem->pinfo), &(elem->in_buffer))<0)
					return -1;
			}

			if(is_TCP_relay() && (stun_get_method(&(elem->in_buffer)) == STUN_METHOD_CONNECT)) {
				stun_attr_ref sar = stun_attr_get_first(&(elem->in_buffer));
				u32bits cid = 0;
				while(sar) {
				  int attr_type = stun_attr_get_type(sar);
				  if(attr_type == STUN_ATTRIBUTE_CONNECTION_ID) {
					  cid = *((const u32bits*)stun_attr_get_value(sar));
					  break;
				  }
				  sar = stun_attr_get_next_str(elem->in_buffer.buf,elem->in_buffer.len,sar);
				}
				tcp_data_connect(elem,cid);
			}

			return rc;
		} else if (stun_is_challenge_response_str(elem->in_buffer.buf, (size_t)elem->in_buffer.len,
							&err_code,err_msg,sizeof(err_msg),
							clnet_info->realm,clnet_info->nonce,
							clnet_info->server_name, &(clnet_info->oauth))) {
			if(is_TCP_relay() && (stun_get_method(&(elem->in_buffer)) == STUN_METHOD_CONNECT)) {
				turn_tcp_connect(clnet_verbose, &(elem->pinfo), &(elem->pinfo.peer_addr));
			} else if(stun_get_method(&(elem->in_buffer)) == STUN_METHOD_REFRESH) {
				refresh_channel(elem, stun_get_method(&elem->in_buffer),600);
			}
			return rc;
		} else if (stun_is_error_response(&(elem->in_buffer), NULL,NULL,0)) {
			return rc;
		} else if (stun_is_channel_message(&(elem->in_buffer), &chnumber, use_tcp)) {
			if (elem->chnum != chnumber) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						"ERROR: received message has wrong channel: %d\n",
						(int) chnumber);
				return rc;
			}

			if (elem->in_buffer.len >= 4) {
				if (((int)(elem->in_buffer.len-4) < clmessage_length) ||
					((int)(elem->in_buffer.len-4) > clmessage_length + 3)) {
					TURN_LOG_FUNC(
							TURN_LOG_LEVEL_INFO,
							"ERROR: received buffer have wrong length: %d, must be %d, len=%d\n",
							rc, clmessage_length + 4,(int)elem->in_buffer.len);
					return rc;
				}

				mi = (message_info*)(elem->in_buffer.buf + 4);
				applen = elem->in_buffer.len -4;
			}
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					"ERROR: Unknown message received of size: %d\n",(int)(elem->in_buffer.len));
			return rc;
		}

		if(mi) {
			/*
			printf("%s: 111.111: msgnum=%d, rmsgnum=%d, sent=%lu, recv=%lu\n",__FUNCTION__,
				mi->msgnum,elem->recvmsgnum,(unsigned long)mi->mstime,(unsigned long)current_mstime);
				*/
			if(mi->msgnum != elem->recvmsgnum+1)
				++(elem->loss);
			else {
			  u64bits clatency = (u64bits)time_minus(current_mstime,mi->mstime);
			  if(clatency>max_latency)
			    max_latency = clatency;
			  if(clatency<min_latency)
			    min_latency = clatency;
			  elem->latency += clatency;
			  if(elem->rmsgnum>0) {
			    u64bits cjitter = abs((int)(current_mstime-elem->recvtimems)-RTP_PACKET_INTERVAL);
			    
			    if(cjitter>max_jitter)
			      max_jitter = cjitter;
			    if(cjitter<min_jitter)
			      min_jitter = cjitter;
			    
			    elem->jitter += cjitter;
			  }
			}

			elem->recvmsgnum = mi->msgnum;
		}

		elem->rmsgnum+=buffers;
		tot_recv_messages+=buffers;
		if(applen > 0)
			tot_recv_bytes += applen;
		else
			tot_recv_bytes += elem->in_buffer.len;
		elem->recvtimems=current_mstime;
		elem->wait_cycles = 0;

	} else if(rc == 0) {
		return 0;
	} else {
		return -1;
	}

	return rc;
}

static int client_shutdown(app_ur_session *elem) {

  if(!elem) return -1;

  elem->state=UR_STATE_DONE;

  elem->ctime=current_time;

  remove_all_from_ss(elem);
  
  if (clnet_verbose)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"done, connection 0x%lx closed.\n",(long)elem);
  
  return 0;
}

static int client_write(app_ur_session *elem) {

  if(!elem) return -1;

  if(elem->state!=UR_STATE_READY) return -1;

  elem->ctime=current_time;

  message_info *mi = (message_info*)buffer_to_send;
  mi->msgnum=elem->wmsgnum;
  mi->mstime=current_mstime;
  app_tcp_conn_info *atc=NULL;

  if (is_TCP_relay()) {

	  memcpy(elem->out_buffer.buf, buffer_to_send, clmessage_length);
	  elem->out_buffer.len = clmessage_length;

	  if(elem->pinfo.is_peer) {
		  if(send(elem->pinfo.fd, elem->out_buffer.buf, clmessage_length, 0)>=0) {
			  ++elem->wmsgnum;
			  elem->to_send_timems += RTP_PACKET_INTERVAL;
			  tot_send_messages++;
			  tot_send_bytes += clmessage_length;
		  }
		  return 0;
	  }

	if (!(elem->pinfo.tcp_conn) || !(elem->pinfo.tcp_conn_number)) {
		return -1;
	}
	int i = (unsigned int)(random()) % elem->pinfo.tcp_conn_number;
	atc = elem->pinfo.tcp_conn[i];
	if(!atc->tcp_data_bound) {
		printf("%s: Uninitialized atc: i=%d, atc=0x%lx\n",__FUNCTION__,i,(long)atc);
		return -1;
	}
  } else if(!do_not_use_channel) {
	  /* Let's always do padding: */
    stun_init_channel_message(elem->chnum, &(elem->out_buffer), clmessage_length, mandatory_channel_padding || use_tcp);
    memcpy(elem->out_buffer.buf+4,buffer_to_send,clmessage_length);
  } else {
    stun_init_indication(STUN_METHOD_SEND, &(elem->out_buffer));
    stun_attr_add(&(elem->out_buffer), STUN_ATTRIBUTE_DATA, buffer_to_send, clmessage_length);
    stun_attr_add_addr(&(elem->out_buffer),STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(elem->pinfo.peer_addr));
    if(dont_fragment)
	    stun_attr_add(&(elem->out_buffer), STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);

    if(use_fingerprints)
	    stun_attr_add_fingerprint_str(elem->out_buffer.buf,(size_t*)&(elem->out_buffer.len));
  }

  if (elem->out_buffer.len > 0) {
    
    if (clnet_verbose && verbose_packets) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "before write ...\n");
    }

    int rc=send_buffer(&(elem->pinfo),&(elem->out_buffer),1,atc);

    ++elem->wmsgnum;
    elem->to_send_timems += RTP_PACKET_INTERVAL;
    
    if(rc >= 0) {
      if (clnet_verbose && verbose_packets) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "wrote %d bytes\n", (int) rc);
	  }
      tot_send_messages++;
      tot_send_bytes += clmessage_length;
    } else {
    	return -1;
    }
  }

  return 0;
}

void client_input_handler(evutil_socket_t fd, short what, void* arg) {

  if(!(what&EV_READ)||!arg) return;

  UNUSED_ARG(fd);

  app_ur_session* elem = (app_ur_session*)arg;
  if(!elem) {
    return;
  }
  
  switch(elem->state) {
  case UR_STATE_READY:
  do {
    app_tcp_conn_info *atc = NULL;
    int is_tcp_data = 0;
    if(elem->pinfo.tcp_conn) {
      int i = 0;
      for(i=0;i<(int)(elem->pinfo.tcp_conn_number);++i) {
    	  if(elem->pinfo.tcp_conn[i]) {
    		  if((fd==elem->pinfo.tcp_conn[i]->tcp_data_fd) && (elem->pinfo.tcp_conn[i]->tcp_data_bound)) {
    			  is_tcp_data = 1;
    			  atc = elem->pinfo.tcp_conn[i];
    			  break;
    		  }
    	  }
      }
    }
    int rc = client_read(elem, is_tcp_data, atc);
    if(rc<=0) break;
  } while(1);

    break;
  default:
    ;
  }
}

static void run_events(int short_burst)
{
	struct timeval timeout;

	if(!short_burst) {
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
	} else {
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;
	}

	event_base_loopexit(client_event_base, &timeout);

	event_base_dispatch(client_event_base);
}

////////////////////// main method /////////////////

static int start_client(const char *remote_address, int port,
			const unsigned char* ifname, const char *local_address, 
			int messagenumber, 
			int i) {

  app_ur_session* ss=create_new_ss();
  app_ur_session* ss_rtcp=NULL;

  if(!no_rtcp)
    ss_rtcp = create_new_ss();

  app_ur_conn_info clnet_info_probe; /* for load balancing probe */
  ns_bzero(&clnet_info_probe,sizeof(clnet_info_probe));
  clnet_info_probe.fd = -1;

  app_ur_conn_info *clnet_info=&(ss->pinfo);
  app_ur_conn_info *clnet_info_rtcp=NULL;

  if(!no_rtcp) 
    clnet_info_rtcp = &(ss_rtcp->pinfo);

  uint16_t chnum=0;
  uint16_t chnum_rtcp=0;

  start_connection(port, remote_address, 
		   ifname, local_address, 
		   clnet_verbose,
		   &clnet_info_probe,
		   clnet_info, &chnum,
		   clnet_info_rtcp, &chnum_rtcp);
		   
  if(clnet_info_probe.ssl) {
  	SSL_FREE(clnet_info_probe.ssl);
  	clnet_info_probe.fd = -1;
  } else if(clnet_info_probe.fd != -1) {
	  socket_closesocket(clnet_info_probe.fd);
	  clnet_info_probe.fd = -1;
  }
  
  socket_set_nonblocking(clnet_info->fd);
  
  if(!no_rtcp) 
	  socket_set_nonblocking(clnet_info_rtcp->fd);
  
  struct event* ev = event_new(client_event_base,clnet_info->fd,
				EV_READ|EV_PERSIST,client_input_handler,
				ss);

  event_add(ev,NULL);
  
  struct event* ev_rtcp = NULL;

  if(!no_rtcp) {
    ev_rtcp = event_new(client_event_base,clnet_info_rtcp->fd,
			EV_READ|EV_PERSIST,client_input_handler,
			ss_rtcp);
  
    event_add(ev_rtcp,NULL);
  }
  
  ss->state=UR_STATE_READY;
  
  ss->input_ev=ev;
  ss->tot_msgnum=messagenumber;
  ss->recvmsgnum=-1;
  ss->chnum=chnum;

  if(!no_rtcp) {

    ss_rtcp->state=UR_STATE_READY;
    
    ss_rtcp->input_ev=ev_rtcp;
    ss_rtcp->tot_msgnum=ss->tot_msgnum;
    if(ss_rtcp->tot_msgnum<1) ss_rtcp->tot_msgnum=1;
    ss_rtcp->recvmsgnum=-1;
    ss_rtcp->chnum=chnum_rtcp;
  }
  
  elems[i]=ss;

  refresh_channel(ss, 0, 600);

  if(!no_rtcp)
    elems[i+1]=ss_rtcp;

  return 0;
}

static int start_c2c(const char *remote_address, int port,
			    const unsigned char* ifname, const char *local_address, 
			    int messagenumber, 
			    int i) {

  app_ur_session* ss1=create_new_ss();
  app_ur_session* ss1_rtcp=NULL;

  if(!no_rtcp)
    ss1_rtcp = create_new_ss();

  app_ur_session* ss2=create_new_ss();
  app_ur_session* ss2_rtcp=NULL;

  if(!no_rtcp)
    ss2_rtcp = create_new_ss();

  app_ur_conn_info clnet_info_probe; /* for load balancing probe */
  ns_bzero(&clnet_info_probe,sizeof(clnet_info_probe));
  clnet_info_probe.fd = -1;

  app_ur_conn_info *clnet_info1=&(ss1->pinfo);
  app_ur_conn_info *clnet_info1_rtcp=NULL;

  if(!no_rtcp)
    clnet_info1_rtcp = &(ss1_rtcp->pinfo);

  app_ur_conn_info *clnet_info2=&(ss2->pinfo);
  app_ur_conn_info *clnet_info2_rtcp=NULL;

  if(!no_rtcp)
    clnet_info2_rtcp = &(ss2_rtcp->pinfo);

  uint16_t chnum1=0;
  uint16_t chnum1_rtcp=0;
  uint16_t chnum2=0;
  uint16_t chnum2_rtcp=0;

  start_c2c_connection(port, remote_address, 
		       ifname, local_address, 
		       clnet_verbose,
		       &clnet_info_probe,
		       clnet_info1, &chnum1,
		       clnet_info1_rtcp, &chnum1_rtcp,
		       clnet_info2, &chnum2,
		       clnet_info2_rtcp, &chnum2_rtcp);
		       
  if(clnet_info_probe.ssl) {
	SSL_FREE(clnet_info_probe.ssl);
	clnet_info_probe.fd = -1;
  } else if(clnet_info_probe.fd != -1) {
	  socket_closesocket(clnet_info_probe.fd);
	  clnet_info_probe.fd = -1;
  }
  
  socket_set_nonblocking(clnet_info1->fd);
  
  if(!no_rtcp)
	  socket_set_nonblocking(clnet_info1_rtcp->fd);
  
  socket_set_nonblocking(clnet_info2->fd);
  
  if(!no_rtcp)
	  socket_set_nonblocking(clnet_info2_rtcp->fd);
  
  struct event* ev1 = event_new(client_event_base,clnet_info1->fd,
				EV_READ|EV_PERSIST,client_input_handler,
				ss1);

  event_add(ev1,NULL);
  
  struct event* ev1_rtcp = NULL;

  if(!no_rtcp) {
    ev1_rtcp = event_new(client_event_base,clnet_info1_rtcp->fd,
			 EV_READ|EV_PERSIST,client_input_handler,
			 ss1_rtcp);
    
    event_add(ev1_rtcp,NULL);
  }

  struct event* ev2 = event_new(client_event_base,clnet_info2->fd,
				EV_READ|EV_PERSIST,client_input_handler,
				ss2);

  event_add(ev2,NULL);
  
  struct event* ev2_rtcp = NULL;

  if(!no_rtcp) {
    ev2_rtcp = event_new(client_event_base,clnet_info2_rtcp->fd,
			 EV_READ|EV_PERSIST,client_input_handler,
			 ss2_rtcp);
    
    event_add(ev2_rtcp,NULL);
  }

  ss1->state=UR_STATE_READY;
  
  ss1->input_ev=ev1;
  ss1->tot_msgnum=messagenumber;
  ss1->recvmsgnum=-1;
  ss1->chnum=chnum1;

  if(!no_rtcp) {

    ss1_rtcp->state=UR_STATE_READY;
    
    ss1_rtcp->input_ev=ev1_rtcp;
    ss1_rtcp->tot_msgnum=ss1->tot_msgnum;
    if(ss1_rtcp->tot_msgnum<1) ss1_rtcp->tot_msgnum=1;
    ss1_rtcp->recvmsgnum=-1;
    ss1_rtcp->chnum=chnum1_rtcp;
  }

  ss2->state=UR_STATE_READY;
  
  ss2->input_ev=ev2;
  ss2->tot_msgnum=ss1->tot_msgnum;
  ss2->recvmsgnum=-1;
  ss2->chnum=chnum2;

  if(!no_rtcp) {
    ss2_rtcp->state=UR_STATE_READY;
  
    ss2_rtcp->input_ev=ev2_rtcp;
    ss2_rtcp->tot_msgnum=ss1_rtcp->tot_msgnum;
    ss2_rtcp->recvmsgnum=-1;
    ss2_rtcp->chnum=chnum2_rtcp;
  }
  
  elems[i++]=ss1;
  if(!no_rtcp)
    elems[i++]=ss1_rtcp;
  elems[i++]=ss2;
  if(!no_rtcp)
    elems[i++]=ss2_rtcp;

  return 0;
}

static int refresh_channel(app_ur_session* elem, u16bits method, uint32_t lt)
{

	stun_buffer message;
	app_ur_conn_info *clnet_info = &(elem->pinfo);

	if(clnet_info->is_peer)
		return 0;

	if (!method || (method == STUN_METHOD_REFRESH)) {
		stun_init_request(STUN_METHOD_REFRESH, &message);
		lt = htonl(lt);
		stun_attr_add(&message, STUN_ATTRIBUTE_LIFETIME, (const char*) &lt, 4);

		if(dual_allocation && !mobility) {
			int t = ((u08bits)random())%3;
			if(t) {
				u08bits field[4];
				field[0] = (t==1) ? (u08bits)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4 : (u08bits)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
				field[1]=0;
				field[2]=0;
				field[3]=0;
				stun_attr_add(&message, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY, (const char*) field, 4);
			}
		}

		add_origin(&message);
		if(add_integrity(clnet_info, &message)<0) return -1;
		if(use_fingerprints)
			    stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
		send_buffer(clnet_info, &message, 0,0);
	}

	if (lt && !addr_any(&(elem->pinfo.peer_addr))) {

		if(!no_permissions) {
			if (!method || (method == STUN_METHOD_CREATE_PERMISSION)) {
				stun_init_request(STUN_METHOD_CREATE_PERMISSION, &message);
				stun_attr_add_addr(&message, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(elem->pinfo.peer_addr));
				add_origin(&message);
				if(add_integrity(clnet_info, &message)<0) return -1;
				if(use_fingerprints)
				    stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
				send_buffer(&(elem->pinfo), &message, 0,0);
			}
		}

		if (!method || (method == STUN_METHOD_CHANNEL_BIND)) {
			if (STUN_VALID_CHANNEL(elem->chnum)) {
				stun_set_channel_bind_request(&message, &(elem->pinfo.peer_addr), elem->chnum);
				add_origin(&message);
				if(add_integrity(clnet_info, &message)<0) return -1;
				if(use_fingerprints)
					    stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
				send_buffer(&(elem->pinfo), &message,1,0);
			}
		}
	}

	elem->refresh_time = current_mstime + 30*1000;

	return 0;
}

static inline int client_timer_handler(app_ur_session* elem, int *done)
{
	if (elem) {
		if (!turn_time_before(current_mstime, elem->refresh_time)) {
			refresh_channel(elem, 0, 600);
		}

		if(hang_on && elem->completed)
			return 0;

		int max_num = 50;
		int cur_num = 0;

		while (!turn_time_before(current_mstime, elem->to_send_timems)) {
		  if(cur_num++>=max_num)
		    break;
			if (elem->wmsgnum >= elem->tot_msgnum) {
				if (!turn_time_before(current_mstime, elem->finished_time) ||
				 (tot_recv_messages>=tot_messages)) {
					/*
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: elem=0x%x: 111.111: c=%d, t=%d, r=%d, w=%d\n",__FUNCTION__,(int)elem,elem->wait_cycles,elem->tot_msgnum,elem->rmsgnum,elem->wmsgnum);
					*/
					/*
					 TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: 111.222: ly=%llu, ls=%llu, j=%llu\n",__FUNCTION__,
					 (unsigned long long)elem->latency,
					 (unsigned long long)elem->loss,
					 (unsigned long long)elem->jitter);
					*/
					total_loss += elem->loss;
					elem->loss=0;
					total_latency += elem->latency;
					elem->latency=0;
					total_jitter += elem->jitter;
					elem->jitter=0;
					elem->completed = 1;
					if (!hang_on) {
						refresh_channel(elem,0,0);
						client_shutdown(elem);
						return 1;
					} else {
						return 0;
					}
				}
			} else {
				*done += 1;
				client_write(elem);
				elem->finished_time = current_mstime + STOPPING_TIME*1000;
			}
		}
	}

	return 0;
}

static void timer_handler(evutil_socket_t fd, short event, void *arg)
{
	UNUSED_ARG(fd);
	UNUSED_ARG(event);
	UNUSED_ARG(arg);

	__turn_getMSTime();

	if(start_full_timer) {
		int i = 0;
		int done = 0;
		for (i = 0; i < total_clients; ++i) {
			if (elems[i]) {
				int finished = client_timer_handler(elems[i], &done);
				if (finished) {
					elems[i] = NULL;
				}
			}
		}
		if(done>5 && (dos || random_disconnect)) {
			for (i = 0; i < total_clients; ++i) {
				if (elems[i]) {
					close(elems[i]->pinfo.fd);
					elems[i]->pinfo.fd = -1;
				}
			}
		}
	}
}

void start_mclient(const char *remote_address, int port,
		const unsigned char* ifname, const char *local_address,
		int messagenumber, int mclient) {

	if (mclient < 1)
		mclient = 1;

	total_clients = mclient;

	if(c2c) {
	  //mclient must be a multiple of 4:
	  if(!no_rtcp)
	    mclient += ((4 - (mclient & 0x00000003)) & 0x00000003);
	  else if(mclient & 0x1)
	    ++mclient;
	} else {
	  if(!no_rtcp)
	    if(mclient & 0x1)
	      ++mclient;
	}

	elems = (app_ur_session**)turn_malloc(sizeof(app_ur_session)*((mclient*2)+1)+sizeof(void*));

	__turn_getMSTime();
	u32bits stime = current_time;

	memset(buffer_to_send, 7, clmessage_length);

	client_event_base = turn_event_base_new();

	int i = 0;
	int tot_clients = 0;

	if(c2c) {
	  if(!no_rtcp)
	    for (i = 0; i < (mclient >> 2); i++) {
	      if(!dos) usleep(SLEEP_INTERVAL);
	      if (start_c2c(remote_address, port, ifname, local_address,
			    messagenumber, i << 2) < 0) {
	    	  exit(-1);
	      }
	      tot_clients+=4;
	    }
	  else
	    for (i = 0; i < (mclient >> 1); i++) {
	      if(!dos) usleep(SLEEP_INTERVAL);
	      if (start_c2c(remote_address, port, ifname, local_address,
			    messagenumber, i << 1) < 0) {
	    	  exit(-1);
	      }
	      tot_clients+=2;
	    }
	} else {
	  if(!no_rtcp)
	    for (i = 0; i < (mclient >> 1); i++) {
	      if(!dos) usleep(SLEEP_INTERVAL);
	      if (start_client(remote_address, port, ifname, local_address,
			       messagenumber, i << 1) < 0) {
	    	  exit(-1);
	      }
	      tot_clients+=2;
	    }
	  else 
	    for (i = 0; i < mclient; i++) {
	      if(!dos) usleep(SLEEP_INTERVAL);
	      if (start_client(remote_address, port, ifname, local_address,
			       messagenumber, i) < 0) {
	    	  exit(-1);
	      }
	      tot_clients++;
	    }
	}

	if(dos)
		_exit(0);

	total_clients = tot_clients;

	__turn_getMSTime();

	struct event *ev = event_new(client_event_base, -1, EV_TIMEOUT|EV_PERSIST, timer_handler, NULL);
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	evtimer_add(ev,&tv);

	for(i=0;i<total_clients;i++) {

		if(is_TCP_relay()) {
			if(passive_tcp) {
				if(elems[i]->pinfo.is_peer) {
					int connect_err = 0;
					socket_connect(elems[i]->pinfo.fd, &(elems[i]->pinfo.remote_addr), &connect_err);
				}
			} else {
				int j = 0;
				for(j=i+1;j<total_clients;j++) {
					if (turn_tcp_connect(clnet_verbose, &(elems[i]->pinfo), &(elems[j]->pinfo.relay_addr)) < 0) {
						exit(-1);
					}
				}
			}
		}
		run_events(1);
	}

	__turn_getMSTime();

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total connect time is %u\n",
			((unsigned int) (current_time - stime)));

	stime = current_time;

	if(is_TCP_relay()) {
		u64bits connect_wait_start_time = current_time;
		while(1) {
			int i = 0;
			int completed = 0;
			if(passive_tcp) {
				for(i=0;i<total_clients;++i) {
					if(elems[i]->pinfo.is_peer) {
						completed+=1;
					} else if(elems[i]->pinfo.tcp_conn_number>0 &&
							elems[i]->pinfo.tcp_conn[0]->tcp_data_bound) {
						completed += elems[i]->pinfo.tcp_conn_number;
					}
				}
				if(completed >= total_clients)
					break;
			} else {
				for(i=0;i<total_clients;++i) {
					int j = 0;
					for(j=0;j<(int)elems[i]->pinfo.tcp_conn_number;j++) {
						if(elems[i]->pinfo.tcp_conn[j]->tcp_data_bound) {
							completed++;
						}
					}
				}
				if(completed >= total_clients*(total_clients-1)) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%d connections are completed\n",(int)(completed));
					break;
				}
			}
			run_events(0);
			if(current_time > connect_wait_start_time + STARTING_TCP_RELAY_TIME + total_clients) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: %d connections are completed, not enough\n",
						(int)(completed));
				break;
			}
		}
	}

	__turn_getMSTime();
	stime = current_time;

	for(i=0;i<total_clients;i++) {
		elems[i]->to_send_timems = current_mstime + 1000 + ((u32bits)random())%5000;
	}

	tot_messages = elems[0]->tot_msgnum * total_clients;

	start_full_timer = 1;

	while (1) {

		run_events(1);

		int msz = (int)current_clients_number;
		if (msz < 1) {
			break;
		}

		if(show_statistics) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				      "%s: msz=%d, tot_send_msgs=%lu, tot_recv_msgs=%lu, tot_send_bytes ~ %llu, tot_recv_bytes ~ %llu\n",
				      __FUNCTION__, msz, (unsigned long) tot_send_messages,
				      (unsigned long) tot_recv_messages, 
				      (unsigned long long) tot_send_bytes,
				      (unsigned long long) tot_recv_bytes);
			show_statistics=0;
		}
	}

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
		      "%s: tot_send_msgs=%lu, tot_recv_msgs=%lu\n",
		      __FUNCTION__,
		      (unsigned long) tot_send_messages,
		      (unsigned long) tot_recv_messages);

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
		      "%s: tot_send_bytes ~ %lu, tot_recv_bytes ~ %lu\n",
		      __FUNCTION__,
		      (unsigned long) tot_send_bytes,
		      (unsigned long) tot_recv_bytes);

	if (client_event_base)
		event_base_free(client_event_base);

	if(tot_send_messages<tot_recv_messages)
		tot_recv_messages=tot_send_messages;

	total_loss = tot_send_messages-tot_recv_messages;

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total transmit time is %u\n",
			((unsigned int)(current_time - stime)));
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total lost packets %llu (%f%c), total send dropped %llu (%f%c)\n",
				(unsigned long long)total_loss, (((double)total_loss/(double)tot_send_messages)*100.00),'%',
				(unsigned long long)tot_send_dropped, (((double)tot_send_dropped/(double)(tot_send_messages+tot_send_dropped))*100.00),'%');
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Average round trip delay %f ms; min = %lu ms, max = %lu ms\n",
				((double)total_latency/(double)((tot_recv_messages<1) ? 1 : tot_recv_messages)),
				(unsigned long)min_latency,
				(unsigned long)max_latency);
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Average jitter %f ms; min = %lu ms, max = %lu ms\n",
				((double)total_jitter/(double)tot_recv_messages),
				(unsigned long)min_jitter,
				(unsigned long)max_jitter);

	turn_free(elems,0);
}

///////////////////////////////////////////

turn_credential_type get_turn_credentials_type(void)
{
	return TURN_CREDENTIALS_LONG_TERM;
}

int add_integrity(app_ur_conn_info *clnet_info, stun_buffer *message)
{
	if(clnet_info->nonce[0]) {

		if(oauth && clnet_info->oauth) {

			u16bits method = stun_get_method_str(message->buf, message->len);

			int cok = clnet_info->cok;

			if(((method == STUN_METHOD_ALLOCATE) || (method == STUN_METHOD_REFRESH)) || !(clnet_info->key_set))
			{

				cok=((unsigned short)random())%3;
				clnet_info->cok = cok;
				oauth_token otoken;
				encoded_oauth_token etoken;
				u08bits nonce[12];
				RAND_bytes((unsigned char*)nonce,12);
				long halflifetime = OAUTH_SESSION_LIFETIME/2;
				long random_lifetime = 0;
				while(!random_lifetime) {
					random_lifetime = random();
				}
				if(random_lifetime<0) random_lifetime=-random_lifetime;
				random_lifetime = random_lifetime % halflifetime;
				otoken.enc_block.lifetime =  (uint32_t)(halflifetime + random_lifetime);
				otoken.enc_block.timestamp = ((uint64_t)turn_time()) << 16;
				if(shatype == SHATYPE_SHA256) {
					otoken.enc_block.key_length = 32;
				} else if(shatype == SHATYPE_SHA384) {
					otoken.enc_block.key_length = 48;
				} else if(shatype == SHATYPE_SHA512) {
					otoken.enc_block.key_length = 64;
				} else {
					otoken.enc_block.key_length = 20;
				}
				RAND_bytes((unsigned char *)(otoken.enc_block.mac_key), otoken.enc_block.key_length);
				if(encode_oauth_token(clnet_info->server_name, &etoken, &(okey_array[cok]), &otoken, nonce)<0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO," Cannot encode token\n");
					return -1;
				}
				stun_attr_add_str(message->buf, (size_t*)&(message->len), STUN_ATTRIBUTE_OAUTH_ACCESS_TOKEN,
					(const u08bits*)etoken.token, (int)etoken.size);

				ns_bcopy(otoken.enc_block.mac_key,clnet_info->key,otoken.enc_block.key_length);
				clnet_info->key_set = 1;
			}

			if(stun_attr_add_integrity_by_key_str(message->buf, (size_t*)&(message->len), (u08bits*)okey_array[cok].kid,
					clnet_info->realm, clnet_info->key, clnet_info->nonce, shatype)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO," Cannot add integrity to the message\n");
				return -1;
			}

			//self-test:
			{
				password_t pwd;
				if(stun_check_message_integrity_by_key_str(get_turn_credentials_type(),
								message->buf, (size_t)(message->len), clnet_info->key, pwd, shatype)<1) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR," Self-test of integrity does not comple correctly !\n");
					return -1;
				}
			}
		} else {
			if(stun_attr_add_integrity_by_user_str(message->buf, (size_t*)&(message->len), g_uname,
					clnet_info->realm, g_upwd, clnet_info->nonce, shatype)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO," Cannot add integrity to the message\n");
				return -1;
			}
		}
	}

	return 0;
}

int check_integrity(app_ur_conn_info *clnet_info, stun_buffer *message)
{
	SHATYPE sht = shatype;

	if(oauth && clnet_info->oauth) {

		password_t pwd;

		return stun_check_message_integrity_by_key_str(get_turn_credentials_type(),
				message->buf, (size_t)(message->len), clnet_info->key, pwd, sht);

	} else {

		if(stun_check_message_integrity_str(get_turn_credentials_type(),
			message->buf, (size_t)(message->len), g_uname,
			clnet_info->realm, g_upwd, sht)<1) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Wrong integrity in a message received from server\n");
			return -1;
		}
	}

	return 0;
}

SOCKET_TYPE get_socket_type()
{
	if(use_sctp) {
		if(use_secure) {
			return TLS_SCTP_SOCKET;
		} else {
			return SCTP_SOCKET;
		}
	} else if(use_tcp) {
		if(use_secure) {
			return TLS_SOCKET;
		} else {
			return TCP_SOCKET;
		}
	} else {
		if(use_secure) {
			return DTLS_SOCKET;
		} else {
			return UDP_SOCKET;
		}
	}
}
///////////////////////////////////////////

