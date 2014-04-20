/*
 * libtelnet - TELNET protocol handling library
 *
 * Sean Middleditch
 * sean@sourcemud.org
 *
 * The author or authors of this code dedicate any and all copyright interest
 * in this code to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and successors. We
 * intend this dedication to be an overt act of relinquishment in perpetuity of
 * all present and future rights to this code under copyright law.
 */

/**
 * Minor fixes by Oleg Moskalenko
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

/* Win32 compatibility */
#if defined(_WIN32)
# define vsnprintf _vsnprintf
# define __func__ __FUNCTION__
# define ZLIB_WINAPI 1
#endif

#if defined(HAVE_ZLIB)
# include <zlib.h>
#endif

#include "libtelnet.h"

/* inlinable functions */
#if defined(__GNUC__) || __STDC_VERSION__ >= 199901L
# define INLINE __inline__
#else
# define INLINE
#endif

/* helper for Q-method option tracking */
#define Q_US(q) ((q).state & 0x0F)
#define Q_HIM(q) (((q).state & 0xF0) >> 4)
#define Q_MAKE(us,him) ((us) | ((him) << 4))

/* helper for the negotiation routines */
#define NEGOTIATE_EVENT(telnet,cmd,opt) \
	ev.type = (cmd); \
	ev.neg.telopt = (opt); \
	(telnet)->eh((telnet), &ev, (telnet)->ud);

/* telnet state codes */
enum telnet_state_t {
	TELNET_STATE_DATA = 0,
	TELNET_STATE_IAC,
	TELNET_STATE_WILL,
	TELNET_STATE_WONT,
	TELNET_STATE_DO,
	TELNET_STATE_DONT,
	TELNET_STATE_SB,
	TELNET_STATE_SB_DATA,
	TELNET_STATE_SB_DATA_IAC
};
typedef enum telnet_state_t telnet_state_t;

/* telnet state tracker */
struct telnet_t {
	/* user data */
	void *ud;
	/* telopt support table */
	const telnet_telopt_t *telopts;
	/* event handler */
	telnet_event_handler_t eh;
#if defined(HAVE_ZLIB)
	/* zlib (mccp2) compression */
	z_stream *z;
#endif
	/* RFC1143 option negotiation states */
	struct telnet_rfc1143_t *q;
	/* sub-request buffer */
	char *buffer;
	/* current size of the buffer */
	size_t buffer_size;
	/* current buffer write position (also length of buffer data) */
	size_t buffer_pos;
	/* current state */
	enum telnet_state_t state;
	/* option flags */
	unsigned char flags;
	/* current subnegotiation telopt */
	unsigned char sb_telopt;
	/* length of RFC1143 queue */
	unsigned char q_size;
};

/* RFC1143 option negotiation state */
typedef struct telnet_rfc1143_t {
	unsigned char telopt;
	unsigned char state;
} telnet_rfc1143_t;

/* RFC1143 state names */
#define Q_NO 0
#define Q_YES 1
#define Q_WANTNO 2
#define Q_WANTYES 3
#define Q_WANTNO_OP 4
#define Q_WANTYES_OP 5

/* buffer sizes */
static const size_t _buffer_sizes[] = { 0, 512, 2048, 8192, 16384, };
static const size_t _buffer_sizes_count = sizeof(_buffer_sizes) /
		sizeof(_buffer_sizes[0]);

/* error generation function */
static telnet_error_t _error(telnet_t *telnet, unsigned line,
		const char* func, telnet_error_t err, int fatal, const char *fmt,
		...) {
	telnet_event_t ev;
	char buffer[512];
	va_list va;

	/* format informational text */
	va_start(va, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, va);
	va_end(va);

	/* send error event to the user */
	ev.type = fatal ? TELNET_EV_ERROR : TELNET_EV_WARNING;
	ev.error.file = __FILE__;
	ev.error.func = func;
	ev.error.line = line;
	ev.error.msg = buffer;
	telnet->eh(telnet, &ev, telnet->ud);
	
	return err;
}

#if defined(HAVE_ZLIB)
/* initialize the zlib box for a telnet box; if deflate is non-zero, it
 * initializes zlib for delating (compression), otherwise for inflating
 * (decompression).  returns TELNET_EOK on success, something else on
 * failure.
 */
telnet_error_t _init_zlib(telnet_t *telnet, int deflate, int err_fatal) {
	z_stream *z;
	int rs;

	/* if compression is already enabled, fail loudly */
	if (telnet->z != 0)
		return _error(telnet, __LINE__, __func__, TELNET_EBADVAL,
				err_fatal, "cannot initialize compression twice");

	/* allocate zstream box */
	if ((z= (z_stream *)calloc(1, sizeof(z_stream))) == 0)
		return _error(telnet, __LINE__, __func__, TELNET_ENOMEM, err_fatal,
				"malloc() failed: %s", strerror(errno));

	/* initialize */
	if (deflate) {
		if ((rs = deflateInit(z, Z_DEFAULT_COMPRESSION)) != Z_OK) {
			free(z);
			return _error(telnet, __LINE__, __func__, TELNET_ECOMPRESS,
					err_fatal, "deflateInit() failed: %s", zError(rs));
		}
		telnet->flags |= TELNET_PFLAG_DEFLATE;
	} else {
		if ((rs = inflateInit(z)) != Z_OK) {
			free(z);
			return _error(telnet, __LINE__, __func__, TELNET_ECOMPRESS,
					err_fatal, "inflateInit() failed: %s", zError(rs));
		}
		telnet->flags &= ~TELNET_PFLAG_DEFLATE;
	}

	telnet->z = z;

	return TELNET_EOK;
}
#endif /* defined(HAVE_ZLIB) */

/* push bytes out, compressing them first if need be */
static void _send(telnet_t *telnet, const char *buffer,
		size_t size) {
	telnet_event_t ev;

#if defined(HAVE_ZLIB)
	/* if we have a deflate (compression) zlib box, use it */
	if (telnet->z != 0 && telnet->flags & TELNET_PFLAG_DEFLATE) {
		char deflate_buffer[1024];
		int rs;

		/* initialize z state */
		telnet->z->next_in = (unsigned char *)buffer;
		telnet->z->avail_in = size;
		telnet->z->next_out = (unsigned char *)deflate_buffer;
		telnet->z->avail_out = sizeof(deflate_buffer);

		/* deflate until buffer exhausted and all output is produced */
		while (telnet->z->avail_in > 0 || telnet->z->avail_out == 0) {
			/* compress */
			if ((rs = deflate(telnet->z, Z_SYNC_FLUSH)) != Z_OK) {
				_error(telnet, __LINE__, __func__, TELNET_ECOMPRESS, 1,
						"deflate() failed: %s", zError(rs));
				deflateEnd(telnet->z);
				free(telnet->z);
				telnet->z = 0;
				break;
			}

			/* send event */
			ev.type = TELNET_EV_SEND;
			ev.data.buffer = deflate_buffer;
			ev.data.size = sizeof(deflate_buffer) - telnet->z->avail_out;
			telnet->eh(telnet, &ev, telnet->ud);

			/* prepare output buffer for next run */
			telnet->z->next_out = (unsigned char *)deflate_buffer;
			telnet->z->avail_out = sizeof(deflate_buffer);
		}

		/* do not continue with remaining code */
		return;
	}
#endif /* defined(HAVE_ZLIB) */

	ev.type = TELNET_EV_SEND;
	ev.data.buffer = buffer;
	ev.data.size = size;
	telnet->eh(telnet, &ev, telnet->ud);
}

/* to send bags of unsigned chars */
#define _sendu(t, d, s) _send((t), (const char*)(d), (s))

/* check if we support a particular telopt; if us is non-zero, we
 * check if we (local) supports it, otherwise we check if he (remote)
 * supports it.  return non-zero if supported, zero if not supported.
 */
static INLINE int _check_telopt(telnet_t *telnet, unsigned char telopt,
		int us) {
	int i;

	/* if we have no telopts table, we obviously don't support it */
	if (telnet->telopts == 0)
		return 0;

	/* loop unti found or end marker (us and him both 0) */
	for (i = 0; telnet->telopts[i].telopt != -1; ++i) {
		if (telnet->telopts[i].telopt == telopt) {
			if (us && telnet->telopts[i].us == TELNET_WILL)
				return 1;
			else if (!us && telnet->telopts[i].him == TELNET_DO)
				return 1;
			else
				return 0;
		}
	}

	/* not found, so not supported */
	return 0;
}

/* retrieve RFC1143 option state */
static INLINE telnet_rfc1143_t _get_rfc1143(telnet_t *telnet,
		unsigned char telopt) {
	telnet_rfc1143_t empty;
	int i;

	/* search for entry */
	for (i = 0; i != telnet->q_size; ++i) {
		if (telnet->q[i].telopt == telopt) {
			return telnet->q[i];
		}
	}

	/* not found, return empty value */
 	empty.telopt = telopt;
	empty.state = 0;
	return empty;
}

/* save RFC1143 option state */
static INLINE void _set_rfc1143(telnet_t *telnet, unsigned char telopt,
		char us, char him) {
	telnet_rfc1143_t *qtmp;
	int i;

	/* search for entry */
	for (i = 0; i != telnet->q_size; ++i) {
		if (telnet->q[i].telopt == telopt) {
			telnet->q[i].state = Q_MAKE(us,him);
			return;
		}
	}

	/* we're going to need to track state for it, so grow the queue
	 * by 4 (four) elements and put the telopt into it; bail on allocation
	 * error.  we go by four because it seems like a reasonable guess as
	 * to the number of enabled options for most simple code, and it
	 * allows for an acceptable number of reallocations for complex code.
	 */
	if ((qtmp = (telnet_rfc1143_t *)realloc(telnet->q,
			sizeof(telnet_rfc1143_t) * (telnet->q_size + 4))) == 0) {
		_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
				"realloc() failed: %s", strerror(errno));
		return;
	}
	memset(&qtmp[telnet->q_size], 0, sizeof(telnet_rfc1143_t) * 4);
	telnet->q = qtmp;
	telnet->q[telnet->q_size].telopt = telopt;
	telnet->q[telnet->q_size].state = Q_MAKE(us, him);
	telnet->q_size += 4;
}

/* send negotiation bytes */
static INLINE void _send_negotiate(telnet_t *telnet, unsigned char cmd,
		unsigned char telopt) {
	unsigned char bytes[3];
	bytes[0] = TELNET_IAC;
	bytes[1] = cmd;
	bytes[2] = telopt;
	_sendu(telnet, bytes, 3);
}

/* negotiation handling magic for RFC1143 */
static void _negotiate(telnet_t *telnet, unsigned char telopt) {
	telnet_event_t ev;
	telnet_rfc1143_t q;

	/* in PROXY mode, just pass it thru and do nothing */
	if (telnet->flags & TELNET_FLAG_PROXY) {
		switch ((int)telnet->state) {
		case TELNET_STATE_WILL:
			NEGOTIATE_EVENT(telnet, TELNET_EV_WILL, telopt);
			break;
		case TELNET_STATE_WONT:
			NEGOTIATE_EVENT(telnet, TELNET_EV_WONT, telopt);
			break;
		case TELNET_STATE_DO:
			NEGOTIATE_EVENT(telnet, TELNET_EV_DO, telopt);
			break;
		case TELNET_STATE_DONT:
			NEGOTIATE_EVENT(telnet, TELNET_EV_DONT, telopt);
			break;
		}
		return;
	}

	/* lookup the current state of the option */
	q = _get_rfc1143(telnet, telopt);

	/* start processing... */
	switch ((int)telnet->state) {
	/* request to enable option on remote end or confirm DO */
	case TELNET_STATE_WILL:
		switch (Q_HIM(q)) {
		case Q_NO:
			if (_check_telopt(telnet, telopt, 0)) {
				_set_rfc1143(telnet, telopt, Q_US(q), Q_YES);
				_send_negotiate(telnet, TELNET_DO, telopt);
				NEGOTIATE_EVENT(telnet, TELNET_EV_WILL, telopt);
			} else
				_send_negotiate(telnet, TELNET_DONT, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_NO);
			NEGOTIATE_EVENT(telnet, TELNET_EV_WONT, telopt);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"DONT answered by WILL");
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_YES);
			NEGOTIATE_EVENT(telnet, TELNET_EV_WILL, telopt);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"DONT answered by WILL");
			break;
		case Q_WANTYES:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_YES);
			NEGOTIATE_EVENT(telnet, TELNET_EV_WILL, telopt);
			break;
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_WANTNO);
			_send_negotiate(telnet, TELNET_DONT, telopt);
			NEGOTIATE_EVENT(telnet, TELNET_EV_WILL, telopt);
			break;
		}
		break;

	/* request to disable option on remote end, confirm DONT, reject DO */
	case TELNET_STATE_WONT:
		switch (Q_HIM(q)) {
		case Q_YES:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_NO);
			_send_negotiate(telnet, TELNET_DONT, telopt);
			NEGOTIATE_EVENT(telnet, TELNET_EV_WONT, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_NO);
			NEGOTIATE_EVENT(telnet, TELNET_EV_WONT, telopt);
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_WANTYES);
			NEGOTIATE_EVENT(telnet, TELNET_EV_DO, telopt);
			break;
		case Q_WANTYES:
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_NO);
			break;
		}
		break;

	/* request to enable option on local end or confirm WILL */
	case TELNET_STATE_DO:
		switch (Q_US(q)) {
		case Q_NO:
			if (_check_telopt(telnet, telopt, 1)) {
				_set_rfc1143(telnet, telopt, Q_YES, Q_HIM(q));
				_send_negotiate(telnet, TELNET_WILL, telopt);
				NEGOTIATE_EVENT(telnet, TELNET_EV_DO, telopt);
			} else
				_send_negotiate(telnet, TELNET_WONT, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, Q_NO, Q_HIM(q));
			NEGOTIATE_EVENT(telnet, TELNET_EV_DONT, telopt);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"WONT answered by DO");
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, Q_YES, Q_HIM(q));
			NEGOTIATE_EVENT(telnet, TELNET_EV_DO, telopt);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"WONT answered by DO");
			break;
		case Q_WANTYES:
			_set_rfc1143(telnet, telopt, Q_YES, Q_HIM(q));
			NEGOTIATE_EVENT(telnet, TELNET_EV_DO, telopt);
			break;
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, Q_WANTNO, Q_HIM(q));
			_send_negotiate(telnet, TELNET_WONT, telopt);
			NEGOTIATE_EVENT(telnet, TELNET_EV_DO, telopt);
			break;
		}
		break;

	/* request to disable option on local end, confirm WONT, reject WILL */
	case TELNET_STATE_DONT:
		switch (Q_US(q)) {
		case Q_YES:
			_set_rfc1143(telnet, telopt, Q_NO, Q_HIM(q));
			_send_negotiate(telnet, TELNET_WONT, telopt);
			NEGOTIATE_EVENT(telnet, TELNET_EV_DONT, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, Q_NO, Q_HIM(q));
			NEGOTIATE_EVENT(telnet, TELNET_EV_WONT, telopt);
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, Q_WANTYES, Q_HIM(q));
			_send_negotiate(telnet, TELNET_WILL, telopt);
			NEGOTIATE_EVENT(telnet, TELNET_EV_WILL, telopt);
			break;
		case Q_WANTYES:
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, Q_NO, Q_HIM(q));
			break;
		}
		break;
	}
}

/* process an ENVIRON/NEW-ENVIRON subnegotiation buffer
 *
 * the algorithm and approach used here is kind of a hack,
 * but it reduces the number of memory allocations we have
 * to make.
 *
 * we copy the bytes back into the buffer, starting at the very
 * beginning, which makes it easy to handle the ENVIRON ESC
 * escape mechanism as well as ensure the variable name and
 * value strings are NUL-terminated, all while fitting inside
 * of the original buffer.
 */
static int _environ_telnet(telnet_t *telnet, unsigned char type,
		char* buffer, size_t size) {
	telnet_event_t ev;
	struct telnet_environ_t *values = 0;
	char *c, *last, *out;
	size_t index, count;

	/* if we have no data, just pass it through */
	if (size == 0) {
		return 0;
	}

	/* first byte must be a valid command */
	if ((unsigned)buffer[0] != TELNET_ENVIRON_SEND &&
			(unsigned)buffer[0] != TELNET_ENVIRON_IS && 
			(unsigned)buffer[0] != TELNET_ENVIRON_INFO) {
		_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
				"telopt %d subneg has invalid command", type);
		return 0;
	}

	/* store ENVIRON command */
	ev.environ.cmd = buffer[0];

	/* if we have no arguments, send an event with no data end return */
	if (size == 1) {
		/* no list of variables given */
		ev.environ.values = 0;
		ev.environ.size = 0;

		/* invoke event with our arguments */
		ev.type = TELNET_EV_ENVIRON;
		telnet->eh(telnet, &ev, telnet->ud);

		return 1;
	}

	/* very second byte must be VAR or USERVAR, if present */
	if ((unsigned)buffer[1] != TELNET_ENVIRON_VAR &&
			(unsigned)buffer[1] != TELNET_ENVIRON_USERVAR) {
		_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
				"telopt %d subneg missing variable type", type);
		return 0;
	}

	/* ensure last byte is not an escape byte (makes parsing later easier) */
	if ((unsigned)buffer[size - 1] == TELNET_ENVIRON_ESC) {
		_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
				"telopt %d subneg ends with ESC", type);
		return 0;
	}

	/* count arguments; each valid entry starts with VAR or USERVAR */
	count = 0;
	for (c = buffer + 1; c < buffer + size; ++c) {
		if (*c == TELNET_ENVIRON_VAR || *c == TELNET_ENVIRON_USERVAR) {
			++count;
		} else if (*c == TELNET_ENVIRON_ESC) {
			/* skip the next byte */
			++c;
		}
	}

	/* allocate argument array, bail on error */
	if ((values = (struct telnet_environ_t *)calloc(count,
			sizeof(struct telnet_environ_t))) == 0) {
		_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
				"calloc() failed: %s", strerror(errno));
		return 0;
	}

	/* parse argument array strings */
	out = buffer;
	c = buffer + 1;
	for (index = 0; index != count; ++index) {
		/* remember the variable type (will be VAR or USERVAR) */
		values[index].type = *c++;

		/* scan until we find an end-marker, and buffer up unescaped
		 * bytes into our buffer */
		last = out;
		while (c < buffer + size) {
			/* stop at the next variable or at the value */
			if ((unsigned)*c == TELNET_ENVIRON_VAR ||
					(unsigned)*c == TELNET_ENVIRON_VALUE ||
					(unsigned)*c == TELNET_ENVIRON_USERVAR) {
				break;
			}

			/* buffer next byte (taking into account ESC) */
			if (*c == TELNET_ENVIRON_ESC) {
				++c;
			}

			*out++ = *c++;
		}
		*out++ = '\0';

		/* store the variable name we have just received */
		values[index].var = last;
		values[index].value = "";

		/* if we got a value, find the next end marker and
		 * store the value; otherwise, store empty string */
		if (c < buffer + size && *c == TELNET_ENVIRON_VALUE) {
			++c;
			last = out;
			while (c < buffer + size) {
				/* stop when we find the start of the next variable */
				if ((unsigned)*c == TELNET_ENVIRON_VAR ||
						(unsigned)*c == TELNET_ENVIRON_USERVAR) {
					break;
				}

				/* buffer next byte (taking into account ESC) */
				if (*c == TELNET_ENVIRON_ESC) {
					++c;
				}

				*out++ = *c++;
			}
			*out++ = '\0';

			/* store the variable value */
			values[index].value = last;
		}
	}

	/* pass values array and count to event */
	ev.environ.values = values;
	ev.environ.size = count;

	/* invoke event with our arguments */
	ev.type = TELNET_EV_ENVIRON;
	telnet->eh(telnet, &ev, telnet->ud);

	/* clean up */
	free(values);
	return 1;
}

/* process an MSSP subnegotiation buffer */
static int _mssp_telnet(telnet_t *telnet, char* buffer, size_t size) {
	telnet_event_t ev;
	struct telnet_environ_t *values;
	char *var = 0;
	char *c, *last, *out;
	size_t i, count;
	unsigned char next_type;

	/* if we have no data, just pass it through */
	if (size == 0) {
		return 0;
	}

	/* first byte must be a VAR */
	if ((unsigned)buffer[0] != TELNET_MSSP_VAR) {
		_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
				"MSSP subnegotiation has invalid data");
		return 0;
	}

	/* count the arguments, any part that starts with VALUE */
	for (count = 0, i = 0; i != size; ++i) {
		if ((unsigned)buffer[i] == TELNET_MSSP_VAL) {
			++count;
		}
	}

	/* allocate argument array, bail on error */
	if ((values = (struct telnet_environ_t *)calloc(count,
			sizeof(struct telnet_environ_t))) == 0) {
		_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
				"calloc() failed: %s", strerror(errno));
		return 0;
	}

	ev.mssp.values = values;
	ev.mssp.size = count;

	/* allocate strings in argument array */
	out = last = buffer;
	next_type = buffer[0];
	for (i = 0, c = buffer + 1; c < buffer + size;) {
		/* search for end marker */
		while (c < buffer + size && (unsigned)*c != TELNET_MSSP_VAR &&
				(unsigned)*c != TELNET_MSSP_VAL) {
			*out++ = *c++;
		}
		*out++ = '\0';

		/* if it's a variable name, just store the name for now */
		if (next_type == TELNET_MSSP_VAR) {
			var = last;
		} else if (next_type == TELNET_MSSP_VAL && var != 0) {
			values[i].var = var;
			values[i].value = last;
			++i;
		} else {
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"invalid MSSP subnegotiation data");
			free(values);
			return 0;
		}

		/* remember our next type and increment c for next loop run */
		last = out;
		next_type = *c++;
	}

	/* invoke event with our arguments */
	ev.type = TELNET_EV_MSSP;
	telnet->eh(telnet, &ev, telnet->ud);

	/* clean up */
	free(values);

	return 0;
}

/* parse ZMP command subnegotiation buffers */
static int _zmp_telnet(telnet_t *telnet, const char* buffer, size_t size) {
	telnet_event_t ev;
	const char **argv;
	const char *c;
	size_t i, argc;

	/* make sure this is a valid ZMP buffer */
	if (size == 0 || buffer[size - 1] != 0) {
		_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
				"incomplete ZMP frame");
		return 0;
	}

	/* count arguments */
	for (argc = 0, c = buffer; c != buffer + size; ++argc)
		c += strlen(c) + 1;

	/* allocate argument array, bail on error */
	if ((argv = (const char **)calloc(argc, sizeof(char *))) == 0) {
		_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
				"calloc() failed: %s", strerror(errno));
		return 0;
	}

	/* populate argument array */
	for (i = 0, c = buffer; i != argc; ++i) {
		argv[i] = c;
		c += strlen(c) + 1;
	}

	/* invoke event with our arguments */
	ev.type = TELNET_EV_ZMP;
	ev.zmp.argv = argv;
	ev.zmp.argc = argc;
	telnet->eh(telnet, &ev, telnet->ud);

	/* clean up */
	free(argv);
	return 0;
}

/* parse TERMINAL-TYPE command subnegotiation buffers */
static int _ttype_telnet(telnet_t *telnet, const char* buffer, size_t size) {
	telnet_event_t ev;

	/* make sure request is not empty */
	if (size == 0) {
		_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
				"incomplete TERMINAL-TYPE request");
		return 0;
	}

	/* make sure request has valid command type */
	if (buffer[0] != TELNET_TTYPE_IS &&
			buffer[0] != TELNET_TTYPE_SEND) {
		_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
				"TERMINAL-TYPE request has invalid type");
		return 0;
	}

	/* send proper event */
	if (buffer[0] == TELNET_TTYPE_IS) {
		char *name;

		/* allocate space for name */
		if ((name = (char *)malloc(size)) == 0) {
			_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
					"malloc() failed: %s", strerror(errno));
			return 0;
		}
		memcpy(name, buffer + 1, size - 1);
		name[size - 1] = '\0';

		ev.type = TELNET_EV_TTYPE;
		ev.ttype.cmd = TELNET_TTYPE_IS;
		ev.ttype.name = name;
		telnet->eh(telnet, &ev, telnet->ud);

		/* clean up */
		free(name);
	} else {
		ev.type = TELNET_EV_TTYPE;
		ev.ttype.cmd = TELNET_TTYPE_SEND;
		ev.ttype.name = 0;
		telnet->eh(telnet, &ev, telnet->ud);
	}

	return 0;
}

/* process a subnegotiation buffer; return non-zero if the current buffer
 * must be aborted and reprocessed due to COMPRESS2 being activated
 */
static int _subnegotiate(telnet_t *telnet) {
	telnet_event_t ev;

	/* standard subnegotiation event */
	ev.type = TELNET_EV_SUBNEGOTIATION;
	ev.sub.telopt = telnet->sb_telopt;
	ev.sub.buffer = telnet->buffer;
	ev.sub.size = telnet->buffer_pos;
	telnet->eh(telnet, &ev, telnet->ud);

	switch (telnet->sb_telopt) {
#if defined(HAVE_ZLIB)
	/* received COMPRESS2 begin marker, setup our zlib box and
	 * start handling the compressed stream if it's not already.
	 */
	case TELNET_TELOPT_COMPRESS2:
		if (telnet->sb_telopt == TELNET_TELOPT_COMPRESS2) {
			if (_init_zlib(telnet, 0, 1) != TELNET_EOK)
				return 0;

			/* notify app that compression was enabled */
			ev.type = TELNET_EV_COMPRESS;
			ev.compress.state = 1;
			telnet->eh(telnet, &ev, telnet->ud);
			return 1;
		}
		return 0;
#endif /* defined(HAVE_ZLIB) */

	/* specially handled subnegotiation telopt types */
	case TELNET_TELOPT_ZMP:
		return _zmp_telnet(telnet, telnet->buffer, telnet->buffer_pos);
	case TELNET_TELOPT_TTYPE:
		return _ttype_telnet(telnet, telnet->buffer, telnet->buffer_pos);
	case TELNET_TELOPT_ENVIRON:
	case TELNET_TELOPT_NEW_ENVIRON:
		return _environ_telnet(telnet, telnet->sb_telopt, telnet->buffer,
				telnet->buffer_pos);
	case TELNET_TELOPT_MSSP:
		return _mssp_telnet(telnet, telnet->buffer, telnet->buffer_pos);
	default:
		return 0;
	}
}

/* initialize a telnet state tracker */
telnet_t *telnet_init(const telnet_telopt_t *telopts,
		telnet_event_handler_t eh, unsigned char flags, void *user_data) {
	/* allocate structure */
	struct telnet_t *telnet = (telnet_t*)calloc(1, sizeof(telnet_t));
	if (telnet == 0)
		return 0;

	/* initialize data */
	telnet->ud = user_data;
	telnet->telopts = telopts;
	telnet->eh = eh;
	telnet->flags = flags;

	return telnet;
}

/* free up any memory allocated by a state tracker */
void telnet_free(telnet_t *telnet) {
	/* free sub-request buffer */
	if (telnet->buffer != 0) {
		free(telnet->buffer);
		telnet->buffer = 0;
		telnet->buffer_size = 0;
		telnet->buffer_pos = 0;
	}

#if defined(HAVE_ZLIB)
	/* free zlib box */
	if (telnet->z != 0) {
		if (telnet->flags & TELNET_PFLAG_DEFLATE)
			deflateEnd(telnet->z);
		else
			inflateEnd(telnet->z);
		free(telnet->z);
		telnet->z = 0;
	}
#endif /* defined(HAVE_ZLIB) */

	/* free RFC1143 queue */
	if (telnet->q) {
		free(telnet->q);
		telnet->q = 0;
		telnet->q_size = 0;
	}

	/* free the telnet structure itself */
	free(telnet);
}

/* push a byte into the telnet buffer */
static telnet_error_t _buffer_byte(telnet_t *telnet,
		unsigned char byte) {
	char *new_buffer;
	size_t i;

	/* check if we're out of room */
	if (telnet->buffer_pos == telnet->buffer_size) {
		/* find the next buffer size */
		for (i = 0; i != _buffer_sizes_count; ++i) {
			if (_buffer_sizes[i] == telnet->buffer_size) {
				break;
			}
		}

		/* overflow -- can't grow any more */
		if (i >= _buffer_sizes_count - 1) {
			_error(telnet, __LINE__, __func__, TELNET_EOVERFLOW, 0,
					"subnegotiation buffer size limit reached");
			return TELNET_EOVERFLOW;
		}

		/* (re)allocate buffer */
		new_buffer = (char *)realloc(telnet->buffer, _buffer_sizes[i + 1]);
		if (new_buffer == 0) {
			_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
					"realloc() failed");
			return TELNET_ENOMEM;
		}

		telnet->buffer = new_buffer;
		telnet->buffer_size = _buffer_sizes[i + 1];
	}

	/* push the byte, all set */
	telnet->buffer[telnet->buffer_pos++] = byte;
	return TELNET_EOK;
}

static void _process(telnet_t *telnet, const char *buffer, size_t size) {
	telnet_event_t ev;
	unsigned char byte;
	size_t i, start;
	for (i = start = 0; i != size; ++i) {
		byte = buffer[i];
		switch (telnet->state) {
		/* regular data */
		case TELNET_STATE_DATA:
			/* on an IAC byte, pass through all pending bytes and
			 * switch states */
			if (byte == TELNET_IAC) {
				if (i != start) {
					ev.type = TELNET_EV_DATA;
					ev.data.buffer = buffer + start;
					ev.data.size = i - start;
					telnet->eh(telnet, &ev, telnet->ud);
				}
				telnet->state = TELNET_STATE_IAC;
			}
			break;

		/* IAC command */
		case TELNET_STATE_IAC:
			switch (byte) {
			/* subnegotiation */
			case TELNET_SB:
				telnet->state = TELNET_STATE_SB;
				break;
			/* negotiation commands */
			case TELNET_WILL:
				telnet->state = TELNET_STATE_WILL;
				break;
			case TELNET_WONT:
				telnet->state = TELNET_STATE_WONT;
				break;
			case TELNET_DO:
				telnet->state = TELNET_STATE_DO;
				break;
			case TELNET_DONT:
				telnet->state = TELNET_STATE_DONT;
				break;
			/* IAC escaping */
			case TELNET_IAC:
				/* event */
				ev.type = TELNET_EV_DATA;
				ev.data.buffer = (char*)&byte;
				ev.data.size = 1;
				telnet->eh(telnet, &ev, telnet->ud);

				/* state update */
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;
				break;
			/* some other command */
			default:
				/* event */
				ev.type = TELNET_EV_IAC;
				ev.iac.cmd = byte;
				telnet->eh(telnet, &ev, telnet->ud);

				/* state update */
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;
			}
			break;

		/* negotiation commands */
		case TELNET_STATE_WILL:
		case TELNET_STATE_WONT:
		case TELNET_STATE_DO:
		case TELNET_STATE_DONT:
			_negotiate(telnet, byte);
			start = i + 1;
			telnet->state = TELNET_STATE_DATA;
			break;

		/* subnegotiation -- determine subnegotiation telopt */
		case TELNET_STATE_SB:
			telnet->sb_telopt = byte;
			telnet->buffer_pos = 0;
			telnet->state = TELNET_STATE_SB_DATA;
			break;

		/* subnegotiation -- buffer bytes until end request */
		case TELNET_STATE_SB_DATA:
			/* IAC command in subnegotiation -- either IAC SE or IAC IAC */
			if (byte == TELNET_IAC) {
				telnet->state = TELNET_STATE_SB_DATA_IAC;
			/* buffer the byte, or bail if we can't */
			} else if (_buffer_byte(telnet, byte) != TELNET_EOK) {
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;
			}
			break;

		/* IAC escaping inside a subnegotiation */
		case TELNET_STATE_SB_DATA_IAC:
			switch (byte) {
			/* end subnegotiation */
			case TELNET_SE:
				/* return to default state */
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;

				/* process subnegotiation */
				if (_subnegotiate(telnet) != 0) {
					/* any remaining bytes in the buffer are compressed.
					 * we have to re-invoke telnet_recv to get those
					 * bytes inflated and abort trying to process the
					 * remaining compressed bytes in the current _process
					 * buffer argument
					 */
					telnet_recv(telnet, &buffer[start], size - start);
					return;
				}
				break;
			/* escaped IAC byte */
			case TELNET_IAC:
				/* push IAC into buffer */
				if (_buffer_byte(telnet, TELNET_IAC) !=
						TELNET_EOK) {
					start = i + 1;
					telnet->state = TELNET_STATE_DATA;
				} else {
					telnet->state = TELNET_STATE_SB_DATA;
				}
				break;
			/* something else -- protocol error.  attempt to process
			 * content in subnegotiation buffer, then evaluate the
			 * given command as an IAC code.
			 */
			default:
				_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
						"unexpected byte after IAC inside SB: %d",
						byte);

				/* enter IAC state */
				start = i + 1;
				telnet->state = TELNET_STATE_IAC;

				/* process subnegotiation; see comment in
				 * TELNET_STATE_SB_DATA_IAC about invoking telnet_recv()
				 */
				if (_subnegotiate(telnet) != 0) {
					telnet_recv(telnet, &buffer[start], size - start);
					return;
				} else {
					/* recursive call to get the current input byte processed
					 * as a regular IAC command.  we could use a goto, but
					 * that would be gross.
					 */
					_process(telnet, (char *)&byte, 1);
				}
				break;
			}
			break;
		}
	}

	/* pass through any remaining bytes */ 
	if (telnet->state == TELNET_STATE_DATA && i != start) {
		ev.type = TELNET_EV_DATA;
		ev.data.buffer = buffer + start;
		ev.data.size = i - start;
		telnet->eh(telnet, &ev, telnet->ud);
	}
}

/* push a bytes into the state tracker */
void telnet_recv(telnet_t *telnet, const char *buffer,
		size_t size) {
#if defined(HAVE_ZLIB)
	/* if we have an inflate (decompression) zlib stream, use it */
	if (telnet->z != 0 && !(telnet->flags & TELNET_PFLAG_DEFLATE)) {
		char inflate_buffer[1024];
		int rs;

		/* initialize zlib state */
		telnet->z->next_in = (unsigned char*)buffer;
		telnet->z->avail_in = size;
		telnet->z->next_out = (unsigned char *)inflate_buffer;
		telnet->z->avail_out = sizeof(inflate_buffer);

		/* inflate until buffer exhausted and all output is produced */
		while (telnet->z->avail_in > 0 || telnet->z->avail_out == 0) {
			/* reset output buffer */

			/* decompress */
			rs = inflate(telnet->z, Z_SYNC_FLUSH);

			/* process the decompressed bytes on success */
			if (rs == Z_OK || rs == Z_STREAM_END)
				_process(telnet, inflate_buffer, sizeof(inflate_buffer) -
						telnet->z->avail_out);
			else
				_error(telnet, __LINE__, __func__, TELNET_ECOMPRESS, 1,
						"inflate() failed: %s", zError(rs));

			/* prepare output buffer for next run */
			telnet->z->next_out = (unsigned char *)inflate_buffer;
			telnet->z->avail_out = sizeof(inflate_buffer);

			/* on error (or on end of stream) disable further inflation */
			if (rs != Z_OK) {
				telnet_event_t ev;

				/* disable compression */
				inflateEnd(telnet->z);
				free(telnet->z);
				telnet->z = 0;

				/* send event */
				ev.type = TELNET_EV_COMPRESS;
				ev.compress.state = 0;
				telnet->eh(telnet, &ev, telnet->ud);

				break;
			}
		}

	/* COMPRESS2 is not negotiated, just process */
	} else
#endif /* defined(HAVE_ZLIB) */
		_process(telnet, buffer, size);
}

/* send an iac command */
void telnet_iac(telnet_t *telnet, unsigned char cmd) {
	unsigned char bytes[2];
	bytes[0] = TELNET_IAC;
	bytes[1] = cmd;
	_sendu(telnet, bytes, 2);
}

/* send negotiation */
void telnet_negotiate(telnet_t *telnet, unsigned char cmd,
		unsigned char telopt) {
	telnet_rfc1143_t q;

	/* if we're in proxy mode, just send it now */
	if (telnet->flags & TELNET_FLAG_PROXY) {
		unsigned char bytes[3];
		bytes[0] = TELNET_IAC;
		bytes[1] = cmd;
		bytes[2] = telopt;
		_sendu(telnet, bytes, 3);
		return;
	}
	
	/* get current option states */
	q = _get_rfc1143(telnet, telopt);

	switch (cmd) {
	/* advertise willingess to support an option */
	case TELNET_WILL:
		switch (Q_US(q)) {
		case Q_NO:
			_set_rfc1143(telnet, telopt, Q_WANTYES, Q_HIM(q));
			_send_negotiate(telnet, TELNET_WILL, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, Q_WANTNO_OP, Q_HIM(q));
			break;
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, Q_WANTYES, Q_HIM(q));
			break;
		}
		break;

	/* force turn-off of locally enabled option */
	case TELNET_WONT:
		switch (Q_US(q)) {
		case Q_YES:
			_set_rfc1143(telnet, telopt, Q_WANTNO, Q_HIM(q));
			_send_negotiate(telnet, TELNET_WONT, telopt);
			break;
		case Q_WANTYES:
			_set_rfc1143(telnet, telopt, Q_WANTYES_OP, Q_HIM(q));
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, Q_WANTNO, Q_HIM(q));
			break;
		}
		break;

	/* ask remote end to enable an option */
	case TELNET_DO:
		switch (Q_HIM(q)) {
		case Q_NO:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_WANTYES);
			_send_negotiate(telnet, TELNET_DO, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_WANTNO_OP);
			break;
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_WANTYES);
			break;
		}
		break;

	/* demand remote end disable an option */
	case TELNET_DONT:
		switch (Q_HIM(q)) {
		case Q_YES:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_WANTNO);
			_send_negotiate(telnet, TELNET_DONT, telopt);
			break;
		case Q_WANTYES:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_WANTYES_OP);
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, Q_US(q), Q_WANTNO);
			break;
		}
		break;
	}
}

/* send non-command data (escapes IAC bytes) */
void telnet_send(telnet_t *telnet, const char *buffer,
		size_t size) {
	size_t i, l;

	for (l = i = 0; i != size; ++i) {
		/* dump prior portion of text, send escaped bytes */
		if (buffer[i] == (char)TELNET_IAC) {
			/* dump prior text if any */
			if (i != l) {
				_send(telnet, buffer + l, i - l);
			}
			l = i + 1;

			/* send escape */
			telnet_iac(telnet, TELNET_IAC);
		}
	}

	/* send whatever portion of buffer is left */
	if (i != l) {
		_send(telnet, buffer + l, i - l);
	}
}

/* send subnegotiation header */
void telnet_begin_sb(telnet_t *telnet, unsigned char telopt) {
	unsigned char sb[3];
	sb[0] = TELNET_IAC;
	sb[1] = TELNET_SB;
	sb[2] = telopt;
	_sendu(telnet, sb, 3);
}


/* send complete subnegotiation */
void telnet_subnegotiation(telnet_t *telnet, unsigned char telopt,
		const char *buffer, size_t size) {
	unsigned char bytes[5];
	bytes[0] = TELNET_IAC;
	bytes[1] = TELNET_SB;
	bytes[2] = telopt;
	bytes[3] = TELNET_IAC;
	bytes[4] = TELNET_SE;

	_sendu(telnet, bytes, 3);
	telnet_send(telnet, buffer, size);
	_sendu(telnet, bytes + 3, 2);

#if defined(HAVE_ZLIB)
	/* if we're a proxy and we just sent the COMPRESS2 marker, we must
	 * make sure all further data is compressed if not already.
	 */
	if (telnet->flags & TELNET_FLAG_PROXY &&
			telopt == TELNET_TELOPT_COMPRESS2) {
		telnet_event_t ev;

		if (_init_zlib(telnet, 1, 1) != TELNET_EOK)
			return;

		/* notify app that compression was enabled */
		ev.type = TELNET_EV_COMPRESS;
		ev.compress.state = 1;
		telnet->eh(telnet, &ev, telnet->ud);
	}
#endif /* defined(HAVE_ZLIB) */
}

void telnet_begin_compress2(telnet_t *telnet) {
	UNUSED_ARG(telnet);
#if defined(HAVE_ZLIB)
	static const unsigned char compress2[] = { TELNET_IAC, TELNET_SB,
			TELNET_TELOPT_COMPRESS2, TELNET_IAC, TELNET_SE };

	telnet_event_t ev;

	/* attempt to create output stream first, bail if we can't */
	if (_init_zlib(telnet, 1, 0) != TELNET_EOK)
		return;

	/* send compression marker.  we send directly to the event handler
	 * instead of passing through _send because _send would result in
	 * the compress marker itself being compressed.
	 */
	ev.type = TELNET_EV_SEND;
	ev.data.buffer = (const char*)compress2;
	ev.data.size = sizeof(compress2);
	telnet->eh(telnet, &ev, telnet->ud);

	/* notify app that compression was successfully enabled */
	ev.type = TELNET_EV_COMPRESS;
	ev.compress.state = 1;
	telnet->eh(telnet, &ev, telnet->ud);
#endif /* defined(HAVE_ZLIB) */
}

/* send formatted data with \r and \n translation in addition to IAC IAC */
int telnet_vprintf(telnet_t *telnet, const char *fmt, va_list va) {
    static const char CRLF[] = { '\r', '\n' };
    static const char CRNUL[] = { '\r', '\0' };
	char buffer[1024];
	char *output = buffer;
	int rs, i, l;

	/* format */
	rs = vsnprintf(buffer, sizeof(buffer), fmt, va);
	if ((size_t)rs >= sizeof(buffer)) {
		output = (char*)malloc(rs + 1);
		if (output == 0) {
			_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
					"malloc() failed: %s", strerror(errno));
			return -1;
		}
		rs = vsnprintf(output, rs + 1, fmt, va);
	}

	/* send */
	for (l = i = 0; i != rs; ++i) {
		/* special characters */
		if (output[i] == (char)TELNET_IAC || output[i] == '\r' ||
				output[i] == '\n') {
			/* dump prior portion of text */
			if (i != l)
				_send(telnet, output + l, i - l);
			l = i + 1;

			/* IAC -> IAC IAC */
			if (output[i] == (char)TELNET_IAC)
				telnet_iac(telnet, TELNET_IAC);
			/* automatic translation of \r -> CRNUL */
			else if (output[i] == '\r')
				_send(telnet, CRNUL, 2);
			/* automatic translation of \n -> CRLF */
			else if (output[i] == '\n')
				_send(telnet, CRLF, 2);
		}
	}

	/* send whatever portion of output is left */
	if (i != l) {
		_send(telnet, output + l, i - l);
	}

	/* free allocated memory, if any */
	if (output != buffer) {
		free(output);
	}

	return rs;
}

/* see telnet_vprintf */
int telnet_printf(telnet_t *telnet, const char *fmt, ...) {
	va_list va;
	int rs;

	va_start(va, fmt);
	rs = telnet_vprintf(telnet, fmt, va);
	va_end(va);

	return rs;
}

/* send formatted data through telnet_send */
int telnet_raw_vprintf(telnet_t *telnet, const char *fmt, va_list va) {
	char buffer[1024];
	char *output = buffer;
	int rs;

	/* format; allocate more space if necessary */
	rs = vsnprintf(buffer, sizeof(buffer), fmt, va);
	if ((size_t)rs >= sizeof(buffer)) {
		output = (char*)malloc(rs + 1);
		if (output == 0) {
			_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
					"malloc() failed: %s", strerror(errno));
			return -1;
		}
		rs = vsnprintf(output, rs + 1, fmt, va);
	}

	/* send out the formatted data */
	telnet_send(telnet, output, rs);

	/* release allocated memory, if any */
	if (output != buffer) {
		free(output);
	}

	return rs;
}

/* see telnet_raw_vprintf */
int telnet_raw_printf(telnet_t *telnet, const char *fmt, ...) {
	va_list va;
	int rs;

	va_start(va, fmt);
	rs = telnet_raw_vprintf(telnet, fmt, va);
	va_end(va);

	return rs;
}

/* begin NEW-ENVIRON subnegotation */
void telnet_begin_newenviron(telnet_t *telnet, unsigned char cmd) {
	telnet_begin_sb(telnet, TELNET_TELOPT_NEW_ENVIRON);
	telnet_send(telnet, (char*)&cmd, 1);
}

/* send a NEW-ENVIRON value */
void telnet_newenviron_value(telnet_t *telnet, unsigned char type,
		const char *string) {
	telnet_send(telnet, (char*)&type, 1);

	if (string != 0) {
		telnet_send(telnet, string, strlen(string));
	}
}

/* send TERMINAL-TYPE SEND command */
void telnet_ttype_send(telnet_t *telnet) {
    static const unsigned char SEND[] = { TELNET_IAC, TELNET_SB,
			TELNET_TELOPT_TTYPE, TELNET_TTYPE_SEND, TELNET_IAC, TELNET_SE };
	_sendu(telnet, SEND, sizeof(SEND));
}

/* send TERMINAL-TYPE IS command */
void telnet_ttype_is(telnet_t *telnet, const char* ttype) {
	static const unsigned char IS[] = { TELNET_IAC, TELNET_SB,
			TELNET_TELOPT_TTYPE, TELNET_TTYPE_IS };
	_sendu(telnet, IS, sizeof(IS));
	_send(telnet, ttype, strlen(ttype));
	telnet_finish_sb(telnet);
}

/* send ZMP data */
void telnet_send_zmp(telnet_t *telnet, size_t argc, const char **argv) {
	size_t i;

	/* ZMP header */
	telnet_begin_zmp(telnet, argv[0]);

	/* send out each argument, including trailing NUL byte */
	for (i = 1; i != argc; ++i)
		telnet_zmp_arg(telnet, argv[i]);

	/* ZMP footer */
	telnet_finish_zmp(telnet);
}

/* send ZMP data using varargs  */
void telnet_send_vzmpv(telnet_t *telnet, va_list va) {
	const char* arg;

	/* ZMP header */
	telnet_begin_sb(telnet, TELNET_TELOPT_ZMP);

	/* send out each argument, including trailing NUL byte */
	while ((arg = va_arg(va, const char *)) != 0)
		telnet_zmp_arg(telnet, arg);

	/* ZMP footer */
	telnet_finish_zmp(telnet);
}

/* see telnet_send_vzmpv */
void telnet_send_zmpv(telnet_t *telnet, ...) {
	va_list va;

	va_start(va, telnet);
	telnet_send_vzmpv(telnet, va);
	va_end(va);
}

/* begin a ZMP command */
void telnet_begin_zmp(telnet_t *telnet, const char *cmd) {
	telnet_begin_sb(telnet, TELNET_TELOPT_ZMP);
	telnet_zmp_arg(telnet, cmd);
}

/* send a ZMP argument */
void telnet_zmp_arg(telnet_t *telnet, const char* arg) {
	telnet_send(telnet, arg, strlen(arg) + 1);
}
