/*!
 * \brief libtelnet - TELNET protocol handling library
 *
 * SUMMARY:
 *
 * libtelnet is a library for handling the TELNET protocol.  It includes
 * routines for parsing incoming data from a remote peer as well as formatting
 * data to send to the remote peer.
 *
 * libtelnet uses a callback-oriented API, allowing application-specific
 * handling of various events.  The callback system is also used for buffering
 * outgoing protocol data, allowing the application to maintain control over
 * the actual socket connection.
 *
 * Features supported include the full TELNET protocol, Q-method option
 * negotiation, ZMP, MCCP2, MSSP, and NEW-ENVIRON.
 *
 * CONFORMS TO:
 *
 * RFC854  - http://www.faqs.org/rfcs/rfc854.html
 * RFC855  - http://www.faqs.org/rfcs/rfc855.html
 * RFC1091 - http://www.faqs.org/rfcs/rfc1091.html
 * RFC1143 - http://www.faqs.org/rfcs/rfc1143.html
 * RFC1408 - http://www.faqs.org/rfcs/rfc1408.html
 * RFC1572 - http://www.faqs.org/rfcs/rfc1572.html
 *
 * LICENSE:
 *
 * The author or authors of this code dedicate any and all copyright interest
 * in this code to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and successors. We
 * intend this dedication to be an overt act of relinquishment in perpetuity of
 * all present and future rights to this code under copyright law.
 *
 * \file libtelnet.h
 *
 * \version 0.21
 *
 * \author Sean Middleditch <sean@sourcemud.org>
 */

/**
 * Minor fixes by Oleg Moskalenko
 */

#if !defined(LIBTELNET_INCLUDE)
#define LIBTELNET_INCLUDE 1

/* standard C headers necessary for the libtelnet API */
#include <stdarg.h>

/* C++ support */
#if defined(__cplusplus)
extern "C" {
#endif

/* printf type checking feature in GCC and some other compilers */
#if __GNUC__
# define TELNET_GNU_PRINTF(f,a) __attribute__((format(printf, f, a))) /*!< internal helper */
#else
# define TELNET_GNU_PRINTF(f,a) /*!< internal helper */
#endif

/*! Telnet state tracker object type. */
typedef struct telnet_t telnet_t;

/*! Telnet event object type. */
typedef union telnet_event_t telnet_event_t;

/*! Telnet option table element type. */
typedef struct telnet_telopt_t telnet_telopt_t;

/*! \name Telnet commands */
/*@{*/
/*! Telnet commands and special values. */
#define TELNET_IAC 255
#define TELNET_DONT 254
#define TELNET_DO 253
#define TELNET_WONT 252
#define TELNET_WILL 251
#define TELNET_SB 250
#define TELNET_GA 249
#define TELNET_EL 248
#define TELNET_EC 247
#define TELNET_AYT 246
#define TELNET_AO 245
#define TELNET_IP 244
#define TELNET_BREAK 243
#define TELNET_DM 242
#define TELNET_NOP 241
#define TELNET_SE 240
#define TELNET_EOR 239
#define TELNET_ABORT 238
#define TELNET_SUSP 237
#define TELNET_EOF 236
/*@}*/

/*! \name Telnet option values. */
/*@{*/
/*! Telnet options. */
#define TELNET_TELOPT_BINARY 0
#define TELNET_TELOPT_ECHO 1
#define TELNET_TELOPT_RCP 2
#define TELNET_TELOPT_SGA 3
#define TELNET_TELOPT_NAMS 4
#define TELNET_TELOPT_STATUS 5
#define TELNET_TELOPT_TM 6
#define TELNET_TELOPT_RCTE 7
#define TELNET_TELOPT_NAOL 8
#define TELNET_TELOPT_NAOP 9
#define TELNET_TELOPT_NAOCRD 10
#define TELNET_TELOPT_NAOHTS 11
#define TELNET_TELOPT_NAOHTD 12
#define TELNET_TELOPT_NAOFFD 13
#define TELNET_TELOPT_NAOVTS 14
#define TELNET_TELOPT_NAOVTD 15
#define TELNET_TELOPT_NAOLFD 16
#define TELNET_TELOPT_XASCII 17
#define TELNET_TELOPT_LOGOUT 18
#define TELNET_TELOPT_BM 19
#define TELNET_TELOPT_DET 20
#define TELNET_TELOPT_SUPDUP 21
#define TELNET_TELOPT_SUPDUPOUTPUT 22
#define TELNET_TELOPT_SNDLOC 23
#define TELNET_TELOPT_TTYPE 24
#define TELNET_TELOPT_EOR 25
#define TELNET_TELOPT_TUID 26
#define TELNET_TELOPT_OUTMRK 27
#define TELNET_TELOPT_TTYLOC 28
#define TELNET_TELOPT_3270REGIME 29
#define TELNET_TELOPT_X3PAD 30
#define TELNET_TELOPT_NAWS 31
#define TELNET_TELOPT_TSPEED 32
#define TELNET_TELOPT_LFLOW 33
#define TELNET_TELOPT_LINEMODE 34
#define TELNET_TELOPT_XDISPLOC 35
#define TELNET_TELOPT_ENVIRON 36
#define TELNET_TELOPT_AUTHENTICATION 37
#define TELNET_TELOPT_ENCRYPT 38
#define TELNET_TELOPT_NEW_ENVIRON 39
#define TELNET_TELOPT_MSSP 70
#define TELNET_TELOPT_COMPRESS2 86
#define TELNET_TELOPT_ZMP 93
#define TELNET_TELOPT_EXOPL 255

#define TELNET_TELOPT_MCCP2 86
/*@}*/

/*! \name Protocol codes for TERMINAL-TYPE commands. */
/*@{*/
/*! TERMINAL-TYPE codes. */
#define TELNET_TTYPE_IS 0
#define TELNET_TTYPE_SEND 1
/*@}*/

/*! \name Protocol codes for NEW-ENVIRON/ENVIRON commands. */
/*@{*/
/*! NEW-ENVIRON/ENVIRON codes. */
#define TELNET_ENVIRON_IS 0
#define TELNET_ENVIRON_SEND 1
#define TELNET_ENVIRON_INFO 2
#define TELNET_ENVIRON_VAR 0
#define TELNET_ENVIRON_VALUE 1
#define TELNET_ENVIRON_ESC 2
#define TELNET_ENVIRON_USERVAR 3
/*@}*/

/*! \name Protocol codes for MSSP commands. */
/*@{*/
/*! MSSP codes. */
#define TELNET_MSSP_VAR 1
#define TELNET_MSSP_VAL 2
/*@}*/

/*! \name Telnet state tracker flags. */
/*@{*/
/*! Control behavior of telnet state tracker. */
#define TELNET_FLAG_PROXY (1<<0)

#define TELNET_PFLAG_DEFLATE (1<<7)
/*@}*/

#if !defined(UNUSED_ARG)
#define UNUSED_ARG(A) do { A=A; } while(0)
#endif

/*! 
 * error codes 
 */
enum telnet_error_t {
	TELNET_EOK = 0,   /*!< no error */
	TELNET_EBADVAL,   /*!< invalid parameter, or API misuse */
	TELNET_ENOMEM,    /*!< memory allocation failure */
	TELNET_EOVERFLOW, /*!< data exceeds buffer size */
	TELNET_EPROTOCOL, /*!< invalid sequence of special bytes */
	TELNET_ECOMPRESS  /*!< error handling compressed streams */
};
typedef enum telnet_error_t telnet_error_t; /*!< Error code type. */

/*! 
 * event codes 
 */
enum telnet_event_type_t {
	TELNET_EV_DATA = 0,        /*!< raw text data has been received */
	TELNET_EV_SEND,            /*!< data needs to be sent to the peer */
	TELNET_EV_IAC,             /*!< generic IAC code received */
	TELNET_EV_WILL,            /*!< WILL option negotiation received */
	TELNET_EV_WONT,            /*!< WONT option neogitation received */
	TELNET_EV_DO,              /*!< DO option negotiation received */
	TELNET_EV_DONT,            /*!< DONT option negotiation received */
	TELNET_EV_SUBNEGOTIATION,  /*!< sub-negotiation data received */
	TELNET_EV_COMPRESS,        /*!< compression has been enabled */
	TELNET_EV_ZMP,             /*!< ZMP command has been received */
	TELNET_EV_TTYPE,           /*!< TTYPE command has been received */
	TELNET_EV_ENVIRON,         /*!< ENVIRON command has been received */
	TELNET_EV_MSSP,            /*!< MSSP command has been received */
	TELNET_EV_WARNING,         /*!< recoverable error has occured */
	TELNET_EV_ERROR            /*!< non-recoverable error has occured */
};
typedef enum telnet_event_type_t telnet_event_type_t; /*!< Telnet event type. */

/*! 
 * environ/MSSP command information 
 */
struct telnet_environ_t {
	unsigned char type; /*!< either TELNET_ENVIRON_VAR or TELNET_ENVIRON_USERVAR */
	const char *var;          /*!< name of the variable being set */
	const char *value;        /*!< value of variable being set; empty string if no value */
};

/*! 
 * event information 
 */
union telnet_event_t {
	/*! 
	 * \brief Event type
	 *
	 * The type field will determine which of the other event structure fields
	 * have been filled in.  For instance, if the event type is TELNET_EV_ZMP,
	 * then the zmp event field (and ONLY the zmp event field) will be filled
	 * in.
	 */ 
	enum telnet_event_type_t type;

	/*! 
	 * data event: for DATA and SEND events 
	 */
	struct data_t {
		enum telnet_event_type_t _type; /*!< alias for type */
		const char *buffer;             /*!< byte buffer */
		size_t size;                    /*!< number of bytes in buffer */
	} data;

	/*! 
	 * WARNING and ERROR events 
	 */
	struct error_t {
		enum telnet_event_type_t _type; /*!< alias for type */
		const char *file;               /*!< file the error occured in */
		const char *func;               /*!< function the error occured in */
		const char *msg;                /*!< error message string */
		int line;                       /*!< line of file error occured on */
		telnet_error_t errcode;         /*!< error code */
	} error;

	/*! 
	 * command event: for IAC 
	 */
	struct iac_t {
		enum telnet_event_type_t _type; /*!< alias for type */
		unsigned char cmd;              /*!< telnet command received */
	} iac;

	/*! 
	 * negotiation event: WILL, WONT, DO, DONT 
	 */
	struct negotiate_t {
		enum telnet_event_type_t _type; /*!< alias for type */
		unsigned char telopt;           /*!< option being negotiated */
	} neg;

	/*! 
	 * subnegotiation event 
	 */
	struct subnegotiate_t {
		enum telnet_event_type_t _type; /*!< alias for type */
		const char *buffer;             /*!< data of sub-negotiation */
		size_t size;                    /*!< number of bytes in buffer */
		unsigned char telopt;           /*!< option code for negotiation */
	} sub;

	/*! 
	 * ZMP event 
	 */
	struct zmp_t {
		enum telnet_event_type_t _type; /*!< alias for type */
		const char **argv;              /*!< array of argument string */
		size_t argc;                    /*!< number of elements in argv */
	} zmp;

	/*! 
	 * TTYPE event 
	 */
	struct ttype_t {
		enum telnet_event_type_t _type; /*!< alias for type */
		unsigned char cmd;              /*!< TELNET_TTYPE_IS or TELNET_TTYPE_SEND */
		const char* name;               /*!< terminal type name (IS only) */
	} ttype;

	/*! 
	 * COMPRESS event 
	 */
	struct compress_t {
		enum telnet_event_type_t _type; /*!< alias for type */
		unsigned char state;            /*!< 1 if compression is enabled,
	                                         0 if disabled */
	} compress;

	/*! 
	 * ENVIRON/NEW-ENVIRON event
	 */
	struct environ_t {
		enum telnet_event_type_t _type;        /*!< alias for type */
		const struct telnet_environ_t *values; /*!< array of variable values */
		size_t size;                           /*!< number of elements in values */
		unsigned char cmd;                     /*!< SEND, IS, or INFO */
	} environ;
	
	/*!
	 * MSSP event
	 */
	struct mssp_t {
		enum telnet_event_type_t _type;        /*!< alias for type */
		const struct telnet_environ_t *values; /*!< array of variable values */
		size_t size;                           /*!< number of elements in values */
	} mssp;
};

/*! 
 * \brief event handler
 *
 * This is the type of function that must be passed to
 * telnet_init() when creating a new telnet object.  The
 * function will be invoked once for every event generated
 * by the libtelnet protocol parser.
 *
 * \param telnet    The telnet object that generated the event
 * \param event     Event structure with details about the event
 * \param user_data User-supplied pointer
 */
typedef void (*telnet_event_handler_t)(telnet_t *telnet,
		telnet_event_t *event, void *user_data);

/*! 
 * telopt support table element; use telopt of -1 for end marker 
 */
struct telnet_telopt_t {
	short telopt;      /*!< one of the TELOPT codes or -1 */
	unsigned char us;  /*!< TELNET_WILL or TELNET_WONT */
	unsigned char him; /*!< TELNET_DO or TELNET_DONT */
};

/*! 
 * state tracker -- private data structure 
 */
struct telnet_t;

/*!
 * \brief Initialize a telnet state tracker.
 *
 * This function initializes a new state tracker, which is used for all
 * other libtelnet functions.  Each connection must have its own
 * telnet state tracker object.
 *
 * \param telopts   Table of TELNET options the application supports.
 * \param eh        Event handler function called for every event.
 * \param flags     0 or TELNET_FLAG_PROXY.
 * \param user_data Optional data pointer that will be passsed to eh.
 * \return Telent state tracker object.
 */
extern telnet_t* telnet_init(const telnet_telopt_t *telopts,
		telnet_event_handler_t eh, unsigned char flags, void *user_data);

/*!
 * \brief Free up any memory allocated by a state tracker.
 *
 * This function must be called when a telnet state tracker is no
 * longer needed (such as after the connection has been closed) to
 * release any memory resources used by the state tracker.
 *
 * \param telnet Telnet state tracker object.
 */
extern void telnet_free(telnet_t *telnet);

/*!
 * \brief Push a byte buffer into the state tracker.
 *
 * Passes one or more bytes to the telnet state tracker for
 * protocol parsing.  The byte buffer is most often going to be
 * the buffer that recv() was called for while handling the
 * connection.
 *
 * \param telnet Telnet state tracker object.
 * \param buffer Pointer to byte buffer.
 * \param size   Number of bytes pointed to by buffer.
 */
extern void telnet_recv(telnet_t *telnet, const char *buffer,
		size_t size);

/*!
 * \brief Send a telnet command.
 *
 * \param telnet Telnet state tracker object.
 * \param cmd    Command to send.
 */
extern void telnet_iac(telnet_t *telnet, unsigned char cmd);

/*!
 * \brief Send negotiation command.
 *
 * Internally, libtelnet uses RFC1143 option negotiation rules.
 * The negotiation commands sent with this function may be ignored
 * if they are determined to be redundant.
 *
 * \param telnet Telnet state tracker object.
 * \param cmd    TELNET_WILL, TELNET_WONT, TELNET_DO, or TELNET_DONT.
 * \param opt    One of the TELNET_TELOPT_* values.
 */
extern void telnet_negotiate(telnet_t *telnet, unsigned char cmd,
		unsigned char opt);

/*!
 * Send non-command data (escapes IAC bytes).
 *
 * \param telnet Telnet state tracker object.
 * \param buffer Buffer of bytes to send.
 * \param size   Number of bytes to send.
 */
extern void telnet_send(telnet_t *telnet,
		const char *buffer, size_t size);

/*!
 * \brief Begin a sub-negotiation command.
 *
 * Sends IAC SB followed by the telopt code.  All following data sent
 * will be part of the sub-negotiation, until telnet_finish_sb() is
 * called.
 *
 * \param telnet Telnet state tracker object.
 * \param telopt One of the TELNET_TELOPT_* values.
 */
extern void telnet_begin_sb(telnet_t *telnet,
		unsigned char telopt);

/*!
 * \brief Finish a sub-negotiation command.
 *
 * This must be called after a call to telnet_begin_sb() to finish a
 * sub-negotiation command.
 *
 * \param telnet Telnet state tracker object.
 */
#define telnet_finish_sb(telnet) telnet_iac((telnet), TELNET_SE)

/*!
 * \brief Shortcut for sending a complete subnegotiation buffer.
 *
 * Equivalent to:
 *   telnet_begin_sb(telnet, telopt);
 *   telnet_send(telnet, buffer, size);
 *   telnet_finish_sb(telnet);
 *
 * \param telnet Telnet state tracker format.
 * \param telopt One of the TELNET_TELOPT_* values.
 * \param buffer Byte buffer for sub-negotiation data.
 * \param size   Number of bytes to use for sub-negotiation data.
 */
extern void telnet_subnegotiation(telnet_t *telnet, unsigned char telopt,
		const char *buffer, size_t size);

/*!
 * \brief Begin sending compressed data.
 *
 * This function will begein sending data using the COMPRESS2 option,
 * which enables the use of zlib to compress data sent to the client.
 * The client must offer support for COMPRESS2 with option negotiation,
 * and zlib support must be compiled into libtelnet.
 *
 * Only the server may call this command.
 *
 * \param telnet Telnet state tracker object.
 */
extern void telnet_begin_compress2(telnet_t *telnet);

/*!
 * \brief Send formatted data.
 *
 * This function is a wrapper around telnet_send().  It allows using
 * printf-style formatting.
 *
 * Additionally, this function will translate \\r to the CR NUL construct and
 * \\n with CR LF, as well as automatically escaping IAC bytes like
 * telnet_send().
 *
 * \param telnet Telnet state tracker object.
 * \param fmt    Format string.
 * \return Number of bytes sent.
 */
extern int telnet_printf(telnet_t *telnet, const char *fmt, ...)
		TELNET_GNU_PRINTF(2, 3);

/*!
 * \brief Send formatted data.
 *
 * See telnet_printf().
 */
extern int telnet_vprintf(telnet_t *telnet, const char *fmt, va_list va);

/*!
 * \brief Send formatted data (no newline escaping).
 *
 * This behaves identically to telnet_printf(), except that the \\r and \\n
 * characters are not translated.  The IAC byte is still escaped as normal
 * with telnet_send().
 *
 * \param telnet Telnet state tracker object.
 * \param fmt    Format string.
 * \return Number of bytes sent.
 */
extern int telnet_raw_printf(telnet_t *telnet, const char *fmt, ...)
		TELNET_GNU_PRINTF(2, 3);

/*!
 * \brief Send formatted data (no newline escaping).
 *
 * See telnet_raw_printf().
 */
extern int telnet_raw_vprintf(telnet_t *telnet, const char *fmt, va_list va);

/*!
 * \brief Begin a new set of NEW-ENVIRON values to request or send.
 *
 * This function will begin the sub-negotiation block for sending or
 * requesting NEW-ENVIRON values.
 *
 * The telnet_finish_newenviron() macro must be called after this
 * function to terminate the NEW-ENVIRON command.
 *
 * \param telnet Telnet state tracker object.
 * \param type   One of TELNET_ENVIRON_SEND, TELNET_ENVIRON_IS, or
 *               TELNET_ENVIRON_INFO.
 */
extern void telnet_begin_newenviron(telnet_t *telnet, unsigned char type);

/*!
 * \brief Send a NEW-ENVIRON variable name or value.
 *
 * This can only be called between calls to telnet_begin_newenviron() and
 * telnet_finish_newenviron().
 *
 * \param telnet Telnet state tracker object.
 * \param type   One of TELNET_ENVIRON_VAR, TELNET_ENVIRON_USERVAR, or
 *               TELNET_ENVIRON_VALUE.
 * \param string Variable name or value.
 */
extern void telnet_newenviron_value(telnet_t* telnet, unsigned char type,
		const char *string);

/*!
 * \brief Finish a NEW-ENVIRON command.
 *
 * This must be called after a call to telnet_begin_newenviron() to finish a
 * NEW-ENVIRON variable list.
 *
 * \param telnet Telnet state tracker object.
 */
#define telnet_finish_newenviron(telnet) telnet_finish_sb((telnet))

/*!
 * \brief Send the TERMINAL-TYPE SEND command.
 *
 * Sends the sequence IAC TERMINAL-TYPE SEND.
 *
 * \param telnet Telnet state tracker object.
 */
extern void telnet_ttype_send(telnet_t *telnet);

/*!
 * \brief Send the TERMINAL-TYPE IS command.
 *
 * Sends the sequence IAC TERMINAL-TYPE IS "string".
 *
 * According to the RFC, the recipient of a TERMINAL-TYPE SEND shall
 * send the next possible terminal-type the client supports.  Upon sending
 * the type, the client should switch modes to begin acting as the terminal
 * type is just sent.
 *
 * The server may continue sending TERMINAL-TYPE IS until it receives a
 * terminal type is understands.  To indicate to the server that it has
 * reached the end of the available optoins, the client must send the last
 * terminal type a second time.  When the server receives the same terminal
 * type twice in a row, it knows it has seen all available terminal types.
 *
 * After the last terminal type is sent, if the client receives another
 * TERMINAL-TYPE SEND command, it must begin enumerating the available
 * terminal types from the very beginning.  This allows the server to
 * scan the available types for a preferred terminal type and, if none
 * is found, to then ask the client to switch to an acceptable
 * alternative.
 *
 * Note that if the client only supports a single terminal type, then
 * simply sending that one type in response to every SEND will satisfy
 * the behavior requirements.
 *
 * \param telnet Telnet state tracker object.
 * \param ttype  Name of the terminal-type being sent.
 */
extern void telnet_ttype_is(telnet_t *telnet, const char* ttype);

/*!
 * \brief Send a ZMP command.
 *
 * \param telnet Telnet state tracker object.
 * \param argc   Number of ZMP commands being sent.
 * \param argv   Array of argument strings.
 */
extern void telnet_send_zmp(telnet_t *telnet, size_t argc, const char **argv);

/*!
 * \brief Send a ZMP command.
 *
 * Arguments are listed out in var-args style.  After the last argument, a
 * NULL pointer must be passed in as a sentinel value.
 *
 * \param telnet Telnet state tracker object.
 */
extern void telnet_send_zmpv(telnet_t *telnet, ...);

/*!
 * \brief Send a ZMP command.
 *
 * See telnet_send_zmpv().
 */
extern void telnet_send_vzmpv(telnet_t *telnet, va_list va);

/*!
 * \brief Begin sending a ZMP command
 *
 * \param telnet Telnet state tracker object.
 * \param cmd    The first argument (command name) for the ZMP command.
 */
extern void telnet_begin_zmp(telnet_t *telnet, const char *cmd);

/*!
 * \brief Send a ZMP command argument.
 *
 * \param telnet Telnet state tracker object.
 * \param arg    Telnet argument string.
 */
extern void telnet_zmp_arg(telnet_t *telnet, const char *arg);

/*!
 * \brief Finish a ZMP command.
 *
 * This must be called after a call to telnet_begin_zmp() to finish a
 * ZMP argument list.
 *
 * \param telnet Telnet state tracker object.
 */
#define telnet_finish_zmp(telnet) telnet_finish_sb((telnet))

/* C++ support */
#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* !defined(LIBTELNET_INCLUDE) */
