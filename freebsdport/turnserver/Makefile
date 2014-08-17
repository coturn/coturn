# $FreeBSD: head/net/turnserver/Makefile 339463 2014-01-12 00:58:18Z tabthorpe $

PORTNAME=	turnserver
PORTVERSION=	4.1.1.1
CATEGORIES=	net
MASTER_SITES=	http://turnserver.open-sys.org/downloads/v${PORTVERSION}/ \
		http://turnserver.open-sys.org/downloads/extradocs/ \
		http://www.olegmoskalenko.com/turnserver/v${PORTVERSION}/ \
		http://www.olegmoskalenko.com/turnserver/extradocs/
PKGNAMEPREFIX=
DISTFILES=	${DISTNAME}${EXTRACT_SUFX} turn.extra.docs-2.0.0.1.tar.gz

MAINTAINER=	mom040267@gmail.com
COMMENT=	STUN/TURN Server; IPv6, DTLS support; RFCs 5389, 5766, 6062, 6156

LICENSE=	BSD

LIB_DEPENDS=	event-2:${PORTSDIR}/devel/libevent2

CONFLICTS=	libevent-1.*

SUB_FILES=	pkg-message

MAN1=	turnserver.1 turnadmin.1 turnutils.1 turnutils_peer.1 turnutils_stunclient.1 turnutils_uclient.1 coturn.1
MANCOMPRESSED=	no

USE_OPENSSL=	YES

USE_RC_SUBR=	turnserver

HAS_CONFIGURE=	YES

OPTIONS_DEFINE=	MYSQL PGSQL REDIS

MYSQL_DESC=	MySQL support for users database
PGSQL_DESC=	PostgreSQL support for users database
REDIS_DESC=	Redis support for user database and for status and statistics reporting

OPTIONS_DEFAULT=	MYSQL PGSQL REDIS

NO_STAGE=	yes
.include <bsd.port.options.mk>

PORTDOCS=	html TurnNetworks.pdf
PORTREADMEDOCS=	LICENSE README.turnserver README.turnadmin README.turnutils INSTALL

_BIN_UTILS=	peer stunclient uclient

_ETC_EXAMPLES=	turnserver.conf turnuserdb.conf turn_client_cert.pem \
		turn_client_pkey.pem turn_server_cert.pem turn_server_pkey.pem
_SCRIPT_EXAMPLES=	peer.sh	\
basic/relay.sh basic/dos_attack.sh \
basic/tcp_client_c2c_tcp_relay.sh basic/udp_c2c_client.sh \
basic/udp_client.sh basic/tcp_client.sh \
loadbalance/master_relay.sh loadbalance/slave_relay_1.sh loadbalance/slave_relay_2.sh \
loadbalance/udp_c2c.sh loadbalance/tcp_c2c_tcp_relay.sh \
longtermsecure/secure_dtls_client.sh longtermsecure/secure_relay.sh \
longtermsecure/secure_tls_client_cert.sh longtermsecure/secure_dtls_client_cert.sh \
longtermsecure/secure_relay_cert.sh \
longtermsecure/secure_tcp_client_c2c_tcp_relay.sh longtermsecure/secure_tcp_client.sh \
longtermsecure/secure_tls_client_c2c_tcp_relay.sh longtermsecure/secure_tls_client.sh \
longtermsecure/secure_udp_c2c.sh longtermsecure/secure_udp_client.sh \
longtermsecure/secure_dos_attack.sh longtermsecure/secure_udp_client.sh \
longtermsecuredb/secure_relay_with_db_psql.sh longtermsecuredb/secure_relay_with_db_mysql.sh \
longtermsecuredb/secure_relay_with_db_mysql_ssl.sh \
longtermsecuredb/secure_relay_with_db_psql.sh longtermsecuredb/secure_relay_with_db_mongo.sh \
longtermsecuredb/secure_relay_with_db_redis.sh \
restapi/secure_relay_secret.sh restapi/secure_relay_secret_with_db_mysql.sh \
restapi/secure_relay_secret.sh restapi/secure_relay_secret_with_db_redis.sh \
restapi/secure_udp_client_with_secret.sh \
restapi/secure_relay_secret_with_db_psql.sh \
restapi/shared_secret_maintainer.pl \
shorttermsecure/secure_tcp_client_c2c_tcp_relay_short_term.sh \
shorttermsecure/secure_udp_client_short_term.sh \
shorttermsecure/secure_relay_short_term_mech.sh \
selfloadbalance/secure_dos_attack.sh \
selfloadbalance/secure_relay.sh

CONFIGURE_ENV+=	PTHREAD_LIBS=-pthread TURN_DISABLE_RPATH=1

.if ${PORT_OPTIONS:MPGSQL}
USE_PGSQL=	yes
.else
CONFIGURE_ENV+=	TURN_NO_PQ=1
.endif

.if ${PORT_OPTIONS:MMYSQL}
USE_MYSQL=	yes
.else
CONFIGURE_ENV+=	TURN_NO_MYSQL=1
.endif

.if ${PORT_OPTIONS:MREDIS}
LIB_DEPENDS+=	hiredis:${PORTSDIR}/databases/hiredis
.else
CONFIGURE_ENV+=	TURN_NO_HIREDIS=1
.endif

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/bin/turnserver ${PREFIX}/bin/turnserver
	${INSTALL_PROGRAM} ${WRKSRC}/bin/turnadmin ${PREFIX}/bin/turnadmin
.for f in ${_BIN_UTILS}
	${INSTALL_PROGRAM} ${WRKSRC}/bin/turnutils_${f} ${PREFIX}/bin/
.endfor
.for f in ${MAN1}
	${INSTALL_MAN} ${WRKSRC}/man/man1/${f} ${PREFIX}/man/man1/${f}
.endfor
	${MKDIR} ${DATADIR}/
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.sql ${DATADIR}/schema.sql
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.userdb.redis ${DATADIR}/schema.userdb.redis
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.stats.redis ${DATADIR}/schema.stats.redis
	${INSTALL_SCRIPT} ${WRKSRC}/turndb/testredisdbsetup.sh ${DATADIR}/testredisdbsetup.sh
	${INSTALL_SCRIPT} ${WRKSRC}/turndb/schema.mongo.sh ${DATADIR}/schema.mongo.sh
	${INSTALL_SCRIPT} ${WRKSRC}/turndb/testmongosetup.sh ${DATADIR}/testmongosetup.sh
	${INSTALL_DATA} ${WRKSRC}/lib/libturnclient.a ${PREFIX}/lib/libturnclient.a
	${INSTALL_DATA} ${WRKSRC}/examples/etc/turnserver.conf ${PREFIX}/etc/turnserver.conf.default
	${INSTALL_DATA} ${WRKSRC}/examples/etc/turnuserdb.conf ${PREFIX}/etc/turnuserdb.conf.default
	${MKDIR} ${PREFIX}/include/turn
	(cd ${WRKSRC}/include/turn/ && ${COPYTREE_SHARE} client ${PREFIX}/include/turn/)
	(cd ${WRKSRC}/include/turn/ && ${COPYTREE_SHARE} ns_turn_defs.h ${PREFIX}/include/turn/)
.if ${PORT_OPTIONS:MEXAMPLES}
	${MKDIR} ${EXAMPLESDIR}/scripts
	${MKDIR} ${EXAMPLESDIR}/scripts/basic
	${MKDIR} ${EXAMPLESDIR}/scripts/loadbalance
	${MKDIR} ${EXAMPLESDIR}/scripts/longtermsecure
	${MKDIR} ${EXAMPLESDIR}/scripts/longtermsecuredb
	${MKDIR} ${EXAMPLESDIR}/scripts/restapi
	${MKDIR} ${EXAMPLESDIR}/scripts/shorttermsecure
	${MKDIR} ${EXAMPLESDIR}/scripts/selfloadbalance
	${MKDIR} ${EXAMPLESDIR}/etc
	${INSTALL_MAN} ${WRKSRC}/examples/scripts/readme.txt ${EXAMPLESDIR}/scripts
.for f in ${_ETC_EXAMPLES}
	${INSTALL_DATA} ${WRKSRC}/examples/etc/${f} ${EXAMPLESDIR}/etc/
.endfor
.for f in ${_SCRIPT_EXAMPLES}
	${INSTALL_SCRIPT} ${WRKSRC}/examples/scripts/${f} ${EXAMPLESDIR}/scripts/${f}
.endfor
.endif
.if ${PORT_OPTIONS:MDOCS}
	${MKDIR} ${DOCSDIR}
.for f in ${PORTDOCS}
	(cd ${WRKSRC}/../turndocs/docs/ && ${COPYTREE_SHARE} ${f} ${DOCSDIR})
.endfor
.for f in ${PORTREADMEDOCS}
	${INSTALL_DATA} ${WRKSRC}/${f} ${DOCSDIR}
.endfor
	${INSTALL_DATA} ${PKGMESSAGE} ${DOCSDIR}/postinstall.txt
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.sql ${DOCSDIR}/schema.sql
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.mongo.sh ${DOCSDIR}/schema.mongo.sh
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.userdb.redis ${DOCSDIR}/schema.userdb.redis
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.stats.redis ${DOCSDIR}/schema.stats.redis
PORTDOCS+=	postinstall.txt ${PORTREADMEDOCS} schema.sql schema.mongo.sh  \
		schema.userdb.redis schema.stats.redis
.endif

post-install:
	${CAT} ${PKGMESSAGE}

regression-test: build
	@(cd ${WRKSRC} && ${SETENV} ${MAKE_ENV} ${MAKE} test)

.include <bsd.port.mk>
