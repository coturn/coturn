# $FreeBSD$

PORTNAME=	turnserver
PORTVERSION=	4.4.1.1
CATEGORIES=	net
MASTER_SITES=	http://turnserver.open-sys.org/downloads/v${PORTVERSION}/:prog \
		http://turnserver.open-sys.org/downloads/extradocs/:xdocs \
		http://coturn.net/turnserver/v${PORTVERSION}/:prog \
		http://coturn.net/turnserver/extradocs/:xdocs
PKGNAMEPREFIX=
DISTFILES=	${DISTNAME}${EXTRACT_SUFX}:prog \
		turn.extra.docs-2.0.0.1.tar.gz:xdocs

MAINTAINER=	mom040267@gmail.com
COMMENT=	STUN/TURN Server; IPv6, DTLS support; RFCs 5389, 5766, 6062, 6156

LICENSE=	BSD3CLAUSE

LIB_DEPENDS=	libevent.so:${PORTSDIR}/devel/libevent2

CONFLICTS=	libevent-1.*

SUB_FILES=	pkg-message

MANPAGES=	turnserver.1 turnadmin.1 turnutils.1 turnutils_peer.1 turnutils_stunclient.1 turnutils_uclient.1 coturn.1

USE_OPENSSL=	YES

USE_RC_SUBR=	turnserver

HAS_CONFIGURE=	YES

OPTIONS_DEFINE=	DOCS EXAMPLES REDIS PGSQL MYSQL SQLITE

SHEBANG_FILES=	examples/scripts/restapi/shared_secret_maintainer.pl
USES=		perl5 shebangfix

MYSQL_DESC=	MySQL database support
PGSQL_DESC=	PostgreSQL database support
REDIS_DESC=	Redis support for user database and for status and statistics reporting
SQLITE_DESC=	SQLite database support

OPTIONS_DEFAULT=	MYSQL PGSQL REDIS SQLITE

DOCS=	html TurnNetworks.pdf
PORTREADMEDOCS=	LICENSE README.turnserver README.turnadmin README.turnutils INSTALL
PORTDOCS=	${DOCS} ${PORTREADMEDOCS} postinstall.txt schema.sql schema.mongo.sh \
		schema.userdb.redis schema.stats.redis

_BIN_UTILS=	peer stunclient uclient

_ETC_EXAMPLES=	turnserver.conf turn_client_cert.pem \
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
	longtermsecuredb/secure_relay_with_db_psql.sh \
	longtermsecuredb/secure_relay_with_db_mysql.sh \
	longtermsecuredb/secure_relay_with_db_mysql_ssl.sh \
	longtermsecuredb/secure_relay_with_db_mongo.sh \
	longtermsecuredb/secure_relay_with_db_redis.sh \
	longtermsecuredb/secure_relay_with_db_sqlite.sh \
	restapi/secure_relay_secret.sh \
	restapi/secure_relay_secret_with_db_mysql.sh \
	restapi/secure_relay_secret_with_db_psql.sh \
	restapi/secure_relay_secret_with_db_redis.sh \
	restapi/secure_relay_secret_with_db_mongo.sh \
	restapi/secure_relay_secret_with_db_sqlite.sh \
	restapi/secure_udp_client_with_secret.sh \
	restapi/secure_relay_secret_with_db_psql.sh \
	restapi/shared_secret_maintainer.pl \
	selfloadbalance/secure_dos_attack.sh \
	selfloadbalance/secure_relay.sh

CONFIGURE_ENV+=	PTHREAD_LIBS=-pthread TURN_DISABLE_RPATH=1

.include <bsd.port.options.mk>

.if ${PORT_OPTIONS:MSQLITE}
USE_SQLITE=	yes
.else
CONFIGURE_ENV+=	TURN_NO_SQLITE=1
.endif

.if ${PORT_OPTIONS:MPGSQL}
USES+=		pgsql
.else
CONFIGURE_ENV+=	TURN_NO_PQ=1
.endif

.if ${PORT_OPTIONS:MMYSQL}
USE_MYSQL=	yes
.else
CONFIGURE_ENV+=	TURN_NO_MYSQL=1
.endif

.if ${PORT_OPTIONS:MREDIS}
LIB_DEPENDS+=	libhiredis.so:${PORTSDIR}/databases/hiredis
.else
CONFIGURE_ENV+=	TURN_NO_HIREDIS=1
.endif

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/bin/turnserver ${STAGEDIR}${PREFIX}/bin/turnserver
	${INSTALL_PROGRAM} ${WRKSRC}/bin/turnadmin ${STAGEDIR}${PREFIX}/bin/turnadmin
.for f in ${_BIN_UTILS}
	${INSTALL_PROGRAM} ${WRKSRC}/bin/turnutils_${f} ${STAGEDIR}${PREFIX}/bin/
.endfor
.for f in ${MANPAGES}
	${INSTALL_MAN} ${WRKSRC}/man/man1/${f} ${STAGEDIR}${PREFIX}/man/man1/${f}
.endfor
	${MKDIR} ${STAGEDIR}${PREFIX}/var/db
.if ${PORT_OPTIONS:MSQLITE}
	${INSTALL_DATA} ${WRKSRC}/sqlite/turndb ${STAGEDIR}${PREFIX}/var/db/turndb
.endif
	${MKDIR} ${STAGEDIR}${DATADIR}/
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.sql ${STAGEDIR}${DATADIR}/schema.sql
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.userdb.redis ${STAGEDIR}${DATADIR}/schema.userdb.redis
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.stats.redis ${STAGEDIR}${DATADIR}/schema.stats.redis
	${INSTALL_SCRIPT} ${WRKSRC}/turndb/testredisdbsetup.sh ${STAGEDIR}${DATADIR}/testredisdbsetup.sh
	${INSTALL_SCRIPT} ${WRKSRC}/turndb/schema.mongo.sh ${STAGEDIR}${DATADIR}/schema.mongo.sh
	${INSTALL_SCRIPT} ${WRKSRC}/turndb/testmongosetup.sh ${STAGEDIR}${DATADIR}/testmongosetup.sh
	${INSTALL_DATA} ${WRKSRC}/lib/libturnclient.a ${STAGEDIR}${PREFIX}/lib/libturnclient.a
	${INSTALL_DATA} ${WRKSRC}/examples/etc/turnserver.conf ${STAGEDIR}${PREFIX}/etc/turnserver.conf.default
	${MKDIR} ${STAGEDIR}${PREFIX}/include/turn
	(cd ${WRKSRC}/include/turn/ && ${COPYTREE_SHARE} client ${STAGEDIR}${PREFIX}/include/turn/)
	(cd ${WRKSRC}/include/turn/ && ${COPYTREE_SHARE} ns_turn_defs.h ${STAGEDIR}${PREFIX}/include/turn/)
.if ${PORT_OPTIONS:MEXAMPLES}
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}/scripts
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}/scripts/basic
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}/scripts/loadbalance
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}/scripts/longtermsecure
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}/scripts/longtermsecuredb
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}/scripts/restapi
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}/scripts/selfloadbalance
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}/etc
	${INSTALL_MAN} ${WRKSRC}/examples/scripts/readme.txt ${STAGEDIR}${EXAMPLESDIR}/scripts
.for f in ${_ETC_EXAMPLES}
	${INSTALL_DATA} ${WRKSRC}/examples/etc/${f} ${STAGEDIR}${EXAMPLESDIR}/etc/
.endfor
.for f in ${_SCRIPT_EXAMPLES}
	${INSTALL_SCRIPT} ${WRKSRC}/examples/scripts/${f} ${STAGEDIR}${EXAMPLESDIR}/scripts/${f}
.endfor
.endif
.if ${PORT_OPTIONS:MDOCS}
	${MKDIR} ${STAGEDIR}${DOCSDIR}
.for f in ${DOCS}
	(cd ${WRKSRC}/../turndocs/docs/ && ${COPYTREE_SHARE} ${f} ${STAGEDIR}${DOCSDIR})
.endfor
.for f in ${PORTREADMEDOCS}
	${INSTALL_DATA} ${WRKSRC}/${f} ${STAGEDIR}${DOCSDIR}
.endfor
	${INSTALL_DATA} ${PKGMESSAGE} ${STAGEDIR}${DOCSDIR}/postinstall.txt
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.sql ${STAGEDIR}${DOCSDIR}/schema.sql
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.mongo.sh ${STAGEDIR}${DOCSDIR}/schema.mongo.sh
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.userdb.redis ${STAGEDIR}${DOCSDIR}/schema.userdb.redis
	${INSTALL_DATA} ${WRKSRC}/turndb/schema.stats.redis ${STAGEDIR}${DOCSDIR}/schema.stats.redis
.endif

regression-test: build
	@(cd ${WRKSRC} && ${SETENV} ${MAKE_ENV} ${MAKE} test)

.include <bsd.port.mk>
