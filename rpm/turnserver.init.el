#!/bin/bash
#
# Startup script for TURN Server
#
# chkconfig: 345 85 15
# description: RFC 5766 TURN Server
#
# processname: turnserver
# pidfile: /var/run/turnserver/turnserver.pid
# config: /etc/turnserver/turnserver.conf
#
### BEGIN INIT INFO
# Provides: turnserver
# Required-Start: $local_fs $network
# Short-Description: RFC 5766 TURN Server
# Description: RFC 5766 TURN Server
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

TURN=/usr/bin/turnserver
PROG=turnserver
TURNCFG=/etc/turnserver/$PROG.conf
PID_FILE=/var/run/turnserver/$PROG.pid
LOCK_FILE=/var/lock/subsys/$PROG
DEFAULTS=/etc/sysconfig/$PROG
RETVAL=0
USER=turnserver

start() {
	echo -n $"Starting $PROG: "
	daemon --user=$USER $TURN $OPTIONS
	RETVAL=$?
	if [ $RETVAL = 0 ]; then
		pidofproc $TURN > $PID_FILE
		RETVAL=$?
		[ $RETVAL = 0 ] && touch $LOCK_FILE && success
	fi
	echo
	return $RETVAL
}

stop() {
	echo -n $"Stopping $PROG: "
	killproc $TURN
	RETVAL=$?
	echo
	[ $RETVAL = 0 ] && rm -f $LOCK_FILE $PID_FILE
}

[ -f $DEFAULTS ] && . $DEFAULTS
OPTIONS="-o -c $TURNCFG $EXTRA_OPTIONS"

# See how we were called.
case "$1" in
	start)
		start
		;;
	stop)
		stop
		;;
	status)
		status $TURN
		RETVAL=$?
		;;
	restart)
		stop
		start
		;;
	condrestart)
		if [ -f $PID_FILE ] ; then
			stop
			start
		fi
		;;
	*)
		echo $"Usage: $PROG {start|stop|restart|condrestart|status|help}"
		exit 1
esac

exit $RETVAL
