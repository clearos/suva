#!/bin/bash

#base=$(dirname $0)/..
base=/home/darryl/source/suva/test
term_server="gnome-terminal --display=$DISPLAY --geometry=155x30+0+0 --hide-menubar --zoom 0.6 -t Server -e "
term_client="gnome-terminal --display=$DISPLAY --geometry=155x30+0-0 --hide-menubar --zoom 0.6 -t Client -e "

export LD_LIBRARY_PATH=$base/lib

function usage()
{
	echo "$0 <start/stop>"
	exit 1
}

function isrunning()
{
	client_pid=$(printf "%s/var/run/suvad/suvad-client.pid" $base)
	server_pid=$(printf "%s/var/run/suvad/suvad-server.pid" $base)

	if [ -f "$client_pid" ]; then
		pid=$(cat $client_pid)
		if [ ! -z "$pid" -a -d "/proc/$pid" ]; then
			return 0
		fi
	fi
	if [ -f "$server_pid" ]; then
		pid=$(cat $server_pid)
		if [ ! -z "$pid" -a -d "/proc/$pid" ]; then
			return 0
		fi
	fi
	return 1
}

function start_gdb()
{
	client_conf=$(printf "%s/etc/client-test%d.conf" $1 $2)
	server_conf=$(printf "%s/etc/server-test%d.conf" $1 $2)
	client_pid=$(printf "%s/var/run/suvad/suvad-client.pid" $1)
	server_pid=$(printf "%s/var/run/suvad/suvad-server.pid" $1)
	#client_log=$(printf "%s/var/log/suvad-client.log" $1)
	#server_log=$(printf "%s/var/log/suvad-server.log" $1)

	echo -e "run -dc $client_conf -p $client_pid\nbt" > /tmp/suva-client-$2.gdb
	echo -e "run -dc $server_conf -p $server_pid\nbt" > /tmp/suva-server-$2.gdb

	pushd "$1/tmp/server"
	$term_server "gdb -x /tmp/suva-server-$id.gdb $base/sbin/suvad-server" &
	popd
	sleep 3
	pushd "$1/tmp/client"
	$term_client "gdb -x /tmp/suva-client-$id.gdb $base/sbin/suvad-client" &
	popd
	sleep 3
}

function stop_gdb()
{
	killall -HUP gdb
}

function start_exec()
{
	client_conf=$(printf "%s/etc/client-test%d.conf" $1 $2)
	server_conf=$(printf "%s/etc/server-test%d.conf" $1 $2)
	client_pid=$(printf "%s/var/run/suvad/suvad-client.pid" $1)
	server_pid=$(printf "%s/var/run/suvad/suvad-server.pid" $1)

	$term_server "$base/sbin/suvad-server -dc $server_conf -p $server_pid"
	sleep 3
	$term_client "$base/sbin/suvad-client -dc $client_conf -p $client_pid"
	sleep 3
}

function start_valgrind()
{
	client_conf=$(printf "%s/etc/client-test%d.conf" $1 $2)
	server_conf=$(printf "%s/etc/server-test%d.conf" $1 $2)
	client_log=$(printf "%s/var/log/valgrind-client%d.log" $1 $2)
	server_log=$(printf "%s/var/log/valgrind-server%d.log" $1 $2)
	client_pid=$(printf "%s/var/run/suvad/suvad-client.pid" $1)
	server_pid=$(printf "%s/var/run/suvad/suvad-server.pid" $1)

	$term_server "valgrind -v --log-file=$server_log --tool=memcheck \
		--leak-check=full --show-reachable=yes --track-origins=yes --db-attach=yes \
		--undef-value-errors=yes --num-callers=24 $base/sbin/suvad-server -dc $server_conf \
		-p $server_pid"
	sleep 3
	$term_client "valgrind -v --log-file=$client_log --tool=memcheck \
		--leak-check=full --show-reachable=yes --track-origins=yes --db-attach=yes \
		--undef-value-errors=yes --num-callers=24 $base/sbin/suvad-client -dc $client_conf \
		-p $client_pid"
#	$base/sbin/suvad-client -c $client_conf
	sleep 3
}

function start_callgrind()
{
	client_conf=$(printf "%s/etc/client-test%d.conf" $1 $2)
	server_conf=$(printf "%s/etc/server-test%d.conf" $1 $2)
	client_log=$(printf "%s/var/log/callgrind-client%d.log" $1 $2)
	server_log=$(printf "%s/var/log/callgrind-server%d.log" $1 $2)
	client_pid=$(printf "%s/var/run/suvad/suvad-client.pid" $1)
	server_pid=$(printf "%s/var/run/suvad/suvad-server.pid" $1)

	$term_server "valgrind --log-file=$server_log --tool=callgrind \
		--instr-atstart=no \
		$base/sbin/suvad-server -dc $server_conf -p $server_pid"
	sleep 3
	$term_client "valgrind --log-file=$client_log --tool=callgrind \
		--instr-atstart=no \
		$base/sbin/suvad-client -dc $client_conf -p $client_pid"
	sleep 3
}

function start()
{
	isrunning && stop

	id=$(basename $0 | sed -e 's/.*-test\([[:digit:]]*\)\.sh$/\1/')

	if [ "$test_type" == "gdb" ]; then
		start_gdb $base $id
	elif [ "$test_type" == "exec" ]; then
		start_exec $base $id
	elif [ "$test_type" == "valgrind" ]; then
		start_valgrind $base $id
	elif [ "$test_type" == "callgrind" ]; then
		start_callgrind $base $id
	else
		echo "$0: invalid test type (\$test_type=?)"
		exit 1
	fi

	sleep 3

	run_test
}

function stop()
{
	isrunning || return

	client_pid=$(printf "%s/var/run/suvad/suvad-client.pid" $base)
	server_pid=$(printf "%s/var/run/suvad/suvad-server.pid" $base)

	if [ -f "$client_pid" ]; then
		pid=$(cat $client_pid)
		if [ ! -z "$pid" -a -d "/proc/$pid" ]; then
			kill -TERM $pid
		fi
	fi
	if [ -f "$server_pid" ]; then
		pid=$(cat $server_pid)
		if [ ! -z "$pid" -a -d "/proc/$pid" ]; then
			kill -TERM $pid
		fi
	fi

	if [ "$test_type" == "gdb" ]; then
		stop_gdb
	elif [ "$test_type" == "exec" ]; then
		echo "$0: test stopped"
	elif [ "$test_type" == "valgrind" ]; then
		echo "$0: test stopped"
	elif [ "$test_type" == "callgrind" ]; then
		echo "$0: test stopped"
	else
		echo "$0: invalid test type (\$test_type=?)"
		exit 1
	fi
}

[ $# -ne 1 ] && usage

if [ "$1" == "start" ]; then
	start $0
elif [ "$1" == "stop" ]; then
	stop $0
else usage
fi

exit 0


# vi: ts=4
