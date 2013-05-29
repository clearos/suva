#!/bin/bash
# An example master key server rotation script.

declare -i ID=0
declare -i KEYS=9
declare -i BITS=2048
KEYDIR=/var/db/suva/pointclark.net
PIDFILE=/var/run/suvad-server.pid

if [ ! -d "$KEYDIR" ]; then
	echo "$0: $KEYDIR: No such directory."
	exit 1
fi

if [ ! -f "$PIDFILE" ]; then
	echo "$0: $PIDFILE: No such file."
	exit 1
fi

if [ -f "$KEYDIR/.id" ]; then
	ID=$(cat "$KEYDIR/.id")
	if [ $ID -gt $KEYS ]; then
		ID=0
	fi
fi

PUBKEY=$(printf "pub-%04d.pem" $ID)
PRVKEY=$(printf "prv-%04d.pem" $ID)

openssl genrsa -out "$KEYDIR/$PRVKEY" $BITS || exit 1
openssl rsa -in "$KEYDIR/$PRVKEY" -out "$KEYDIR/$PUBKEY" -pubout || exit 1

echo $[ $ID + 1 ] > "$KEYDIR/.id" || exit 1

kill -USR1 $(cat $PIDFILE) || exit 1

exit 0
