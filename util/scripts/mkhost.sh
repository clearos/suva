#!/bin/bash
# Generate a new device host key.

if [ "$#" != "1" ]; then
	echo "$0 <suvad.conf>"
	exit 1
fi

KEY=$(head -c 16 /dev/urandom | od -A n -t x1 | tr -d ' ')
SED="s/^\([[:space:]]*<hostkey>\)[a-fA-F0-9]*\(<\/hostkey>\)/\1$KEY\2/i"
TEMP=$(mktemp /tmp/.suvad.confXXXXXXXXXX) || exit 1

if ! $(sed -e "$SED" $1 > $TEMP); then
	rm -f $TEMP; exit 1
else
	mv $TEMP $1
	if [ $? -ne 0 ]; then
		rm -f $TEMP
		exit 1
	fi
	chown suva:suva $1 || exit 1
	chmod 0600 $1 || exit 1
fi

exit 0
