#!/bin/bash
# Set a device name in a Suva configuration file.

if [ "$#" != "2" ]; then
	echo "$0 <suvad.conf> <device name>"
	exit 1
fi

SED="s/^\([[:space:]]*<device>\)[0-9]*\(<\/device>\)/\1$2\2/i"
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

