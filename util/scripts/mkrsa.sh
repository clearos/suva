#!/bin/bash

# Default key size
BITS=2048

if [ "$1" != "" ]; then
	BITS=$1
fi

echo "Generating private-$BITS.pem:"
openssl genrsa -out private-$BITS.pem $BITS || exit 1
echo "Extracting public-$BITS.pem:"
openssl rsa -in private-$BITS.pem -out public-$BITS.pem -pubout || exit 1

exit 0
