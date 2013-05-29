#!/bin/sh

find $(pwd) -name configure.ac | xargs touch

# Regenerate configuration files
aclocal || exit 1
automake --foreign --include-deps --add-missing --copy || exit 1
autoreconf -i -f || exit 1

# Run configure for this platform
./configure $*
