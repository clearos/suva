#!/bin/sh

mkdir -vp m4
find $(pwd) -name configure.ac | xargs touch

# Regenerate configuration files
autoreconf -i -f || exit 1

