#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions

"$builddir"/../src/tdbusm-check

echo Test complete.
