#!/bin/sh
set -eu

watcom=${WATCOM:-/opt/watcom}
out=${1:-build/win16-ne-stub}
scripts=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$scripts/../src" && pwd)

mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)
export WATCOM="$watcom"
export INCLUDE="$watcom/h:$watcom/h/win"
export PATH="$watcom/binl64:$PATH"

wcc -q -bt=windows -ms -0 -os -s -zq -wx \
    -fo="$out/i286-win16.ne.obj" "$src/i286-win16.ne.c"
(
    cd "$out"
    wlink option quiet system windows option map=i286-win16.ne.map \
        name i286-win16.ne file i286-win16.ne.obj
    python3 "$scripts/bin2h.py" --ident=stub_i286_win16_ne \
        i286-win16.ne i286-win16.ne.h
)
