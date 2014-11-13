#!/bin/sh
# Tomatoware native compiler toolchain
PREFIX=""
# Tomato cross-compiler toolchain
#PREFIX="mipsel-uclibc-"
# UPX compressor
UPX="../upx/upx -9"

SRC="util.c socket_handler.c pixelserv.c"
OUT=dist/pixelserv
OUTLIST=""
mkdir -p dist

#tomato common
CC=$PREFIX"gcc"
STRIP=$PREFIX"strip -s -R .note -R .comment -R .gnu.version -R .gnu.version_r"
OPTS="-DDROP_ROOT -DIF_MODE"

#tomato static - standard, optimized for performance
CFLAGS="-O3 -s -Wall -ffunction-sections -fdata-sections"
LDFLAGS="-static -Wl,--gc-sections"
BIN=$OUT
OUTLIST="$OUTLIST $BIN"
echo building $BIN ...
$CC $CFLAGS $LDFLAGS $OPTS $SRC -o $BIN || exit $?
$STRIP $BIN
$UPX $BIN
ls -laF $BIN

#tomato static - standard, debug
CFLAGS="-g -Wall"
LDFLAGS="-static"
BIN=$OUT.debug
OUTLIST="$OUTLIST $BIN"
echo building $BIN ...
$CC $CFLAGS $LDFLAGS $OPTS -DDEBUG $SRC -o $BIN || exit $?
#$STRIP $BIN
#$UPX $BIN
ls -laF $BIN

PVER=`grep VERSION util.h | awk '{print $NF}' | sed 's|\"||g'`
PFIL=pixelserv-$PVER.mips.zip
echo building $PFIL ...
rm -f $PFIL #> /dev/null 2>&1
#zip $PFIL LICENSE README.md dist/pixelserv dist/pixelserv.small dist/pixelserv.static dist/pixelserv.tiny || exit $?
zip $PFIL LICENSE README.md $OUTLIST || exit $?
ls -laF $PFIL
