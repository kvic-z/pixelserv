#!/bin/sh
# Tomatoware native compiler toolchain
PREFIX=""
# Tomato cross-compiler toolchain
#PREFIX="mipsel-uclibc-"
# UPX compressor
UPX="../upx/upx -9"

SRC="util.c socket_handler.c pixelserv.c"
OUT=dist/pixelserv
mkdir -p dist

#CC="gcc -m32"
#CFLAGS="-g -s -Wall -ffunction-sections -fdata-sections -fno-strict-aliasing"
#LDFLAGS="-Wl,--gc-sections"
#STRIP="strip -s -R .note -R .comment -R .gnu.version -R .gnu.version_r"
#OPTS="-DIF_MODE -DDROP_ROOT -DVERBOSE -DTEST -DHEX_DUMP"
#BIN=$OUT.host
#$CC $CFLAGS $OPTS $SRC -o $BIN || exit $?
##$STRIP $BIN
#ls -laF $BIN

#tomato common
#CC=$PREFIX"gcc -mips32"
CC=$PREFIX"gcc"
STRIP=$PREFIX"strip -s -R .note -R .comment -R .gnu.version -R .gnu.version_r"
OPTS="-DDROP_ROOT -DIF_MODE"

#tomato small - standard, optimized for size
CFLAGS="-Os -s -Wall -ffunction-sections -fdata-sections"
LDFLAGS="-Wl,--gc-sections"
# -DIF_MODE "-i br0" responsible for failures when gui changes made
# -DREAD_FILE -DREAD_GIF over-ridden by -DNULLSERV_REPLIES
# -DTEXT_REPLY set by -DREDIRECT
# -DPORT_MODE set by -DMULTIPORT
# -DDO_COUNT set by -DSTATS_REPLY and/or -DSTATS_PIPE
# -DVERBOSE
#BIN=$OUT.small
#$CC $CFLAGS $LDFLAGS $OPTS $SRC -o $BIN || exit $?
#$STRIP $BIN
#ls -laF $BIN

#tomato static - standard, optimized for performance
CFLAGS="-O3 -s -Wall -ffunction-sections -fdata-sections"
#LDFLAGS="-static -Wl,--gc-sections,-Bdynamic,-lgcc_s,-Bstatic"
LDFLAGS="-static -Wl,--gc-sections"
BIN=$OUT
echo building $BIN ...
$CC $CFLAGS $LDFLAGS $OPTS $SRC -o $BIN || exit $?
$STRIP $BIN
$UPX $BIN
ls -laF $BIN

#tomato static - debug
#CFLAGS="-g -Wall -fno-pie"
#LDFLAGS="-static"
#OPTS="-DIF_MODE -DDROP_ROOT -DSTACKTRACE"
#BIN=$OUT.debug
#echo building $BIN ...
#$CC $CFLAGS $LDFLAGS $OPTS $SRC -o $BIN || exit $?
#$STRIP $BIN
#ls -laF $BIN

#tomato fast - standard, optimized for performance
#CFLAGS="-O3 -s -Wall"
#LDFLAGS="-Wl,--gc-sections"
#BIN=$OUT
#echo building $BIN ...
#$CC $CFLAGS $LDFLAGS $OPTS $SRC -o $BIN || exit $?
#$STRIP $BIN
#ls -laF $BIN

PVER=`grep VERSION util.h | awk '{print $NF}' | sed 's|\"||g'`
PFIL=pixelserv-$PVER.mips.zip
echo building $PFIL ...
rm -f $PFIL #> /dev/null 2>&1
#zip $PFIL LICENSE README.md dist/pixelserv dist/pixelserv.small dist/pixelserv.static dist/pixelserv.tiny || exit $?
zip $PFIL LICENSE README.md dist/pixelserv || exit $?
ls -laF $PFIL
