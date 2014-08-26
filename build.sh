#!/bin/sh
SRC=pixelserv.c
OUT=dist/pixelserv
mkdir dist

CC="gcc -m32"
CFLAGS="-g -s -Wall -ffunction-sections -fdata-sections -fno-strict-aliasing"
LDFLAGS="-Wl,--gc-sections"
STRIP="strip -s -R .note -R .comment -R .gnu.version -R .gnu.version_r"
OPTS="-DDO_COUNT -DIF_MODE -DTEXT_REPLY -DPORT_MODE -DDROP_ROOT -DVERBOSE -DTEST -DREAD_FILE -DREAD_GIF -DNULLSERV_REPLIES -DHEX_DUMP -DSSL_RESP -DMULTIPORT"
BIN=$OUT.host
$CC $CFLAGS $OPTS $SRC -o $BIN
#$STRIP $BIN
ls -laF $BIN

# use Linksys Tomato toolchain (or teddy_bear tomatousb K26, Tornado dd-wrt)
export PATH=/opt/brcm/hndtools-mipsel-uclibc/bin:/opt/brcm/hndtools-mipsel-linux/bin:$PATH
CC="mipsel-uclibc-gcc -mips32"
CFLAGS="-Os -s -Wall -ffunction-sections -fdata-sections"
LDFLAGS="-Wl,--gc-sections"
STRIP="mipsel-uclibc-strip -s -R .note -R .comment -R .gnu.version -R .gnu.version_r"

#tomato
OPTS="-DDO_COUNT -DTEXT_REPLY -DDROP_ROOT -DNULLSERV_REPLIES -DSSL_RESP -DMULTIPORT -DIF_MODE"
# -DIF_MODE "-i br0" responsible for failures when gui changes made
# -DREAD_FILE -DREAD_GIF over-ridden by -DNULLSERV_REPLIES
# -DVERBOSE"
BIN=$OUT
$CC $CFLAGS $LDFLAGS $OPTS $SRC -o $BIN
$STRIP $BIN
ls -laF $BIN

OPTS="-O3 -DTINY"
BIN=$OUT.tiny
$CC $CFLAGS $LDFLAGS $OPTS $SRC -o $BIN
$STRIP $BIN
ls -laF $BIN
