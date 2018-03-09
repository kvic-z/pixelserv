bin_PROGRAMS = pixelserv-tls
man1_MANS = pixelserv-tls.1
pixelserv_tls_CFLAGS = -DDROP_ROOT -DIF_MODE -DDEFAULT_PEM_PATH=\"/var/cache/pixelserv\"
pixelserv_tls_CFLAGS += -O3 -s -Wall -ffunction-sections -fdata-sections -fno-strict-aliasing
pixelserv_tls_LDFLAGS = -Wl,--gc-sections
pixelserv_tls_SOURCES =  pixelserv.c socket_handler.c certs.c util.c logger.c
