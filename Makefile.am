bin_PROGRAMS = pixelserv-tls
pixelserv_tls_CFLAGS = -DDROP_ROOT -DIF_MODE -DUSE_PTHREAD
pixelserv_tls_CFLAGS += -O3 -s -Wall -ffunction-sections -fdata-sections -fno-strict-aliasing
pixelserv_tls_LDFLAGS = -Wl,--gc-sections
pixelserv_tls_SOURCES =  pixelserv.c socket_handler.c certs.c util.c logger.c
