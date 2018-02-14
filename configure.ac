AC_INIT([pixelserv-tls], [2.0.0], [])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

AC_CHECK_LIB([crypto], [EVP_EncryptInit], [], 
	AC_MSG_FAILURE([can't find openssl crypto lib]))
AC_CHECK_LIB([ssl], [SSL_CTX_new], [], 
	AC_MSG_FAILURE([can't find openssl ssl lib]))
AC_CHECK_LIB([pthread], [main], [], 
	AC_MSG_ERROR([libpthread not found]))
AC_CHECK_LIB([rt], [clock_gettime], [], [])

AC_CONFIG_FILES([
 Makefile
])
AC_OUTPUT
