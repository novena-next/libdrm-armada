ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CFLAGS = $(WARN_CFLAGS) @LIBDRM_CFLAGS@

libdrm_dove_la_LTLIBRARIES = libdrm_dove.la
libdrm_dove_ladir = $(libdir)
libdrm_dove_la_LDFLAGS = -version-number 1:0:0 -no-undefined
libdrm_dove_la_LIBADD = @LIBDRM_LIBS@

libdrm_dove_la_SOURCES = \
	dove_bufmgr.c

libdrm_doveincludedir = ${includedir}/libdrm
libdrm_doveinclude_HEADERS = dove_bufmgr.h

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = libdrm_dove.pc
