ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CFLAGS = $(WARN_CFLAGS) @LIBDRM_CFLAGS@

libdrm_dove_la_LTLIBRARIES = libdrm_dove.la
libdrm_dove_ladir = $(libdir)
libdrm_dove_la_LDFLAGS = -version-info 2:0:0 -no-undefined
libdrm_dove_la_LIBADD = @LIBDRM_LIBS@ @CLOCK_LIB@

libdrm_dove_la_SOURCES = \
	dove_bufmgr.c \
	libdrm_lists.h

libdrm_doveincludedir = ${includedir}/libdrm
libdrm_doveinclude_HEADERS = dove_bufmgr.h

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = libdrm_dove.pc
