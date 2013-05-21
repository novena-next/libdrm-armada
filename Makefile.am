ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CFLAGS = $(WARN_CFLAGS) @LIBDRM_CFLAGS@

libdrm_armada_la_LTLIBRARIES = libdrm_armada.la
libdrm_armada_ladir = $(libdir)
libdrm_armada_la_LDFLAGS = -version-info 0:0:0 -no-undefined
libdrm_armada_la_LIBADD = @LIBDRM_LIBS@ @CLOCK_LIB@

libdrm_armada_la_SOURCES = \
	armada_bufmgr.c \
	libdrm_lists.h

libdrm_armadaincludedir = ${includedir}/libdrm
libdrm_armadainclude_HEADERS = armada_bufmgr.h

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = libdrm_armada.pc
