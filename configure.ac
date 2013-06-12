AC_PREREQ([2.63])
AC_INIT([libdrm_armada], [2.0.0], [], [libdrm_armada])

AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.10 foreign dist-bzip2])
AM_MAINTAINER_MODE([enable])

# Enable quiet compiles on automake 1.11.
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Check for programs
AC_PROG_CC

AC_USE_SYSTEM_EXTENSIONS

# Initialize libtool
LT_PREREQ([2.2])
LT_INIT([disable-static])

AC_CHECK_FUNCS([clock_gettime], [CLOCK_LIB=],
               [AC_CHECK_LIB([rt], [clock_gettime], [CLOCK_LIB=-lrt],
                             [AC_MSG_ERROR([Could not find clock_gettime])])])
AC_SUBST([CLOCK_LIB])

PKG_CHECK_MODULES(LIBDRM, [libdrm >= 2.4.38])
AC_SUBST(LIBDRM_CFLAGS)
AC_SUBST(LIBDRM_LIBS)

pkgconfigdir=${libdir}/pkgconfig
AC_SUBST(pkgconfigdir)

AC_CONFIG_FILES([
	Makefile
	libdrm_armada.pc
])
AC_OUTPUT
