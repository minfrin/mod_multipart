#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([mod_multipart],[2.4.1],[minfrin@sharp.fm])
AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_FILES([Makefile mod_multipart.spec])
AC_CONFIG_SRCDIR([mod_multipart.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_ARG_WITH(apxs,
    [  --with-apxs=PATH        path to Apache apxs],
    [
        if test "$withval" = "yes"; then
            AC_PATH_PROGS(APXS, apxs apxs2, reject, $PATH:/usr/sbin)
        else
            APXS=$withval
            AC_SUBST(APXS)
        fi
    ],
    [
        AC_PATH_PROGS(APXS, apxs apxs2, reject, $PATH:/usr/sbin)
    ])
if test "$APXS" = "reject"; then
  AC_MSG_ERROR([Could not find apxs on the path.])
fi

# Make sure the Apache include files are found
CPPFLAGS="$CPPFLAGS -I`$APXS -q INCLUDEDIR`"
CFLAGS="$CFLAGS -I`$APXS -q INCLUDEDIR`"

# Checks for libraries.
PKG_CHECK_MODULES(apr, apr-1 >= 1.2)
PKG_CHECK_MODULES(apu, apr-util-1 >= 1.2)

CFLAGS="$CFLAGS $apr_CFLAGS $apu_CFLAGS"
CPPFLAGS="$CPPFLAGS $apr_CPPFLAGS $apu_CPPFLAGS"
LDFLAGS="$LDFLAGS $apr_LDFLAGS $apu_LDFLAGS"
LIBS="$LIBS $apr_LIBS $apu_LIBS"

# Checks for header files.
AC_CHECK_HEADERS(sys/xattr.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([apr_brigade_split_boundary])

AC_SUBST(PACKAGE_VERSION)
AC_OUTPUT
