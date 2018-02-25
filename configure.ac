AC_PREREQ([2.68])
AC_INIT([libvmod-marathon], [0.1], [], [vmod-marathon])
AC_COPYRIGHT([Copyright (c) 2017 Ole Fredrik Skudsvik <ole.skudsvik@gmail.com>])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR(src/vmod_marathon.vcc)
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE([1.12 -Wall -Werror foreign parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

AX_PTHREAD(,[AC_MSG_ERROR([Could not configure pthreads support])])

LIBS="$PTHREAD_LIBS $LIBS -lcurl -lyajl"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AC_ARG_WITH([rst2man],
	AS_HELP_STRING(
		[--with-rst2man=PATH],
		[Location of rst2man (auto)]),
	[RST2MAN="$withval"],
	AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], []))

m4_ifndef([VARNISH_PREREQ], AC_MSG_ERROR([Need varnish.m4 -- see README.rst]))

VARNISH_PREREQ([4.1])
VARNISH_VMODS([marathon])

VMOD_TESTS="$(cd $srcdir/src && echo tests/*.vtc)"
AC_SUBST(VMOD_TESTS)

PKG_CHECK_VAR([LIBVARNISHAPI_LIBDIR], [varnishapi], [libdir])
AC_SUBST([VARNISH_LIBRARY_PATH],
	[$LIBVARNISHAPI_LIBDIR:$LIBVARNISHAPI_LIBDIR/varnish])

# Macro: AS_VERSION_COMPARE (version-1, version-2, [action-if-less], [action-if-equal], [action-if-greater])

AS_VERSION_COMPARE([$VARNISH_VERSION], [5.0], [
	AC_DEFINE([HAVE_VCL_EVENT_USE], [1], [Define if USE events are sent.])])

AS_VERSION_COMPARE([$VARNISH_VERSION], [5.0], [], [
	AC_DEFINE([HAVE_BACKEND_PROXY], [1], [Define if backends support PROXY.])], [
	AC_DEFINE([HAVE_BACKEND_PROXY], [1], [Define if backends support PROXY.])])

AS_VERSION_COMPARE([$VARNISH_VERSION], [5.2], [], [
  AC_DEFINE([HAVE_VSC_LCK], [1], [Define if we have VSC_lck function.])], [
  AC_DEFINE([HAVE_VSC_LCK], [1], [Define if we have VSC_lck function.])])

AS_VERSION_COMPARE([$VARNISH_VERSION], [5.2], [], [
  AC_DEFINE([HAVE_LCK_DESTROYCLASS], [1], [Define if we have Lck_DestroyClass function.])], [
  AC_DEFINE([HAVE_LCK_DESTROYCLASS], [1], [Define if we have Lck_DestroyClass function.])])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
