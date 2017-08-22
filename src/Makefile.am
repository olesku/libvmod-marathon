AM_CFLAGS = $(VARNISHAPI_CFLAGS) -Wall -Werror
AM_LDFLAGS = $(VARNISHAPI_LIBS) $(VMOD_LDFLAGS)

vmod_LTLIBRARIES = libvmod_marathon.la

libvmod_marathon_la_SOURCES = \
	vmod_marathon.c

nodist_libvmod_marathon_la_SOURCES = \
	vcc_marathon_if.c \
	vcc_marathon_if.h

dist_man_MANS = vmod_marathon.3

@BUILD_VMOD_MARATHON@

AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = -Dvmod_marathon="$(VMOD_MARATHON)"

TESTS = @VMOD_TESTS@

EXTRA_DIST = \
	vmod_marathon.vcc \
	$(VMOD_TESTS)
