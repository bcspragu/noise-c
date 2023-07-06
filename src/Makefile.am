
SUBDIRS = protocol protobufs keys

lib_LIBRARIES = libnoise.a

bin_PROGRAMS = noise-test

noise_test_SOURCES = \
	noise-c.c

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/include/noise/protocol
AM_CFLAGS = @WARNING_FLAGS@

LDADD = protocol/libnoiseprotocol.a

libnoise_a_SOURCES = \
	noise-c.c

if USE_LIBSODIUM
AM_CPPFLAGS += -DUSE_LIBSODIUM=1
AM_CFLAGS += $(libsodium_CFLAGS)
LDADD += $(libsodium_LIBS)
endif

if USE_OPENSSL
AM_CPPFLAGS += -DUSE_OPENSSL=1
AM_CFLAGS += $(openssl_CFLAGS)
LDADD += $(openssl_LIBS)
endif
