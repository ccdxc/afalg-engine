plugin_LTLIBRARIES = libafalg.la

libafalg_la_SOURCES = \
	ciphers.c \
	digests.c \
	e_afalg.c \
	e_afalg.h

libafalg_la_CFLAGS = $(OPENSSL_CFLAGS)
libafalg_la_LIBADD = $(OPENSSL_LIBS)
libafalg_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS)
libafalg_la_LIBTOOLFLAGS = --tag=disable-static

noinst_HEADERS = \
	e_afalg.h
