
AM_CFLAGS = ${apr_CFLAGS} ${apu_CFLAGS}
AM_LDFLAGS = ${apr_LDFLAGS} ${apu_LDFLAGS}

EXTRA_DIST = mod_multipart.c mod_multipart.h mod_multipart.spec README.md

all-local:
	$(APXS) -c $(DEF_LDLIBS) -Wc,"$(CFLAGS)" -Wc,"$(AM_CFLAGS)" -Wl,"$(LDFLAGS)" -Wl,"$(AM_LDFLAGS)" $(LIBS) @srcdir@/mod_multipart.c

install-exec-local: 
	mkdir -p $(DESTDIR)`$(APXS) -q LIBEXECDIR`
	$(APXS) -S LIBEXECDIR=$(DESTDIR)`$(APXS) -q LIBEXECDIR` -c -i $(DEF_LDLIBS) -Wc,"$(CFLAGS)" -Wc,"$(AM_CFLAGS)" -Wl,"$(LDFLAGS)" -Wl,"$(AM_LDFLAGS)" $(LIBS) @srcdir@/mod_multipart.c

