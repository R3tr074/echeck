BINDIR := bin
BINS=$(patsubst %.c,$(BINDIR)/%,$(wildcard *.c))
SOURCE=../../src/elf.c ../../src/utils.c ../../src/view.c
CFLAGS+=-I../../src/include/
CFLAGS+=-g
ifeq ($(ASAN),1)
	ASAN_LD_PRELOAD=LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.5
else
	ASAN_LD_PRELOAD=
endif

all: $(BINS)

$(BINDIR)/%: %.c
	mkdir -p "$(BINDIR)"
	$(CC) $(SOURCE) $< -o $@ $(CFLAGS) $(LDFLAGS)

run:
	r=0 ; cd .. ; for a in $(BINS) ; do $(ASAN_LD_PRELOAD) ./unit/$$a || r=1; done ; echo unit$$r ; exit $$r

clean:
	rm -rf "$(BINDIR)"

.PHONY: all