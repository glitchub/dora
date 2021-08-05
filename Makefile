override CFLAGS += -Wall -Werror -Os -s -Wno-format-truncation

default: dora

dora: dora.c options.c bitarray.c

clean:;rm dora

terse:;$(MAKE) CFLAGS=-DTERSE
