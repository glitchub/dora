override CFLAGS += -Wall -Werror -Os -s

dora: dora.c options.c bitarray.c

clean:;rm dora

terse:;$(MAKE) dora CFLAGS=-DTERSE
