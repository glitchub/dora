override CFLAGS += -Wall -Werror -s -Wno-format-truncation

default:;$(MAKE) dora CFLAGS="-O3"

dora: dora.c options.c bitarray.c

clean:;rm dora

terse:;$(MAKE) dora CFLAGS="-DTERSE -Os"
