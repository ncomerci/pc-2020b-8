HEADERS=includes
SRC=src

HFILES=$(shell find $(HEADERS) -name '*.h' | sed 's/^.\///')

FILES=$(shell find $(SRC) -name '*.c' | sed 's/^.\///')
OFILES=$(patsubst %.c,./%.o,$(FILES))

CFLAGS = -Wall -Wextra -pedantic -pedantic-errors \
	-fsanitize=address -g -std=c11 -D_POSIX_C_SOURCE=200112L $(MYCFLAGS)

%.o: %.c $(HFILES)
	$(CC) -c -o $@ $< $(CFLAGS)

all: socks5d tests

socks5d: $(OFILES)
	$(CC) $(OFILES) $(CFLAGS) -o socks5d

tests: 
	cd test; make all;

.PHONY: clean

clean: 
	rm -rf $(OFILES); cd test; make clean;