HEADERS=interfaces
SRC=src
TEST=test

HFILES=$(shell find $(HEADERS) -name '*.h' | sed 's/^.\///')

FILES=$(shell find $(SRC) -name '*.c' | sed 's/^.\///')
OFILES=$(patsubst %.c,./%.o,$(FILES))

TESTFILES=$(shell find $(TEST) -name '*.c' | sed 's/^.\///')
OTESTFILES=$(patsubst %.c,./%.o,$(TESTFILES))

CFLAGS = -Wall -Wextra -pedantic -pedantic-errors -pthread \
	-fsanitize=address -g -std=c11 -D_POSIX_C_SOURCE=200112L $(MYCFLAGS)
TESTFLAGS = -lcheck -lrt -lm -lsubunit $(MYCFLAGS)

%.o: %.c $(HFILES)
	$(CC) -c -o $@ $< $(CFLAGS)

all: socks5d

socks5d: $(OFILES)
	$(CC) $(OFILES) $(CFLAGS)

# TEST NO FUNCIONA: hay que buscar la forma de pasarle argumentos tipo: 'make test buffer' para que compile buffer_test.c y buffer.c solamente
test: $(OFILES) $(OTESTFILES)
	$(CC) $(OFILES) $(OTESTFILES) $(CFLAGS) $(TESTFLAGS)

.PHONY: clean

clean: 
	rm -rf $(OFILES) $(OTESTFILES)