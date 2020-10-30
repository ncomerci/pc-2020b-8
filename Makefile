CFLAGS = -Wall -Wextra -pedantic -pedantic-errors \
	-fsanitize=address -g -std=c11 -D_POSIX_C_SOURCE=200112L $(MYCFLAGS)

# CFLAGS = -Wall -Wextra -Werror -Wno-unused-parameter \
#    -pedantic -pedantic-errors -std=c11 -g -D_POSIX_C_SOURCE=200112L -O3 \
#    -fsanitize=address $(MYCFLAGS)

all: socks5d

buffer.o: buffer.h
hello.o: hello.h
netutils.o: netutils.h
# TODO: add main.o
SOCKS5D_OBJ: buffer.o hello.o netutils.o 
socks5d: $(SOCKS5D_OBJ)
	$(CC) $(SOCKS5D_OBJ) $(CFLAGS) -lpthread 

.PHONY: clean

clean: 
	rm -rf $(SOCKS5D_OBJ) 

