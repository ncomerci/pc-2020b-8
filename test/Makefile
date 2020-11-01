
CFLAGS = -lcheck -lrt -lm -lsubunit -D_POSIX_C_SOURCE=200112L -std=c11 -pthread

all: tests

tests: buffer_test 
# test_hello test_request test_netutils test_selector test_stm

buffer_test: buffer_test.o ../src/buffer.c
	$(CC) $(CFLAGS) -o buffer_test.out

clean: 
	rm -rf *.o *.out