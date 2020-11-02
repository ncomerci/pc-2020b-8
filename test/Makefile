
CFLAGS = -lcheck -lrt -lm -lsubunit -D_POSIX_C_SOURCE=200112L -std=c11 -pthread

all: tests

tests: buffer_test auth_test
# test_hello test_request test_netutils test_selector test_stm

buffer_test: buffer_test.o ../src/buffer.c
	$(CC) buffer_test.c -o buffer_test.out $(CFLAGS)

auth_test: auth_test.o ../src/auth.c
	$(CC) auth_test.c ../src/auth.c ../src/buffer.c -o auth_test.out $(CFLAGS)

clean: 
	rm -rf *.o *.out