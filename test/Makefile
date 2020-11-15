
CFLAGS = -lcheck -lrt -lm -lsubunit -D_POSIX_C_SOURCE=200112L -std=c11 -pthread

all: tests

tests: buffer_test auth_test test_hello test_request
# test_netutils
buffer_test: buffer_test.o ../src/buffer.c
	$(CC) buffer_test.c -o buffer_test.out $(CFLAGS)

auth_test: auth_test.o ../src/auth.c
	$(CC) auth_test.c ../src/auth.c ../src/buffer.c -o auth_test.out $(CFLAGS)

test_hello: hello_test.o 
	$(CC) hello_test.c ../src/hello.c ../src/buffer.c -o hello_test.out $(CFLAGS)

test_request: request_test.o 
	$(CC) request_test.c ../src/request.c ../src/buffer.c -o request_test.out $(CFLAGS)



clean: 
	rm -rf *.o *.out