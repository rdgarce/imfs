CC = gcc
CFLAGS = -Wall -Wextra


.PHONY: default example tests cov clean

default: imfs.c
	$(CC) $(CFLAGS) -c $^

example: imfs.c example.c
	$(CC) $(CFLAGS) $^ -o $@

tests: CFLAGS += -fsanitize=address -g -O0
tests: tests.c imfs.c
	$(CC) $(CFLAGS) $^ -o $@
	./$@

cov: CFLAGS += -fprofile-arcs -ftest-coverage
cov: tests
	@gcov tests-ss.gcno
	@lcov --capture --directory . --output-file coverage.lcov
	@genhtml coverage.lcov --output-directory cov
	@rm -f *.gcda *.gcno *.gcov *.lcov

clean:
	rm -rf cov example tests *.o *.gcda *.gcno