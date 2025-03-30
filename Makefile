CC = gcc
CFLAGS = -Wall -Wextra


.PHONY: example tests cov clean

example: imfs.c example.c
	$(CC) $(CFLAGS) $^ -o $@

tests: CFLAGS += -g -O0
tests: tests.c imfs.c
	$(CC) $(CFLAGS) $^ -o $@
	./$@

cov: CFLAGS += -fprofile-arcs -ftest-coverage
cov: tests
	@gcov tests-imfs.gcno
	@lcov --capture --directory . --output-file coverage.lcov
	@genhtml coverage.lcov --output-directory cov
	@rm -f *.gcda *.gcno *.gcov *.lcov

clean:
	rm -rf cov example tests *.o *.gcda *.gcno *.gcov *.lcov