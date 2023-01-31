CC=gcc
CFLAGS=-I. -Wall -Wextra -Werror -O2

perftest: perftest.o
	$(CC) $(CFLAGS) -o $@ $^
	
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< 
	
clean:
	rm -f *.o perftest
