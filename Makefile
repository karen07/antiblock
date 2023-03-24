CC=gcc
CFLAGS=-I. -I./include/ -Wall -Wextra -Werror -O2

antiblock: antiblock.o dns_ans.o net_data.o route.o stat.o ttl_check.o urls_read.o hash.o hashmap/array_hashmap.a
	$(CC) $(CFLAGS) -o $@ $^
	
perftest:
	make -C test

hashmap/array_hashmap.a:
	make -C hashmap

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< 
	
clean:
	rm -f *.o antiblock
