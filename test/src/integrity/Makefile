CFLAGS:=-g -O2 -pipe -std=c99 -static

all:
	$(CC) $(CFLAGS) -c sha1.c -o sha1.o
	$(CC) $(CFLAGS) -c util.c -o util.o
	$(CC) $(CFLAGS) sender.c sha1.o util.o -o sender
	$(CC) $(CFLAGS) receiver.c sha1.o util.o -o receiver

clean:
	rm -f *.o sender receiver

