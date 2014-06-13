#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define LEN	104857600L

int main(int argc, char *argv[])
{
	long i;
	unsigned char c = 0;

	for (i = 0L; i < LEN; i++) {
		fwrite(&c, 1, 1, stdout);
		c++;
	}

	return 0;
}
