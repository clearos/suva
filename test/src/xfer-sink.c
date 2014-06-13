#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>

#define FILE_OUTPUT "/tmp/xfer-sink.dat"

int main(int argc, char *argv[])
{
	signal(SIGTERM, SIG_IGN);
	size_t chunk_size = getpagesize();
	uint8_t buffer[chunk_size];
	ssize_t bytes, total = 0;
	char tick = '.';
	//fcntl(0, F_SETFL, O_NONBLOCK);
	FILE *fh = fopen(FILE_OUTPUT, "w+");
	for ( ;; ) {
		bytes = read(0, buffer, chunk_size);
		if (bytes == 0) {
			//fprintf(stdout, "\nEnd-of-file.\n");
			break;
		}
		else if (bytes == -1) {
			//fprintf(stdout, "\nRead error: %s.\n", strerror(errno));
			break;
		}
		//fputc('.', stdout);
		//fflush(stdout);
		total += bytes;
		fwrite(buffer, 1, bytes, fh);
		fflush(fh);
	}
	//fprintf(stdout, "\n%ld bytes read\n", total);
	fclose(fh);

	exit(0);
}

/*
 * vi: ts=4
 * */
