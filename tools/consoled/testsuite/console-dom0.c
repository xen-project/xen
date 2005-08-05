/* Written by Anthony Liguori <aliguori@us.ibm.com> */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

static void generate_random_buffer(char *buffer, size_t size)
{
	int i;

	for (i = 0; i < size; i++) {
		buffer[i] = random() & 0xFF;
	}
}

static void canonicalize(char *buffer)
{
	char *reader, *writer;

	reader = writer = buffer;

	while (*reader) {
		*writer = *reader;
		if (*reader != '\r') writer++;
		reader++;
	}
	*writer = *reader;
}

int main(int argc, char **argv)
{
	char buffer[4096];
	char *line;
	unsigned int seed;
	size_t size;
	int runs;
	unsigned long long total_bytes = 0;
	struct termios term;

	tcgetattr(STDIN_FILENO, &term);
	cfmakeraw(&term);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);

	tcgetattr(STDOUT_FILENO, &term);
	cfmakeraw(&term);
	tcsetattr(STDOUT_FILENO, TCSAFLUSH, &term);

	while ((line = fgets(buffer, sizeof(buffer), stdin))) {
		canonicalize(line);

		if (strcmp(line, "!!!XEN Test Begin!!!\n") == 0) {
			break;
		} else {
			fprintf(stderr, "%s", line);
		}
	}

	if (line == NULL) {
		fprintf(stderr, "Client never sent start string.\n");
		return 1;
	}

	seed = time(0);

	printf("%u\n", seed); fflush(stdout);

	fprintf(stderr, "Waiting for seed acknowledgement\n");
	line = fgets(buffer, sizeof(buffer), stdin);
	if (line == NULL) {
		fprintf(stderr, "Client never acknowledge seed.\n");
		return 1;
	}

	canonicalize(line);
	if (strcmp(line, "Seed Okay.\n") != 0) {
		fprintf(stderr, "Incorrect seed acknowledgement.\n");
		fprintf(stderr, "[%s]", line);
		return 1;
	} else {
		fprintf(stderr, "Processed seed.\n");
	}

	srandom(seed);

	for (runs = (random() % 100000) + 4096; runs > 0; runs--) {

		size = random() % 4096;

		fprintf(stderr, "Writing %d bytes.\n", size);

		generate_random_buffer(buffer, size);
		fwrite(buffer, size, 1, stdout);
		fflush(stdout);

		do {
			line = fgets(buffer, sizeof(buffer), stdin);
			if (line == NULL) {
				fprintf(stderr, "Premature EOF from client.\n");
				return 1;
			}

			canonicalize(line);
			fprintf(stderr, "%s", line);
		} while (strcmp(line, "Okay.\n") != 0);

		total_bytes += size;
	}

	fprintf(stderr, "PASS: processed %llu byte(s).\n", total_bytes);

	return 0;
}
