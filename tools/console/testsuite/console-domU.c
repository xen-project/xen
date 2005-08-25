/* Written by Anthony Liguori <aliguori@us.ibm.com> */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>

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
	int i;
	int runs;
	struct termios term;

	tcgetattr(STDIN_FILENO, &term);
	cfmakeraw(&term);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);

	tcgetattr(STDOUT_FILENO, &term);
	cfmakeraw(&term);
	tcsetattr(STDOUT_FILENO, TCSAFLUSH, &term);

	printf("!!!XEN Test Begin!!!\n"); fflush(stdout);
	line = fgets(buffer, sizeof(buffer), stdin);
	if (line == NULL) {
		printf("Failure\n"); fflush(stdout);
		return 1;
	}

	canonicalize(line);
	seed = strtoul(line, 0, 0);

	printf("Seed Okay.\n"); fflush(stdout);

	srandom(seed);

	for (runs = (random() % 100000) + 4096; runs > 0; runs--) {
		size = random() % 4096;

		for (i = 0; i < size; i++) {
			int ch;
			int exp;

			ch = fgetc(stdin);
			exp = random() & 0xFF;
			if (ch != exp) {
				printf("Expected %d got %d\n",
				       exp, ch);
				fflush(stdout);
			}
			printf("Got %d/%d good bytes\n", i, size);
		}
		
		printf("Okay.\n"); fflush(stdout);
	}

	return 0;
}
