/***************************************************************************************
   Project informations:
      Project:    bin2c
      Version:    1.00
      Plateforme: PC
      Copyright:  DNDD.INC
      Date:       28/03/2004

   File informations:
      Name:       bin2c.c
      Description:Convert any file to a C array

   Author informations:
      Author:     DOUALOT Nicolas
      E-Mail:     slubman@laposte.net
      site:       http://membres.lycos.fr/slubman/gp32
***************************************************************************************/


#include <stdio.h>				/*perror */
#include <sys/mman.h>			/*PROT_READ,MAP_xxx */
#include <fcntl.h>				/*O_RDONLY */
#include <sys/stat.h>			/*stat */
#include <stdlib.h>				/*atoi */
#include <string.h>				/*strcmp */
#include <ctype.h>				/*toupper */

#define VERSION "1.10"


static void help(void)
{
	fprintf(stdout, "\nbin2c v"VERSION"\n");
	fprintf(stdout, "Slubman DevSoft (c)2003-2004 slubman.dndd@laposte.net \n\n");

	fprintf(stdout, "Usage: bin2c [flags] <infile>\n\n");

	//fprintf(stdout, "\t-quiet      :\tdon't output standard messages\n");
	//fprintf(stdout, "\t-slash      :\tappend backslash at end of line\n");
	fprintf(stdout, "\t-n <count>  :\tnumber of items per line\n");
	fprintf(stdout, "\t-b1         :\tgenerate unsigned char array\n");
	fprintf(stdout, "\t-b2         :\tgenerate unsigned short  array\n");
	fprintf(stdout, "\t-b4         :\tgenerate unsigned long array\n");
	fprintf(stdout, "\t-a <name>   :\tgenerate an array with given name\n");
	fprintf(stdout, "\t-ss <nr>    :\tskip number of bytes at begin of inputfile\n");
	fprintf(stdout, "\t-se <nr>    :\tskip number of bytes at end of inputfile\n");
	fprintf(stdout, "\t-lb <nr>    :\tinsert an additionally linebreak every nr line\n");
	fprintf(stdout, "\t-h          :\tproduce an header\n");
	fprintf(stdout, "\tinfile      :\tname of infile\n");
	fprintf(stdout, "\toutfile     :\tname of outfile (use \"-\" for stdout)\n\n");

	fprintf(stdout, " \tconverts binary file to C array data\n");
}

static void UnknownFlag(char *flag)
{
	fprintf(stderr, "Error: unknown flag %s\n", flag);
	help();
	exit(EXIT_FAILURE);
}

static void WriteHeader(FILE * outFile, char *oFileName, char *iFileName)
{
	// File Header
	fprintf(outFile, "/***************************************************************************************\n");
	fprintf(outFile, "*   File Name:\n");
	fprintf(outFile, "*      Name:       %s\n", oFileName);
	fprintf(outFile, "*      From:       %s\n", iFileName);
	fprintf(outFile, "*      Created by :bin2c v"VERSION"\n*\n");
	fprintf(outFile, "*   bin2c v"VERSION":\n");
	fprintf(outFile, "*      Author:     DOUALOT Nicolas\n");
	fprintf(outFile, "*      E-Mail:     slubman.dndd@laposte.net\n");
	fprintf(outFile, "*      site:       http://www.slubman.linux-fan.com/\n");
	fprintf(outFile, "***************************************************************************************/\n\n");
}

int main(int argc, char *argv[])
{
	FILE *inFile = stdin, *outFile = stdout;
	int a, i, nbLine = 0;
	unsigned char *memory;
	struct stat st;

	// Options
	char arrayName[255] = "array";	// Array name
	char *iFileName = NULL;		// File to convert
	char *oFileName = NULL;		// File to write
	int bpd = 1;				// Array item length
	int lb = 0;					// Array blank line each lb line(s)
	int nbCol = 15;					// Nuber of items per line
	int SkeepStart = 0;			// Number of byte to skip at file begining
	int SkeepEnd = 0;			// Number of byte to skip at file end
	int header = 0;				// Produce an header

	// Is there the good number of arguments
	if (argc < 2)
	{
		help();
		return 0;
	}

	// On récupère les arguments (Ready for more options)
	for (a = 1; a < argc; a++)
	{
		// An option
		if (argv[a][0] == '-')
		{
			// Wich flag is it ?
			switch (argv[a][1])
			{
					// Writting on stdout
				case 0:
					printf("%s\n", argv[a]);
					outFile = stdout;
					break;

					// ArrayName flag
				case 'a':
					strcpy(arrayName, argv[++a]);
					break;

					// Data type
				case 'b':
					switch (argv[a][2])
					{
						case '1':
							bpd = 1;
							break;

						case '2':
							bpd = 2;
							break;

						case '4':
							bpd = 4;
							break;

						default:
							UnknownFlag(argv[a]);
					}
					break;

					// Produce an header
				case 'h':
					header = 1;
					break;

					// New line each n line
				case 'l':
					switch (argv[a][2])
					{
						case 'b':
							lb = atoi(argv[++a]);
							break;

						default:
							UnknownFlag(argv[a]);
					}

					// Number of bit per line
				case 'n':
					nbCol = atoi(argv[++a]);
					break;

					// Skip bytes
				case 's':
					switch (argv[a][2])
					{
							// Beginig of file
						case 's':
							SkeepStart = atoi(argv[++a]);
							break;

							// End of file
						case 'e':
							SkeepEnd = atoi(argv[++a]);
							break;

							// Flag inconnu
						default:
							UnknownFlag(argv[a]);
					}

					// Flag inconnu
				default:
					UnknownFlag(argv[a]);
			}
		}
		// A filename
		else
		{
			if (iFileName == NULL)
			{
				iFileName = argv[a];
				if ((inFile = fopen(iFileName, "rb")) == NULL)
				{
					fprintf(stderr, "Error: can't open %s\n", iFileName);
					exit(EXIT_FAILURE);
				}
			}
			else
			{
				if (oFileName == NULL)
				{
					oFileName = argv[a];
					if ((outFile = fopen(oFileName, "wb")) == NULL)
					{
						fprintf(stderr, "Error: can't open %s\n", oFileName);
						exit(EXIT_FAILURE);
					}
				}
				else
				{
					fprintf(stderr, "Error: Too many filesnames given!\n");
					help();
					exit(EXIT_FAILURE);
				}
			}
		}
	}

	if (!iFileName)
		exit(EXIT_FAILURE);

	// Get file informations
	if (stat(iFileName, &st) != 0)
	{
		fprintf(stderr, "Error: when scanning file %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	// Allocating memory
	if (!(memory = malloc(st.st_size + 3)))
	{
		memset(memory, 0, st.st_size + 3);
		fprintf(stderr, "Error: not enought memory\n");
		exit(EXIT_FAILURE);
	}

	// Reading the file
	if (fread(memory, 1, st.st_size, inFile) != (size_t)st.st_size)
	{
		fprintf(stderr, "Error: when reading file %s\n", argv[1]);
		fclose(inFile);
		exit(EXIT_FAILURE);
	}
	fclose(inFile);

	// Must produce an header
	if (header)
	{
		unsigned int i;
		char hFileName[256], *def = NULL;
		FILE *hFile = stdout;

		if (oFileName)
		{
			strcpy(hFileName, oFileName);
			hFileName[strlen(hFileName) - 1] = 'h';
			hFile = fopen(hFileName, "wt");
		}

		WriteHeader(hFile, hFileName, iFileName);

		// Replace all '.' by '_'
		for (i = 0; i < strlen(hFileName); i++)
			if (hFileName[i] == '.')
				hFileName[i] = '_';
			else
				hFileName[i] = toupper(hFileName[i]);

		// the #ifdef at the begining
		def = strrchr(hFileName, '/');
		def = def ? def + 1 : hFileName;
		fprintf(hFile, "#ifndef __%s__\n#define __%s__\n\n", def, def);

		// Define array size
		fprintf(hFile, "#define _%s_size_ %u\n\n", arrayName, (unsigned int) (st.st_size - SkeepStart - SkeepEnd) / bpd);

		// Begin the array
		fprintf(hFile, "extern unsigned ");
		fprintf(hFile, "%s ", bpd == 1 ? "char" : bpd == 2 ? "short" : "long");
		fprintf(hFile, "%s[", arrayName);
		fprintf(hFile, "%u];\n\n", (unsigned int) (st.st_size - SkeepStart - SkeepEnd) / bpd);

		// the #endif at the end
		fprintf(hFile, "#endif\n\n");

		if (oFileName)
			fclose(hFile);
	}

	WriteHeader(outFile, oFileName, iFileName);

	// Define array size
	if (!header)
		fprintf(outFile, "#define _%s_size_ %u\n\n", arrayName, (unsigned int) (st.st_size - SkeepStart - SkeepEnd) / bpd);

	// Begin the array
	fprintf(outFile, "unsigned ");
	fprintf(outFile, "%s ", bpd == 1 ? "char" : bpd == 2 ? "short" : "long");
	fprintf(outFile, "%s[", arrayName);
	fprintf(outFile, "%u] = {\n\t", (unsigned int) (st.st_size - SkeepStart - SkeepEnd) / bpd);

	// Writing file elements
	for (i = 0; i < (st.st_size - SkeepEnd - SkeepStart) / bpd; /*i+=bpd */ i++)
	{
		// We write an item of bpd byte(s)
		switch (bpd)
		{
			case 1:
				fprintf(outFile, "0x%02x", *(unsigned char *) &memory[SkeepStart + i]);
				break;

			case 2:
				fprintf(outFile, "0x%04x", *(unsigned short *) &memory[SkeepStart + i]);
				break;

			case 4:
				fprintf(outFile, "0x%08lx", *(unsigned long *) &memory[SkeepStart + i]);
				break;
		}

		// Must put a coma ?
		if (i != st.st_size - 1)
			fprintf(outFile, ",");

		// End of a line ?
		if (i && !((i + 1) % nbCol))
		{
			// -lb option
			if (lb && !((++nbLine) % lb))
				fprintf(outFile, "\n");
			fprintf(outFile, "\n\t");
		}
		// Add a space
		else
			fprintf(outFile, " ");
	}

	// The last line as nbCol elements
	if (((st.st_size - SkeepStart - SkeepEnd) / bpd) % nbCol)
		fprintf(outFile, "\n");

	// Close the array
	fprintf(outFile, "};\n");

	// CLose the output file
	if (outFile != stdout)
		fclose(outFile);

	// Free allocated memory
	free(memory);

	exit(EXIT_SUCCESS);
}
