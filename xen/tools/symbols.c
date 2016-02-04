/* Generate assembler source containing symbol information
 *
 * Copyright 2002       by Kai Germaschewski
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 *
 * Usage: nm -n vmlinux | scripts/symbols [--all-symbols] > symbols.S
 *
 * ChangeLog:
 *
 * (25/Aug/2004) Paulo Marques <pmarques@grupopie.com>
 *      Changed the compression method from stem compression to "table lookup"
 *      compression
 *
 *      Table compression uses all the unused char codes on the symbols and
 *  maps these to the most used substrings (tokens). For instance, it might
 *  map char code 0xF7 to represent "write_" and then in every symbol where
 *  "write_" appears it can be replaced by 0xF7, saving 5 bytes.
 *      The used codes themselves are also placed in the table so that the
 *  decompresion can work without "special cases".
 *      Applied to kernel symbols, this usually produces a compression ratio
 *  of about 50%.
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#define KSYM_NAME_LEN		127


struct sym_entry {
	unsigned long long addr;
	unsigned int len;
	unsigned char *sym;
	char *orig_symbol;
	unsigned int addr_idx;
	unsigned int stream_offset;
	unsigned char type;
};
#define SYMBOL_NAME(s) ((char *)(s)->sym + 1)

static struct sym_entry *table;
static unsigned int table_size, table_cnt;
static unsigned long long _stext, _etext, _sinittext, _einittext, _sextratext, _eextratext;
static int all_symbols = 0;
static int sort_by_name = 0;
static int map_only = 0;
static char symbol_prefix_char = '\0';
static enum { fmt_bsd, fmt_sysv } input_format;
static int compare_name(const void *p1, const void *p2);

int token_profit[0x10000];

/* the table that holds the result of the compression */
unsigned char best_table[256][2];
unsigned char best_table_len[256];


static void usage(void)
{
	fprintf(stderr, "Usage: symbols [--all-symbols] [--symbol-prefix=<prefix char>] < in.map > out.S\n");
	exit(1);
}

/*
 * This ignores the intensely annoying "mapping symbols" found
 * in ARM ELF files: $a, $t and $d.
 */
static inline int is_arm_mapping_symbol(const char *str)
{
	return str[0] == '$' && strchr("atd", str[1])
	       && (str[2] == '\0' || str[2] == '.');
}

static int read_symbol(FILE *in, struct sym_entry *s)
{
	char str[500], type[20] = "";
	char *sym, stype;
	static enum { symbol, single_source, multi_source } last;
	static char *filename;
	int rc = -1;

	switch (input_format) {
	case fmt_bsd:
		rc = fscanf(in, "%llx %c %499s\n", &s->addr, &stype, str);
		break;
	case fmt_sysv:
		while (fscanf(in, "\n") == 1)
			/* nothing */;
		rc = fscanf(in, "%499[^ |] |%llx | %c |",
			    str, &s->addr, &stype);
		if (rc == 3 && fscanf(in, " %19[^ |] |", type) != 1)
			*type = '\0';
		break;
	}
	if (rc != 3) {
		if (rc != EOF) {
			/* skip line */
			if (fgets(str, 500, in) == NULL)
				return -1; /* must check fgets result */
		}
		return -1;
	}

	sym = strrchr(str, '.');
	if (strcasecmp(type, "FILE") == 0 ||
	    (/*
	      * GNU nm prior to binutils commit 552e55ed06 (expected to
	      * appear in 2.27) doesn't produce a type for EFI binaries.
	      */
	     input_format == fmt_sysv && !*type && stype == '?' && sym &&
	     sym[1] && strchr("cSsoh", sym[1]) && !sym[2])) {
		/*
		 * gas prior to binutils commit fbdf9406b0 (expected to appear
		 * in 2.27) outputs symbol table entries resulting from .file
		 * in reverse order. If we get two consecutive file symbols,
		 * prefer the first one if that names an object file or has a
		 * directory component (to cover multiply compiled files).
		 */
		bool multi = strchr(str, '/') || (sym && sym[1] == 'o');

		if (multi || last != multi_source) {
			free(filename);
			filename = *str ? strdup(str) : NULL;
		}
		last = multi ? multi_source : single_source;
		goto skip_tail;
	}

	last = symbol;
	rc = -1;

	sym = str;
	/* skip prefix char */
	if (symbol_prefix_char && str[0] == symbol_prefix_char)
		sym++;

	/* Ignore most absolute/undefined (?) symbols. */
	if (strcmp(sym, "_stext") == 0)
		_stext = s->addr;
	else if (strcmp(sym, "_etext") == 0)
		_etext = s->addr;
	else if (strcmp(sym, "_sinittext") == 0)
		_sinittext = s->addr;
	else if (strcmp(sym, "_einittext") == 0)
		_einittext = s->addr;
	else if (strcmp(sym, "_sextratext") == 0)
		_sextratext = s->addr;
	else if (strcmp(sym, "_eextratext") == 0)
		_eextratext = s->addr;
	else if (toupper((uint8_t)stype) == 'A')
	{
		/* Keep these useful absolute symbols */
		if (strcmp(sym, "__gp"))
			goto skip_tail;
	}
	else if (toupper((uint8_t)stype) == 'U' ||
		 toupper((uint8_t)stype) == 'N' ||
		 is_arm_mapping_symbol(sym))
		goto skip_tail;
	/* exclude also MIPS ELF local symbols ($L123 instead of .L123) */
	else if (str[0] == '$')
		goto skip_tail;

	/* include the type field in the symbol name, so that it gets
	 * compressed together */
	s->len = strlen(str) + 1;
	if (islower(stype) && filename)
		s->len += strlen(filename) + 1;
	s->sym = malloc(s->len + 1);
	sym = SYMBOL_NAME(s);
	if (islower(stype) && filename) {
		sym = stpcpy(sym, filename);
		*sym++ = '#';
	}
	strcpy(sym, str);
	if (sort_by_name || map_only) {
		s->orig_symbol = strdup(SYMBOL_NAME(s));
		s->type = stype; /* As s->sym[0] ends mangled. */
	}
	s->sym[0] = stype;
	rc = 0;

 skip_tail:
	if ((input_format == fmt_sysv) && fgets(str, 500, in) == NULL)
		/* ignore errors while discarding rest of line */;

	return rc;
}

static int symbol_valid(struct sym_entry *s)
{
	int offset = 1;

	/* skip prefix char */
	if (symbol_prefix_char && *(s->sym + 1) == symbol_prefix_char)
		offset++;

	/* if --all-symbols is not specified, then symbols outside the text
	 * and inittext sections are discarded */
	if (!all_symbols) {
		if ((s->addr < _stext || s->addr > _etext)
		    && (s->addr < _sinittext || s->addr > _einittext)
		    && (s->addr < _sextratext || s->addr > _eextratext))
			return 0;
		/* Corner case.  Discard any symbols with the same value as
		 * _etext _einittext or _eextratext; they can move between pass
		 * 1 and 2 when the symbols data are added.  If these symbols
		 * move then they may get dropped in pass 2, which breaks the
		 * symbols rules.
		 */
		if ((s->addr == _etext && strcmp((char*)s->sym + offset, "_etext")) ||
		    (s->addr == _einittext && strcmp((char*)s->sym + offset, "_einittext")) ||
		    (s->addr == _eextratext && strcmp((char*)s->sym + offset, "_eextratext")))
			return 0;
	}

	/* Exclude symbols which vary between passes. */
	if (strstr((char *)s->sym + offset, "_compiled."))
		return 0;

	return 1;
}

static void read_map(FILE *in)
{
	while (!feof(in)) {
		if (table_cnt >= table_size) {
			table_size += 10000;
			table = realloc(table, sizeof(*table) * table_size);
			if (!table) {
				fprintf(stderr, "out of memory\n");
				exit (1);
			}
		}
		if (read_symbol(in, &table[table_cnt]) == 0)
			table_cnt++;
	}
}

static void output_label(char *label)
{
	if (symbol_prefix_char)
		printf(".globl %c%s\n", symbol_prefix_char, label);
	else
		printf(".globl %s\n", label);
	printf("\tALGN\n");
	if (symbol_prefix_char)
		printf("%c%s:\n", symbol_prefix_char, label);
	else
		printf("%s:\n", label);
}

/* uncompress a compressed symbol. When this function is called, the best table
 * might still be compressed itself, so the function needs to be recursive */
static int expand_symbol(unsigned char *data, int len, char *result)
{
	int c, rlen, total=0;

	while (len) {
		c = *data;
		/* if the table holds a single char that is the same as the one
		 * we are looking for, then end the search */
		if (best_table[c][0]==c && best_table_len[c]==1) {
			*result++ = c;
			total++;
		} else {
			/* if not, recurse and expand */
			rlen = expand_symbol(best_table[c], best_table_len[c], result);
			total += rlen;
			result += rlen;
		}
		data++;
		len--;
	}
	*result=0;

	return total;
}

/* Sort by original (non mangled) symbol name, then type. */
static int compare_name_orig(const void *p1, const void *p2)
{
	const struct sym_entry *sym1 = p1;
	const struct sym_entry *sym2 = p2;
	int rc;

	rc = strcmp(sym1->orig_symbol, sym2->orig_symbol);

	if (!rc)
		rc = sym1->type - sym2->type;

	return rc;
}

static void write_src(void)
{
	unsigned int i, k, off;
	unsigned int best_idx[256];
	unsigned int *markers;
	char buf[KSYM_NAME_LEN+1];

	if (map_only) {
		for (i = 0; i < table_cnt; i++)
			printf("%#llx %c %s\n", table[i].addr, table[i].type,
						table[i].orig_symbol);

		return;
	}
	printf("#include <xen/config.h>\n");
	printf("#include <asm/types.h>\n");
	printf("#if BITS_PER_LONG == 64 && !defined(SYMBOLS_ORIGIN)\n");
	printf("#define PTR .quad\n");
	printf("#define ALGN .align 8\n");
	printf("#else\n");
	printf("#define PTR .long\n");
	printf("#define ALGN .align 4\n");
	printf("#endif\n");

	printf("\t.section .rodata, \"a\"\n");

	printf("#ifndef SYMBOLS_ORIGIN\n");
	printf("#define SYMBOLS_ORIGIN 0\n");
	output_label("symbols_addresses");
	printf("#else\n");
	output_label("symbols_offsets");
	printf("#endif\n");
	for (i = 0; i < table_cnt; i++) {
		printf("\tPTR\t%#llx - SYMBOLS_ORIGIN\n", table[i].addr);
	}
	printf("\n");

	output_label("symbols_num_syms");
	printf("\t.long\t%d\n", table_cnt);
	printf("\n");

	/* table of offset markers, that give the offset in the compressed stream
	 * every 256 symbols */
	markers = (unsigned int *) malloc(sizeof(unsigned int) * ((table_cnt + 255) / 256));

	output_label("symbols_names");
	off = 0;
	for (i = 0; i < table_cnt; i++) {
		if ((i & 0xFF) == 0)
			markers[i >> 8] = off;

		printf("\t.byte 0x%02x", table[i].len);
		for (k = 0; k < table[i].len; k++)
			printf(", 0x%02x", table[i].sym[k]);
		printf("\n");

		table[i].stream_offset = off;
		off += table[i].len + 1;
	}
	printf("\n");

	output_label("symbols_markers");
	for (i = 0; i < ((table_cnt + 255) >> 8); i++)
		printf("\t.long\t%d\n", markers[i]);
	printf("\n");


	output_label("symbols_token_table");
	off = 0;
	for (i = 0; i < 256; i++) {
		best_idx[i] = off;
		expand_symbol(best_table[i], best_table_len[i], buf);
		printf("\t.asciz\t\"%s\"\n", buf);
		off += strlen(buf) + 1;
	}
	printf("\n");

	output_label("symbols_token_index");
	for (i = 0; i < 256; i++)
		printf("\t.short\t%d\n", best_idx[i]);
	printf("\n");

	if (!sort_by_name) {
		free(markers);
		return;
	}

	/* Sorted by original symbol names and type. */
	qsort(table, table_cnt, sizeof(*table), compare_name_orig);

	output_label("symbols_sorted_offsets");
	/* A fixed sized array with two entries: offset in the
	 * compressed stream (for symbol name), and offset in
	 * symbols_addresses (or symbols_offset). */
	for (i = 0; i < table_cnt; i++) {
		printf("\t.long %u, %u\n", table[i].stream_offset, table[i].addr_idx);
	}
	printf("\n");

	free(markers);
}


/* table lookup compression functions */

/* count all the possible tokens in a symbol */
static void learn_symbol(unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]++;
}

/* decrease the count for all the possible tokens in a symbol */
static void forget_symbol(unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]--;
}

/* remove all the invalid symbols from the table and do the initial token count */
static void build_initial_tok_table(void)
{
	unsigned int i, pos;

	pos = 0;
	for (i = 0; i < table_cnt; i++) {
		if ( symbol_valid(&table[i]) ) {
			if (pos != i)
				table[pos] = table[i];
			learn_symbol(table[pos].sym, table[pos].len);
			pos++;
		}
	}
	table_cnt = pos;
}

static void *memmem_pvt(void *h, size_t hlen, void *n, size_t nlen)
{
	char *p;
	for (p = h; (p - (char *)h) <= (long)(hlen - nlen); p++)
		if (!memcmp(p, n, nlen)) return p;
	return NULL;
}

/* replace a given token in all the valid symbols. Use the sampled symbols
 * to update the counts */
static void compress_symbols(unsigned char *str, int idx)
{
	unsigned int i, len, size;
	unsigned char *p1, *p2;

	for (i = 0; i < table_cnt; i++) {

		len = table[i].len;
		p1 = table[i].sym;

		table[i].addr_idx = i;
		/* find the token on the symbol */
		p2 = memmem_pvt(p1, len, str, 2);
		if (!p2) continue;

		/* decrease the counts for this symbol's tokens */
		forget_symbol(table[i].sym, len);

		size = len;

		do {
			*p2 = idx;
			p2++;
			size -= (p2 - p1);
			memmove(p2, p2 + 1, size);
			p1 = p2;
			len--;

			if (size < 2) break;

			/* find the token on the symbol */
			p2 = memmem_pvt(p1, size, str, 2);

		} while (p2);

		table[i].len = len;

		/* increase the counts for this symbol's new tokens */
		learn_symbol(table[i].sym, len);
	}
}

/* search the token with the maximum profit */
static int find_best_token(void)
{
	int i, best, bestprofit;

	bestprofit=-10000;
	best = 0;

	for (i = 0; i < 0x10000; i++) {
		if (token_profit[i] > bestprofit) {
			best = i;
			bestprofit = token_profit[i];
		}
	}
	return best;
}

/* this is the core of the algorithm: calculate the "best" table */
static void optimize_result(void)
{
	int i, best;

	/* using the '\0' symbol last allows compress_symbols to use standard
	 * fast string functions */
	for (i = 255; i >= 0; i--) {

		/* if this table slot is empty (it is not used by an actual
		 * original char code */
		if (!best_table_len[i]) {

			/* find the token with the breates profit value */
			best = find_best_token();
			if (token_profit[best] == 0)
			        break;

			/* place it in the "best" table */
			best_table_len[i] = 2;
			best_table[i][0] = best & 0xFF;
			best_table[i][1] = (best >> 8) & 0xFF;

			/* replace this token in all the valid symbols */
			compress_symbols(best_table[i], i);
		}
	}
}

/* start by placing the symbols that are actually used on the table */
static void insert_real_symbols_in_table(void)
{
	unsigned int i, j, c;

	memset(best_table, 0, sizeof(best_table));
	memset(best_table_len, 0, sizeof(best_table_len));

	for (i = 0; i < table_cnt; i++) {
		for (j = 0; j < table[i].len; j++) {
			c = table[i].sym[j];
			best_table[c][0]=c;
			best_table_len[c]=1;
		}
	}
}

static void optimize_token_table(void)
{
	build_initial_tok_table();

	insert_real_symbols_in_table();

	/* When valid symbol is not registered, exit to error */
	if (!table_cnt) {
		fprintf(stderr, "No valid symbol.\n");
		exit(1);
	}

	optimize_result();
}

static int compare_value(const void *p1, const void *p2)
{
	const struct sym_entry *sym1 = p1;
	const struct sym_entry *sym2 = p2;

	if (sym1->addr < sym2->addr)
		return -1;
	if (sym1->addr > sym2->addr)
		return +1;
	/* Prefer global symbols. */
	if (isupper(*sym1->sym))
		return -1;
	if (isupper(*sym2->sym))
		return +1;
	return 0;
}

static int compare_name(const void *p1, const void *p2)
{
	const struct sym_entry *sym1 = p1;
	const struct sym_entry *sym2 = p2;

	return strcmp(SYMBOL_NAME(sym1), SYMBOL_NAME(sym2));
}

int main(int argc, char **argv)
{
	unsigned int i;
	bool unsorted = false, warn_dup = false, error_dup = false, found_dup = false;

	if (argc >= 2) {
		for (i = 1; i < argc; i++) {
			if(strcmp(argv[i], "--all-symbols") == 0)
				all_symbols = 1;
			else if (strncmp(argv[i], "--symbol-prefix=", 16) == 0) {
				char *p = &argv[i][16];
				/* skip quote */
				if ((*p == '"' && *(p+2) == '"') || (*p == '\'' && *(p+2) == '\''))
					p++;
				symbol_prefix_char = *p;
			} else if (strcmp(argv[i], "--sysv") == 0)
				input_format = fmt_sysv;
			else if (strcmp(argv[i], "--sort") == 0)
				unsorted = true;
			else if (strcmp(argv[i], "--sort-by-name") == 0)
				sort_by_name = 1;
			else if (strcmp(argv[i], "--warn-dup") == 0)
				warn_dup = true;
			else if (strcmp(argv[i], "--error-dup") == 0)
				warn_dup = error_dup = true;
			else if (strcmp(argv[i], "--xensyms") == 0)
				map_only = true;
			else
				usage();
		}
	} else if (argc != 1)
		usage();

	read_map(stdin);

	if (warn_dup) {
		qsort(table, table_cnt, sizeof(*table), compare_name);
		for (i = 1; i < table_cnt; ++i)
			if (strcmp(SYMBOL_NAME(table + i - 1),
				   SYMBOL_NAME(table + i)) == 0 &&
			    table[i - 1].addr != table[i].addr) {
				fprintf(stderr,
					"Duplicate symbol '%s' (%llx != %llx)\n",
					SYMBOL_NAME(table + i),
					table[i].addr, table[i - 1].addr);
				found_dup = true;
			}
		unsorted = true;
	}

	if (error_dup && found_dup)
		exit(1);

	if (unsorted)
		qsort(table, table_cnt, sizeof(*table), compare_value);

	optimize_token_table();
	write_src();

	return 0;
}
