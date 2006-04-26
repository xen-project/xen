/*
 * QEMU keylayout reader: read rdesktop style keylaouts
 *
 * Copyright (c) 2004,2005 Johannes E. Schindelin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <ctype.h>

#ifdef KEYBOARD_IGNORE_CASE
#define STRCMP strcasecmp
#else
#define STRCMP strcmp
#endif

/* binary search through nameToKeysym */
static int get_keysym(const char* name)
{
	int i1=-1,i2=sizeof(name2keysym)/sizeof(name2keysym_t),i3=i2/2,r;
	while((r=STRCMP(name,name2keysym[i3].name))!=0) {
		if(r<0)
			i2=i3;
		else
			i1=i3;
		i3=(i1+i2)/2;
		if(i2-i1<2)
			return 0;
	}
	return name2keysym[i3].keysym;
}

typedef unsigned short WORD;
#define MAX_NORMAL_KEYCODE 512
#define MAX_EXTRA_COUNT 256
typedef struct {
	WORD keysym2keycode[MAX_NORMAL_KEYCODE];
	struct {
		int keysym;
		WORD keycode;
	} keysym2keycode_extra[MAX_EXTRA_COUNT];
	int extra_count;
} kbd_layout_t;

static int parse_int(const char* text)
{
	if(!strncmp(text,"0x",2)) {
		int result=0;
		sscanf(text+2,"%x",&result);
		return result;
	}
	return atoi(text);
}

static kbd_layout_t* parse_keyboard_layout(const char* language,kbd_layout_t* k)
{
	FILE* f;
    const char* prefix="/keymaps/";
    char* file_name=malloc(strlen(prefix)+strlen(language)+strlen(bios_dir)+1);

	if(!k)
		k=calloc(1, sizeof(kbd_layout_t));
	strcpy(file_name,bios_dir);
	strcat(file_name,prefix);
	strcat(file_name,language);
	if(file_name[strlen(file_name)-1]=='\n')
		file_name[strlen(file_name)-1]=0;
	if(!(f=fopen(file_name,"r"))) {
		term_printf("Warning: could not read keymap - falling back native keycodes!\n");
		free(file_name);
		return 0;
	}
	free(file_name);
	while(!feof(f)) {
		char line[1024];
		fgets(line,1024,f);
		if(line[0]=='#')
			continue;
		if(!strncmp(line,"map ",4))
			continue;
		if(!strncmp(line,"include ",8))
			parse_keyboard_layout(line+8,k);
		else {
			char* end_of_keysym=line;
			while(*end_of_keysym!=0 && *end_of_keysym!=' ')
				end_of_keysym++;
			if(*end_of_keysym) {
				int keysym;
				*end_of_keysym=0;
				keysym=get_keysym(line);
				if(keysym==0) {
					term_printf("Warning: 1unknown keysym %s\n",line);
				} else {
					const char* rest=end_of_keysym+1;
					int keycode=parse_int(rest);
					/* if(keycode&0x80)
						keycode=(keycode<<8)^0x80e0; */
					if(keysym<MAX_NORMAL_KEYCODE) {
						//term_printf("Setting keysym %s (%d) to %d\n",line,keysym,keycode);
						k->keysym2keycode[keysym]=keycode;
#ifndef KEYBOARD_IGNORE_CASE
						line[0]=toupper(line[0]);
						keysym=get_keysym(line);
						if(keysym)
							k->keysym2keycode[keysym]=keycode;
#endif
					} else {
						if(k->extra_count>=MAX_EXTRA_COUNT) {
							term_printf("Warning: Could not assign keysym %s (0x%x) because of memory constraints.\n",line,keysym);
						} else {
							//term_printf("Setting %d: %d,%d\n",k->extra_count,keysym,keycode);
							k->keysym2keycode_extra[k->extra_count].keysym=keysym;
							k->keysym2keycode_extra[k->extra_count].keycode=keycode;
							k->extra_count++;
						}
					}
				}
			}
		}
	}
	fclose(f);
	return k;
}

static void* init_keyboard_layout(const char* language)
{
	return parse_keyboard_layout(language,0);
}

static WORD keysym2scancode(void* kbd_layout, int keysym)
{
	kbd_layout_t* k=kbd_layout;
	if(keysym<MAX_NORMAL_KEYCODE) {
		if(k->keysym2keycode[keysym]==0)
			term_printf("Warning: no scancode found for keysym %d\n",keysym);
		return k->keysym2keycode[keysym];
	} else {
		int i;
#ifdef XK_ISO_Left_Tab
		if(keysym==XK_ISO_Left_Tab)
			keysym=XK_Tab;
#endif
		for(i=0;i<k->extra_count;i++)
			if(k->keysym2keycode_extra[i].keysym==keysym)
				return k->keysym2keycode_extra[i].keycode;
	}
	return 0;
}

