/* Libxpl by skylazart - Jun/2005 */

#include <stdlib.h>
#include <string.h>
#include "libxpl.h"

void xpl_init (XPL *b)
{
	b->len = 0;
	b->buf = malloc (1);
	b->b = b->e = b->buf;
}

void xpl_end (XPL *b)
{
	b->len = 0;
	free (b->buf);
	b->b = b->e = NULL;
}

char * xpl_buf (XPL *b) 
{
	return (b->buf);
}

int xpl_len (XPL *b) 
{
	return (b->len);
}

int xpl_inst (XPL *b, const void *data, int size, int nmemb)
{
	int oct;
	int n;
	int y;

	oct = size * nmemb;
	b->buf = realloc (b->buf, b->len + oct + 1);
	b->b = b->buf;
	b->e = b->buf + b->len;
	b->len += oct;

	for (n = 0; n < nmemb; n++) {
		memcpy (b->e, data, size);
		b->e = b->e + size;
	}
	return (oct);
}

#ifdef TEST
int main (int argc, char ** argv)
{
	XPL xpl;
	int len;
	char * b;
	long ret = 0x41424344;

	xpl_init (&xpl);
	xpl_inst (&xpl, "\x90", 1, 10);       
	xpl_inst (&xpl, "\x80", 1, 10);
	xpl_inst (&xpl, &ret, sizeof (ret), 10);

	b = xpl_buf (&xpl);
	len = xpl_len (&xpl);

	printf ("len = %d\n", len);
	write (2, b, len);
	
	xpl_end (&xpl);

	return (0);
}
#endif
