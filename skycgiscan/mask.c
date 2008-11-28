/* Copyright (C) 2003 by BufferOverflow  */
/* by skylazart */

#include <stdlib.h>
#include <string.h>
#include "net.h"

struct {
	unsigned int base, bits;
	unsigned int x;
} mask_scan;

int mask_init (char *str)
{
	char * fqdn;
	unsigned int a,b,c,d,e,f,g,h;
	char newstr[128];
	SA sa;
        
	if (sscanf(str, "%d.%d.%d.%d/%d.%d.%d.%d", &a, &b, &c, &d, 
                   &e, &f, &g, &h) == 8) {
		return (mask_fnat_init (a, b, c, d, e, f, g, h));
	}
	if (sscanf (str, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &e) == 5) {
		return (mask_bit_init (a, b, c, d, e));
	}
        
	fqdn = malloc (strlen (str) + 4);
	if (!fqdn) return (-1);
	
	printf ("%s\n", str);
	if (sscanf (str, "%[^/]/%d", fqdn, &e) == 2) {
		sa.sin_addr.s_addr = net_resolve (fqdn);
		free (fqdn);
		snprintf (newstr, sizeof (newstr), "%s/%d", 
                          inet_ntoa (sa.sin_addr), e);
		return (mask_init (newstr));
	}
	return (-1);
}

int mask_fnat_init (unsigned int a, unsigned int b, unsigned int c,
                    unsigned int d, unsigned int ma, unsigned int mb, 
                    unsigned int mc, unsigned int md)
{
	unsigned int x = 0, y = 0;
#ifndef WORDS_BIGENDIAN
	x = ma << 24; x |= mb << 16; x |= mc << 8; x |= md;
	y = a << 24; y |= b << 16; y |= c << 8; y |= d;
#else  /* WORDS_BIGENDIAN */
	x = ma << 24; x |= mb << 16; x |= mc << 8; x |= md;
	y = a << 24; y |= b << 16; y |= c << 8; y |= d;
#endif /* WORDS_BIGENDIAN */
        
	y = y & x;
	if (x > 0xffffffff) return (-1);
	if (y > 0xffffffff) return (-1);
	mask_scan.base = y;
	mask_scan.bits = x;
	mask_scan.x = 0;
	return (1);
}

int mask_bit_init (unsigned int a, unsigned int b, unsigned int c, 
		   unsigned int d, unsigned int bt)
{
	unsigned int x;

#ifndef WORDS_BIGENDIAN
	x = a; x = x << 24; x |= b << 16; x |= c << 8; x |= d;
	mask_scan.base = x; mask_scan.bits = bt;
	x = 0; x =~ x; x <<= (32 - bt);
#else  /* WORDS_BIGENDIAN */
	x = a; x = x << 24; x |= b << 16; x |= c << 8; x |= d;
	mask_scan.base = x; mask_scan.bits = bt;
	x = 0; x =~ x; x <<= (32 - bt);
#endif /* WORDS_BIGENDIAN */

	mask_scan.base = mask_scan.base & x;
	mask_scan.bits = x;
	mask_scan.x = 0;
	if (mask_scan.bits > 0xffffffff) return (-1);
	if (mask_scan.base > 0xffffffff) return (-1);
	return (1);
}

char * mask_get_next (char *ip, unsigned int len)
{
	unsigned int new = mask_scan.base;
	unsigned short a,b,c,d;

	new += mask_scan.x++;  
	if ( (new & mask_scan.bits) <= (mask_scan.base & mask_scan.bits) ) {
		a = new >> 24;
		b = (new & 0x00ff0000) >> 16;
		c = (new & 0x0000ff00) >> 8;
		d = (new & 0x000000ff);
		snprintf (ip, len, "%d.%d.%d.%d", a, b, c, d);
		return (ip);
	}
	return (0);
}
