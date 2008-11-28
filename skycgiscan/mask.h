/* Copyright (C) 2003 by BufferOverflow  */
/* by skylazart */

#ifndef MASK_H
#define MASK_H

extern int mask_init (char *str);
extern int mask_bit_init (unsigned int a, unsigned int b, unsigned int c, 
			  unsigned int d, unsigned int bt);
extern int mask_fnat_init (unsigned int a, unsigned int b, unsigned int c,
			  unsigned int d, unsigned int ma, unsigned int mb, 
			  unsigned int mc, unsigned int md);
extern char * mask_get_next (char *ip, unsigned int len);

#endif /* MASK_H */
