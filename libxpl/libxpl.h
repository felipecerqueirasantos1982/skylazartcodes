/* Libxpl by skylazart - Jun/2005 */

#ifndef LIB_XPL_H
#define LIB_XPL_H

struct xpl_ {
  char * buf;
  int len;
  
  /* Internal controll */
  char *b;
  char *e;
};

typedef struct xpl_ XPL;

void xpl_init (XPL *);
void xpl_end (XPL *);
char * xpl_buf (XPL *);
int xpl_len (XPL *);
int xpl_inst (XPL *, const void *, int, int);

#endif /* LIB_XPL_H */
