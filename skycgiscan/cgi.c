/* 
   Private CGI Scan, Do Not Distribute!

   skycgiscan 0.1 beta
   by skylazart - Jun/2005
*/

#include <stdio.h>
#include <string.h>
#include "net.h"

#define TIMEOUT 6

#define HTTP_HEAD_VERSION "HEAD / HTTP/1.0\r\n\r\n"

/* what for? */
#define HTTP_CGI_CHPASSWD "GET /cgi-bin/chpasswd.cgi HTTP/1.0\r\n\r\n"

int http_result (char *buf)
{
        if (strstr (buf, "HTTP/1.1 404"))
                return (404);
        
        if (strstr (buf, " 404 "))
                return (404);

        if (strstr (buf, "HTTP/1.1 500"))
                return (500);
        
        if (strstr (buf, " 500 "))
                return (500);
        
        if (strstr (buf, "HTTP/1.1 200 OK")) {
                return (200);
        }
        
        if (strstr (buf, " 200 ")) {
                return (200);
        }
        
        return (-1);
}

int http_header (char * ip, char *res, int len)
{
        char buf[512], *p, *e;
        int fd;
        int n;
        
        /*fprintf (stderr, "[%d] Scanning http_header %s %.40s...\r", 
          pthread_self(), ip, " ");*/
        
        fd = net_connect (ip, 80, TIMEOUT);
        if (fd <= 0) {
                return (-1);
        }
        
        n = write (fd, HTTP_HEAD_VERSION, sizeof (HTTP_HEAD_VERSION));
        if (n <= 0) {
                close (fd);
                return (-1);
        }
        
        for (;;) {
                if (!net_has_data (fd, TIMEOUT)) {
                        close (fd);
                        return (-1);
                }
                
                n = read (fd, buf, sizeof (buf));
                if (n <= 0) {
                        close (fd);
                        return (-1);
                }
                
                buf[n] = '\0';
                
                if ((p = strstr (buf, "Server: "))) {
                        e = p+1;
                        while (*e) {
                                if (*e == '\n')
                                        *e = '\0';
                                if (*e == '\r')
                                        *e = '\0';
                                e++;
                        }
                        
                        fprintf (stderr, "%s - %s\n", ip, p);
                        strncpy (res, p, len-1);
                        
                        close (fd);
                        return (1);
                }
        }
}

int http_cgi (char * ip, char * cgi)
{
        char buf[512], *p, *e;
        int fd;
        int n;
        FILE *fp;

        /*fprintf (stderr, "%d Scanning http_cgi %s %.40s...\r", 
          pthread_self (), ip, " ");*/

        if (ip == NULL || cgi == NULL) {
                return (-1);
        } 
        
        fd = net_connect (ip, 80, TIMEOUT);
        if (fd <= 0) 
                return (-1);
        
        snprintf (buf, sizeof (buf), "GET %s HTTP/1.0\r\n\r\n", cgi);
        n = write (fd, buf, strlen (buf));
        
        if (n <= 0) {
                close (fd);
                return (-1);
        }
        
        for (;;) {
                if (!net_has_data (fd, TIMEOUT)) {
                        close (fd);
                        return (-1);
                }
                
                n = read (fd, buf, sizeof (buf));
                if (n <= 0) {
                        close (fd);
                        return (-1);
                }
                
          buf[n] = '\0';
          
          n = http_result (buf);
          if (n == 200) {
                  fp = fopen ("cgi.log", "a+");
                  fprintf (stderr, "%s - %s\n", ip, cgi);
                  fprintf (fp, "%s - %s\n", ip, cgi);
                  fclose (fp);
 
          }
          close (fd);
          return (n);
        }
        return (-1);
}
