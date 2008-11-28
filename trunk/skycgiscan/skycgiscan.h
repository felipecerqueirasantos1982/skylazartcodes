/* 
   Private CGI Scan, Do Not Distribute!

   skycgiscan 0.1 beta
   by skylazart - Jun/2005
*/

#ifndef SKYCGISCAN_H
#define SKYCGISCAN_H

#define FIFO_SERVER_PATH "mycgiscan.fifo"

// Error messages
#define MSG1 "Error creating/acessing fifo server"

char errmsg[1024];

extern int verify_fifo (const char * path);
extern int create_fifo (const char * path);
extern void Log (char * m);


extern int http_header (char * ip, char * res, int len);
extern int http_cgi (char * ip, char * cgi);

#endif /* SKYCGISCAN_H */
