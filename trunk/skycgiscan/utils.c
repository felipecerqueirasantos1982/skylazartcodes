#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int verify_fifo (const char * path)
{
  return (access (path, R_OK | W_OK));
}

int create_fifo (const char * path)
{
  return (mkfifo (path, 0666));
}

void Log (char * m)
{
  fprintf (stderr, "Log - %s\n", m);
}
