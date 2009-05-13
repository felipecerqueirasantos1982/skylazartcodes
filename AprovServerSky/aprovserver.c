#include <stdio.h>
#include <sys/types.h>
#include <regex.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#define MAX_REGEX 4096
#define REGEX_FILE "operadoras.txt"

typedef struct {
	union {
		struct {
			int total_registers;
		} control;
		struct {
			int oper_code;
			char * regex_str;
			regex_t preg;
		} data;
	};
} OperRegularExpression;



int
load_regular_expressions (OperRegularExpression * oper_regular_expression_ptr)
{
	FILE * fp;
	char str[1024];
	int len;
	
	int index;

	if (oper_regular_expression_ptr[0].control.total_registers > 0) {
		for (index = 1; index <= oper_regular_expression_ptr[0].control.total_registers; index++) {
			fprintf (stderr, "Releasing %d\n", index);
			regfree (&oper_regular_expression_ptr[index].data.preg);
			free (oper_regular_expression_ptr[index].data.regex_str);
		}
	}

	oper_regular_expression_ptr[0].control.total_registers = 0;
	index = 1;

	fp = fopen (REGEX_FILE, "r");
	if (!fp) {
		fprintf (stderr, "Error opening file %s: %s\n", REGEX_FILE, strerror (errno));
		return (-1);
	}	

	while (fgets (str, sizeof (str)-1, fp)) {
		len = strlen (str);
		if (str[len-1] == '\n')
			str[len-1] = '\0';
		
		
		if (regcomp (&oper_regular_expression_ptr[index].data.preg, str, 0) != 0) {
			fprintf (stderr, "Error compiling %s\n", str);
			continue;
		}

		oper_regular_expression_ptr[index].data.regex_str = malloc (len + 1);
		if (!oper_regular_expression_ptr[index].data.regex_str) {
			fprintf (stderr, "Error with malloc: %s\n", strerror (errno));
			regfree (&oper_regular_expression_ptr[index].data.preg);
			
			continue;
		}

		strcpy (oper_regular_expression_ptr[index].data.regex_str, str);
		oper_regular_expression_ptr[index].data.oper_code = 20;

		index++;
		oper_regular_expression_ptr[0].control.total_registers++;

		if (index > (MAX_REGEX - 2)) {
			fprintf (stderr, "Maximum of regex reached! %d\n", MAX_REGEX);
			break;
		}
	}
	
	
	fclose (fp);
	
	printf ("Loaded %d regular expressions...\n", oper_regular_expression_ptr[0].control.total_registers);
	
	return (oper_regular_expression_ptr[0].control.total_registers);

}

int
getOperatorCode (OperRegularExpression * oper_regular_expression_ptr, char * str_match)
{
	int index;
	int oper_code;

	oper_code = -1;
	
	for (index = 1; index <= oper_regular_expression_ptr[0].control.total_registers; index++) {
		if (regexec (&oper_regular_expression_ptr[index].data.preg, str_match, 0, 0, 0) == 0) {
			oper_code = oper_regular_expression_ptr[index].data.oper_code;
			break;
		}
	}

	return (oper_code);
}

int
main (int argc, char ** argv)
{
	OperRegularExpression oper_regular_expression[MAX_REGEX];
	unsigned int x;

	// Initializing	
	oper_regular_expression[0].control.total_registers = 0;
	load_regular_expressions (&oper_regular_expression[0]);

	for (x = 0; x < 1000000; x++) {
		getOperatorCode (&oper_regular_expression[0], "552198519898");
	}
	
	printf ("Total of queries: %u\n", x);
	return (0);

}
