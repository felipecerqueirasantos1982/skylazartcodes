/*
 * conv.c - iso8583 little parser
 * 31/03/2009
 *
 * Felipe Cerqueira / skylazart@gmail.com
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>




typedef struct {
	char * p;
	char * data;
} iso8583;


struct bitmapdescription_t {
	int bitmap;
	char * description;
} bitmapdescriptions[] = {
	{0,   "Unused"},
	{1,   "Bit Map Extended"},
	{2,   "Primary account number (PAN)"},
	{3,   "Processing code"},
	{4,   "Amount, transaction"},
	{5,   "Amount, Settlement"},
	{6,   "Amount, cardholder billing"},
	{7,   "Transmission date & time"},
	{8,   "Amount, Cardholder billing fee"},
	{9,   "Conversion rate, Settlement"},
	{10,  "Conversion rate, cardholder billing"},
	{11,  "Systems trace audit number"},
	{12,  "Time, Local transaction"},
	{13,  "Date, Local transaction"},
	{14,  "Date, Expiration"},
	{15,  "Date, Settlement"},
	{16,  "Date, conversion"},
	{17,  "Date, capture"},
	{18,  "Merchant type"},
	{19,  "Acquiring institution country code"},
	{20,  "PAN Extended, country code"},
	{21,  "Forwarding institution. country code"},
	{22,  "Point of service entry mode"},
	{23,  "Application PAN number"},
	{24,  "Function code(ISO 8583:1993)/Network International identifier (?)"},
	{25,  "Point of service condition code"},
	{26,  "Point of service capture code"},
	{27,  "Authorizing identification response length"},
	{28,  "Amount, transaction fee"},
	{29,  "Amount. settlement fee"},
	{30,  "Amount, transaction processing fee"},
	{31,  "Amount, settlement processing fee"},
	{32,  "Acquiring institution identification code"},
	{33,  "Forwarding institution identification code"},
	{34,  "Primary account number, extended"},
	{35,  "Track 2 data"},
	{36,  "Track 3 data"},
	{37,  "Retrieval reference number"},
	{38,  "Authorization identification response"},
	{39,  "Response code"},
	{40,  "Service restriction code"},
	{41,  "Card acceptor terminal identification"},
	{42,  "Card acceptor identification code"},
	{43,  "Card acceptor name/location"},
	{44,  "Additional response data"},
	{45,  "Track 1 Data"},
	{46,  "Additional data - ISO"},
	{47,  "Additional data - National"},
	{48,  "Additional data - Private"},
	{49,  "Currency code, transaction"},
	{50,  "Currency code, settlement"},
	{51,  "Currency code, cardholder billing"},
	{52,  "Personal Identification number data"},
	{53,  "Security related control information"},
	{54,  "Additional amounts"},
	{55,  "Reserved ISO"},
	{56,  "Reserved ISO"},
	{57,  "Reserved National"},
	{58,  "Reserved National"},
	{59,  "Reserved for national use"},
	{60,  "Advice/reason code (private reserved)"},
	{61,  "Reserved Private"},
	{62,  "Reserved Private"},
	{63,  "Reserved Private"},
	{64,  "Message authentication code (MAC)"},
	{65,  "Bit map, tertiary"},
	{66,  "Settlement code"},
	{67,  "Extended payment code"},
	{68,  "Receiving institution country code"},
	{69,  "Settlement institution county code"},
	{70,  "Network management Information code"},
	{71,  "Message number"},
	{72,  "Data record (ISO 8583:1993)/n 4 Message number, last(?)"},
	{73,  "Date, Action"},
	{74,  "Credits, number"},
	{75,  "Credits, reversal number"},
	{76,  "Debits, number"},
	{77,  "Debits, reversal number"},
	{78,  "Transfer number"},
	{79,  "Transfer, reversal number"},
	{80,  "Inquiries number"},
	{81,  "Authorizations, number"},
	{82,  "Credits, processing fee amount"},
	{83,  "Credits, transaction fee amount"},
	{84,  "Debits, processing fee amount"},
	{85,  "Debits, transaction fee amount"},
	{86,  "Credits, amount"},
	{87,  "Credits, reversal amount"},
	{88,  "Debits, amount"},
	{89,  "Debits, reversal amount"},
	{90,  "Original data elements"},
	{91,  "File update code"},
	{92,  "File security code"},
	{93,  "Response indicator"},
	{94,  "Service indicator"},
	{95,  "Replacement amounts"},
	{96,  "Message security code"},
	{97,  "Amount, net settlement"},
	{98,  "Payee"},
	{99,  "Settlement institution identification code"},
	{100, "Receiving institution identification code"},
	{101, "File name"},
	{102, "Account identification 1"},
	{103, "Account identification 2"},
	{104, "Transaction description"},
	{105, "Reserved for ISO use"},
	{106, "Reserved for ISO use"},
	{107, "Reserved for ISO use"},
	{108, "Reserved for ISO use"},
	{109, "Reserved for ISO use"},
	{110, "Reserved for ISO use"},
	{111, "Reserved for ISO use"},
	{112, "Reserved for national use"},
	{113, "Authorizing agent institution id code"},
	{114, "Reserved for national use"},
	{115, "Reserved for national use"},
	{116, "Reserved for national use"},
	{117, "Reserved for national use"},
	{118, "Reserved for national use"},
	{119, "Reserved for national use"},
	{120, "Reserved for private use"},
	{121, "Reserved for private use"},
	{122, "Reserved for private use"},
	{123, "Reserved for private use"},
	{124, "Info Text"},
	{125, "Network management information"},
	{126, "Issuer trace id"},
	{127, "Reserved for private use"},
	{128, "Message Authentication code"}
};
 



int
BITn (unsigned long long x, int b) 
{
	unsigned long long mask;	
	if (b > 1)                      
                mask = pow (2, b-1);	
	else				
		mask = 1;			

	return ((x & mask) > 0);	
}
					
void
init_iso8583 (iso8583 * data, char * inbuffer)
{
	data->data = strdup (inbuffer);
	data->p=data->data;
}

void
release_iso8583 (iso8583 * data)
{
	data->p = NULL;
	free (data->data);
}

void
getdigit (iso8583 * data, int n, char * out)
{
	strncpy (out, data->p, n);
	out[n] = 0;
	data->p += n;
}

void
hex2bin (unsigned char number, char * binascii)
{
	int i;
	int d;

	d = 7;
	for (i = 1; i <= 8; i++) {
		if (BITn(number,i)) {
			binascii[d] = '1';
		} else {
			binascii[d] = '0';
		}
		d--;
	}
	binascii[8] = 0;
}

void
printMTI (char * mti)
{
	int digit;
	digit = mti[0];

	switch (digit) {
	case '0': printf ("ISO 8583-1:1987 version\n"); break;
	case '1': printf ("ISO 8583-2:1993 version\n"); break;
	case '2': printf ("ISO 8583-1:2003 version\n"); break;
	case '9': printf ("Private usage\n"); break;
	}	
	
	digit = mti[1];

	switch (digit) {
	case '1': printf ("Authorization Message     \n"); break;
	case '2': printf ("Financial Message         \n"); break;
	case '3': printf ("File Actions Message      \n"); break;
	case '4': printf ("Reversal Message          \n"); break;
	case '5': printf ("Reconciliation Message    \n"); break;
	case '6': printf ("Administrative Message    \n"); break;
	case '7': printf ("Fee Collection Message    \n"); break;
	case '8': printf ("Network Management Message\n"); break;
	case '9': printf ("Reserved by ISO           \n"); break;
	}
	
	digit = mti[2];

	switch (digit) {
	case '0': printf ("Request                \n"); break;
	case '1': printf ("Request Response       \n"); break;
	case '2': printf ("Advice                 \n"); break;
	case '3': printf ("Advice Response        \n"); break;
	case '4': printf ("Notification           \n"); break;
	case '8': printf ("Response acknowledgment\n"); break;
	case '9': printf ("Negative acknowledgment\n"); break;		
	}

	digit = mti[3];
	switch (digit) {
	case '0': printf ("Acquirer       \n"); break;
	case '1': printf ("Acquirer Repeat\n"); break;
	case '2': printf ("Issuer	  \n"); break;
	case '3': printf ("Issuer Repeat  \n"); break;
	case '4': printf ("Other	  \n"); break;
	case '5': printf ("Other Repeat   \n"); break;
	}

}


void
printBitMaps (iso8583 * data, int bit)
{
	char out[256];

	printf ("[%-40s] ", bitmapdescriptions[bit].description);

	switch (bit) {
	case 3:
		getdigit (data, 6, out);
		printf ("DATA=%s\n", out);
		break;		

	case 4:
		getdigit (data, 12, out);
		printf ("DATA=%s\n", out);
		break;		
	case 11:
		getdigit (data, 6, out);
		printf ("DATA=%s\n", out);
		break;		
	case 12:
		getdigit (data, 12, out);
		printf ("DATA=%s\n", out);
		break;		
	case 18:
		getdigit (data, 4, out);
		printf ("DATA=%s\n", out);
		break;		
	case 22:
		getdigit (data, 3, out);
		printf ("DATA=%s\n", out);
		break;		
	case 24:
		getdigit (data, 4, out);
		printf ("DATA=%s\n", out);
		break;
	case 34:
		getdigit (data, 8, out);
		printf ("DATA=%s\n", out);
		break;		
	case 39:
		getdigit (data, 3, out);
		printf ("DATA=%s\n", out);
		break;		
	case 41:
		getdigit (data, 8, out);
		printf ("DATA=%s\n", out);
		break;		

	default:
		printf ("\n");
		break;
	}
}

int
main (int argc, char ** argv)
{
	iso8583 data;
	char out[256];

	unsigned char bitmap;
	char eightbits[12];
	char bitmapstr[66];
	

	int i;
	
	if (!argv[1]) exit (1);

	init_iso8583 (&data, argv[1]);

	getdigit (&data, 12, out);	
	printf (">> SDLC HEADER:\n"
		"%s\n\n", out);

	getdigit (&data, 4, out);	
	printf (">> MTI:\n"
		"%s\n", out);
	printMTI (out);
	printf ("\n");

	
	bitmapstr[0] = 0;

	for (i = 0; i < 8; i++) {
		memset (out, 0, sizeof (out));
		
		getdigit (&data, 2, out);	
		bitmap = (unsigned char)strtoul (out, NULL, 16);
		
		hex2bin (bitmap, eightbits);
		
		strcat (bitmapstr, eightbits);
	}

	printf (">> BITMAP:\n"
		"%s\n", bitmapstr);
	
	printf (">> BITS:\n");
	for (i = 0; i <= 63; i++) {
		if (bitmapstr[i] == '1') {
			printf ("[%.03d] ", i+1);
			
			printBitMaps (&data, i+1);
		}
	}
	printf ("\n\n");

	release_iso8583 (&data);

	return (0);
}
