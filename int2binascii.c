
void
hex2bin8bits (unsigned char number, char * binascii)
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
hex2bin16bits (unsigned short number, char * binascii)
{
        int i;
        int d;


        d = 15;
        for (i = 1; i <= 16; i++) {
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
hex2bin32bits (unsigned int number, char * binascii)
{
        int i;
        int d;


        d = 31;
        for (i = 1; i <= 32; i++) {
                if (BITn(number,i)) {
                        binascii[d] = '1';
                } else {
                        binascii[d] = '0';
                }
                d--;
        }
        binascii[8] = 0;
}

