#!/usr/bin/python


class Bitmap:
    bitmap = 0
    vectorBitmap = range (1, 64)

    def __init__ (self):
        for i in range (0, 63):
            self.vectorBitmap[i] = '0'

    def setBit (self, position):
        value = 1 << (64 - position)
        self.bitmap |= value

    def unsetBit (self, position):
        value = 1 << (64 - position)
        self.bitmap ^= value

    def getBitmapDecimalValue (self):
        return (self.bitmap)

    def getBitmalHexStringValue (self):
        return ('%16X' % self.bitmap)

    def getBitmapVector (self):
        bitmask = 0

        for bitcheck in range (1, 63):
            bitmask = 1 << (64 - bitcheck)
            if (self.bitmap & bitmask):
                self.vectorBitmap[bitcheck-1] = '1'
        return (self.vectorBitmap)
        


x = Bitmap ()

x.setBit (3)
x.setBit (4)
x.setBit (11)
x.setBit (12)
x.setBit (18)

x.setBit (22)
x.setBit (24)
x.setBit (34)

x.setBit (35)
x.setBit (41)
x.setBit (42)

x.setBit (43)
x.setBit (45)
x.setBit (47)

x.setBit (49)
x.setBit (61)
x.setBit (64)


print 'Valor em decimal: ', x.getBitmapDecimalValue ()
print 'Valor em hexa: ', x.getBitmalHexStringValue ()
print x.getBitmapVector ()



