// Bitarray operations
typedef struct
{
    unsigned bits;          // number of represented bits
    unsigned numset;        // number of set bits
    unsigned char array[];  // zero length array
} bitarray;

// Return 1 if numbered bit is set, 0 if reset, -1 if bit number is invalid
int bitarray_test(bitarray *b, unsigned bit);

// Set numbered bit and return 0, or -1 if bit number is invalid
int bitarray_set(bitarray *b, unsigned bit);

// Reset numbered bit and return 0, or -1 if bit number is invalod
int bitarray_reset(bitarray *b, unsigned bit);

// Clear all bits in the bitarray.
void bitarray_wipe(bitarray *b);

// Return number of set bits in the bitarray
int bitarray_numset(bitarray *b);

// Create new bitarray and return pointer, or NULL if OOM. Caller must free()
// it when done.
bitarray *bitarray_create(unsigned bits);

// Given a bit number, return that bit if it's set, else the number of the next
// highest set bit. Or return -1 if none.
int bitarray_next(bitarray *b, unsigned bit);
