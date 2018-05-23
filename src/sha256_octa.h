/// octa-instance sha-256 evaluation on 1 block
/// the hard-wired padding routines assume that the data is exactly 52 bytes
/// so that sha-256 only requires 1 iteration of the compression loop.
///
/// aas 2017
///
/// To compile:
///  gcc -c -O3 -mavx2 sha256_octa.c
///


// takes buf, pointer to 8 64-byte buffers as input (using only the first 52 bytes of the buffer), 
// and writes answer to out, a ptr to 8 32-byte buffers.

void sha256_octa_52b(const unsigned char* buf, unsigned char* out);
void sha256_multi_52b(const unsigned char* buf, unsigned char* out, size_t count);
