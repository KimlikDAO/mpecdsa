#include "../blake2/ref/blake2.h"

void blake2s_multi_raw(const unsigned char* buf, unsigned char* out, size_t count) {
	size_t ii;
	//#pragma omp parallel for
	for (ii = 0; ii < count; ii++) {
		blake2s(&out[32*ii], 32, &buf[64*ii], 64, 0, 0);
	}
}