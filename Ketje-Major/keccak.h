#ifndef KECCAK_H
#define KECCAK_H

/* Perform the KECCAK-p*[b, n_r] permutation
 *
 * S  - the input bit string
 * b  - the length of the input string in bits
 * nr - the number of rounds
 * l  - the value of l associated with b (log2(b/25))
 *
 * Returns a pointer to the output bit string
 */
unsigned char *keccak_p_star(unsigned char *S, unsigned long b, int nr, int l);

/* Utility functions */
void cpynbits(unsigned char *dst, unsigned int dst_o,
	      const unsigned char *src, unsigned int src_o, unsigned int n);
unsigned long concatenate(unsigned char **Z,
			  const unsigned char *X, unsigned long X_len,
			  const unsigned char *Y, unsigned long Y_len);
unsigned long concatenate_00(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len);
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len);
unsigned long concatenate_10(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len);
unsigned long concatenate_11(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len);
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m);

/* If needed, you can add your own functions below this line.
 * Do NOT modify anything above. */

#endif				/* KECCAK_H */
