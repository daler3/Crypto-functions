/* Implement the following API. Do NOT modify the given prototypes. */

/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer (allocated by the caller)
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */
void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
	  unsigned int l);

/* You can add your own functions below this line.
 * Do NOT modify anything above. */
