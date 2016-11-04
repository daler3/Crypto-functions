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

#include <inttypes.h>

/* Main body of Kekkak-p function
*
* s        - Input string 
* nrounds  - Number of permutation rounds
*/
void keccakp (void *s);

/* Iota step of Keccak-p function
* s      - pointer to the string representing the stare array
* nround - identification number of the current round
*/
void keccakp_iota (uint64_t *s, unsigned int nround);

/* Chi step of Keccak-p function
* s - pointer to the string representing the stare array
*/
void keccakp_chi (uint64_t *s);

/* Pi step of Keccak-p function
* s - pointer to the string representing the stare array
*/
void keccakp_pi (uint64_t *s);

/* Rho step of Keccak-p function
* s - pointer to the string representing the stare array
*/
void keccakp_rho (uint64_t *s);

/* Theta step of Keccak-p function
* s - pointer to the string representing the stare array
*/
void keccakp_theta (uint64_t *s);


/*Simple function for calcating the value of a number in modulo of another number
 *
 * a - the number of which it is wanted to calulate the modulo
 * b - the modulo respect to which we wanted to calulate the value of a
 *
 * Return a mod b
 */
unsigned int mod (int a, int b);
