#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "sha3.h"
#include <math.h>

/* Number of rounds of keccak-f function */
#define NROUNDS 24
/* Lenght of the keccak-f input string */
#define BITLENGHT 1600

/* Useful macros */
/* Rotate a 64b word to the left by n positions */
#define ROL64(a, n) ((((n)%64) != 0) ? ((((uint64_t)a) << ((n)%64)) ^ (((uint64_t)a) >> (64-((n)%64)))) : a)
/* Mapping index of the string to the index of the state array */
#define mapping(x, y) (x + (y*5))


void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
	  unsigned int l);

unsigned long concatenate(unsigned char **Z, const unsigned char *X,
			  unsigned long X_len, const unsigned char *Y,
			  unsigned long Y_len);
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len);
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m);

unsigned int mod (int a, int b);

void keccakp_iota (uint64_t *s, unsigned int nround);
void keccakp_chi (uint64_t *s);
void keccakp_pi (uint64_t *s);
void keccakp_rho (uint64_t *s);
void keccakp_theta (uint64_t *s);
void keccakp (void *s);

/*
* Array containing Round Constants for 24 Rounds of Keccak-f 
* Used as the second input of iota function
*/
static unsigned long RC[] =
{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008
};


/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */
void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
	  unsigned int l)
{
	/* The hash size must be one of the supported ones */
	if (s != 224 && s != 256 && s != 384 && s != 512)
		return;

	/*Implementation of the rest of sha3 function*/

	unsigned int rate = BITLENGHT - 512; //rate in bits

	/*Message concatenation with 01*/
	unsigned char *m_conc = NULL; //where the results of concatenation will be stored
	unsigned long m_conc_len; //m_conc_len will contain the lenght of the resulting array
	m_conc_len = concatenate_01(&m_conc, m, l); 

	/*Sponge framework*/
	/*
	* First step of Sponge: padding and concatenation.
	* The aim is to produce a string of length "rate".
	* We have to generate a string of desired length (padding) 
	* that has to be concatenate with the initial one (m_conc).
	*/
	//padded will contain the string of desired lenght
	//concat will contain the result of the concatenation
	unsigned char *padded = NULL, *concat = NULL;  
	unsigned long padded_len, concat_len; 
	padded_len = pad10x1(&padded, rate, m_conc_len); 
	concat_len = concatenate(&concat, m_conc, m_conc_len, padded, padded_len);

	/*Free memory not used anymore*/
	free(m_conc);
	free(padded);

	/* 
	* The string obtained has to be splitted in n string. 
	* where n is equal to lenght of the concatenated string divided by the rate
	*/
	unsigned int n = concat_len/rate;

	/*
	* An array of pointer is used to keep track 
	* of the different n substrings of length r
	*/
	unsigned char *string_div[n]; //n pointer because we need n substrings
	unsigned long j = 0; //initialize a counter
	unsigned int div = rate/8; //the rate in bytes
	for (unsigned int i = 0; i < n; i ++){ 
		string_div[i] = &concat[j]; 
		j = j + div; //move from string of length rate to another one
	}

	/* Allocate a string os of b zeros; b = 1600 bits = 200 bytes */
	unsigned char *os = calloc (200, sizeof(unsigned char)); 
	/* Allocate a string os of c zeros; c = 512 bits = 64 bytes */
	unsigned char *oc = calloc (64, sizeof(unsigned char)); 

	/* This will contain the input string for keccakp function */
	unsigned char *inputStringKeccaKP = NULL; 
	/* This will contain  the length of the input string for keccakp function */
	unsigned long inputStringKeccaKP_len; 

	/* For-loop used for calling keccakp function on each of the n substring of length rate */
	for (unsigned int count = 0; count < n; count ++){
		/* Concatenation of one substring with 512 zeros */
		inputStringKeccaKP_len = concatenate(&inputStringKeccaKP, string_div[count], 1088, oc, 512);
		
		/* Absorbing phase */
		/* 
		* XOR of the string os with the result of the concatenation
		* This has been done byte per byte 
		*/
		for (j = 0; j < (inputStringKeccaKP_len / 8); j ++){
			os[j] ^= inputStringKeccaKP[j];
		} //now, each byte has been XORed, the result is in the string called os

		/* calling KeccakP */
		keccakp(os); 
	}

	/*Free memory not used anymore*/
	free(inputStringKeccaKP);
	free(oc);

	/* Squeezing phase */
	/* Allocate Z as a pointer to null */
	unsigned char *Z = NULL; 

	/* The string os will be concatenated */
	unsigned char *Z_init = NULL; //this will contain the concatenated string of Z and os
	unsigned long Z_len = 0; //this will contain the length concatenated string of Z and os

	while(1){
		/* now concatenate Z with the truncate os of 1088 bit */
		Z_len = concatenate(&Z_init, Z, Z_len, os, rate);

		/* check if the size of the output buffer is less than the length of the concatenated string */
		/* In the case the comparison is true, the while loop will stop at this iteraction */
		if (s <= Z_len){
			/* copy 32 bytes of Z_init in the output buffer, called d */
			memcpy(d, Z_init, 32);

			/*Free memory not used anymore before returning*/
			free(os);
			free(Z_init);
			return; 
		}

		/* Z will now point to Z_init, */
		Z = Z_init; 

		/* calling KeccakP */
		keccakp(os);
	}
}


/* Concatenate two bit strings (X||Y)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the first bit string
 * X_len - the length of the first string in bits
 * Y     - the second bit string
 * Y_len - the length of the second string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate(unsigned char **Z, const unsigned char *X,
			  unsigned long X_len, const unsigned char *Y,
			  unsigned long Y_len)
{
	/* The bit length of Z: the sum of X_len and Y_len */
	unsigned long Z_bit_len = X_len + Y_len;
	/* The byte length of Z:
	 * the least multiple of 8 greater than X_len + Y_len */
	unsigned long Z_byte_len = (Z_bit_len / 8) + (Z_bit_len % 8 ? 1 : 0);
	// Allocate the output string and initialize it to 0
	*Z = calloc(Z_byte_len, sizeof(unsigned char));
	if (*Z == NULL)
		return 0;
	// Copy X_len/8 bytes from X to Z
	memcpy(*Z, X, X_len / 8);
	// Copy X_len%8 bits from X to Z
	for (unsigned int i = 0; i < X_len % 8; i++) {
		(*Z)[X_len / 8] |= (X[X_len / 8] & (1 << i));
	}
	// Copy Y_len bits from Y to Z
	unsigned long Z_byte_cursor = X_len / 8, Z_bit_cursor = X_len % 8;
	unsigned long Y_byte_cursor = 0, Y_bit_cursor = 0;
	unsigned int v;
	for (unsigned long i = 0; i < Y_len; i++) {
		// Get the bit
		v = ((Y[Y_byte_cursor] >> Y_bit_cursor) & 1);
		// Set the bit
		(*Z)[Z_byte_cursor] |= (v << Z_bit_cursor);
		// Increment cursors
		if (++Y_bit_cursor == 8) {
			Y_byte_cursor++;
			Y_bit_cursor = 0;
		}
		if (++Z_bit_cursor == 8) {
			Z_byte_cursor++;
			Z_bit_cursor = 0;
		}
	}
	return Z_bit_len;
}

/* Concatenate the 01 bit string to a given bit string (X||01)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the bit string
 * X_len - the length of the string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len)
{
	/* Due to the SHA-3 bit string representation convention, the 01
	 * bit string is represented in hexadecimal as 0x02.
	 * See Appendix B.1 of the Standard.
	 */
	unsigned char zeroone[] = { 0x02 };
	return concatenate(Z, X, X_len, zeroone, 2);
}

/* Performs the pad10*1(x, m) algorithm
 *
 * P - the output bit string. The array is allocated by this function: the
 *     caller must take care of freeing it after use.
 * x - the alignment value
 * m - the existing string length in bits
 *
 * Returns the length in bits of the output bit string.
 */
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m)
{
	/* 1. j = (-m-2) mod x */
	long j = x - ((m + 2) % x);
	/* 2. P = 1 || zeroes(j) || 1 */
	// Compute P bit and byte length
	unsigned long P_bit_len = 2 + j;
	unsigned long P_byte_len = (P_bit_len / 8) + (P_bit_len % 8 ? 1 : 0);
	// Allocate P and initialize to 0
	*P = calloc(P_byte_len, sizeof(unsigned char));
	if (*P == NULL)
		return 0;
	// Set the 1st bit of P to 1
	(*P)[0] |= 1;
	// Set the last bit of P to 1
	(*P)[P_byte_len - 1] |= (1 << (P_bit_len - 1) % 8);

	return P_bit_len;
}


/*Simple function for calcating the value of number in modulo of another number
* 
* a - the number of which it is wanted to calulate the modulo
* b - the modulo respect to which we wanted to calulate the value of a  
* 
* Return a mod b
*/
unsigned int mod (int a, int b)
{
	int ret = a % b;
    if(ret < 0)
    	ret+=b;
    return ret;
}

/* Theta step of Keccak-p function
* s - pointer to the string representing the stare array
*/
void keccakp_theta (uint64_t *s)
{

	uint64_t C[5];
	uint64_t D[5];
	unsigned int j = 0, count = 0;

	for (j = 0; j < 5; j ++){
		C[j] = s[mapping (j, 0)] ^ s[mapping (j, 1)] ^ s[mapping (j, 2)] ^ s[mapping (j, 3)] ^ s[mapping (j, 4)];
	}

	for (j = 0; j < 5; j ++){
		D[j] = C[mod((j - 1), 5)] ^ ROL64 (C[mod ((j + 1), 5)], 1);
	}

	/* Final step of theta 
	* j represents x index
	* count represents y index
	*/
	for (j = 0; j < 5; j ++){
		for (count = 0; count < 5; count ++){
			s[mapping(j,count)] ^= D[j];
		}
	}
}

/* Rho step of Keccak-p function
* s - pointer to the string representing the stare array
*/
void keccakp_rho (uint64_t *s)
{
	int x = 1, y = 0, temp = 0; 
	int val, val2; 
	for (int t = 0; t < 24; t++){
		val2 = (t+1)*(t+2); //parameter for macro ROL64
		s[mapping(x, y)] = ROL64 (s[mapping(x, y)], (val2/2));
		/* Changing indexes: (x, y) = (y, (2x + 3y)mod 5)*/
		temp = x; 
		x = y; 
		val = (2*temp) + (3*y);
		y =  mod(val, 5); 
	}

}

/* Pi step of Keccak-p function
* s - pointer to the string representing the stare array
*/
void keccakp_pi (uint64_t *s)
{

	unsigned int x = 1, y = 0; 
	unsigned int x2 = 0, y2 = 0; 
	unsigned int posInitial = 0; 
	unsigned int posInitialFlag = mapping (x, y); //index of (1, 0)
	unsigned int posNext = 0; 
	uint64_t s1 = s[posInitialFlag]; //save the element in position number one 

	/* For all the element, perform the operation: A[x,y] = A[(x+3y)mod 5, x] */
	/* Since this operation should be performed for all the values of x and y 
	* it is necessary to initialize x or y to a value different to 0,
	* otherwise in each iteraction of the while loop above 
	* will not change the values of x and y ( mapping (0,0) == (0,0) ).
	* If (x, y) are initialized to (1, 0), the element at this index
	* will be changed, thus it is necessary to store its initial value 
	* somewhere (in s1), in order to assign it later to another element
	* when required.
	*/
	while (posNext != posInitialFlag){
		posInitial = mapping (x, y); //find the position in the string for the left element of the operation
		y2 = x; //y index for the right element of the operation
		x2 = mod ((x + 3*y), 5); //x index for the right element of the operation
		posNext = mapping (x2, y2); //find the position in the string for the right element of the operation

		/* The element is position 1 has been modified by previous iteraction, so we cannot perform 
		* a normal assignment operation, but we need to assign the old value of the element s[1],
		* previous saved in s1 */
		if(posNext != posInitialFlag) 
			s[posInitial] = s[posNext]; //the operation is normally performed
		else s[posInitial] = s1;  
		/* Changing x and y value for the next iteration */ 
		x = x2;
		y = y2;
	} 

}


/* Chi step of Keccak-p function
* s - pointer to the string representing the stare array
*/
void keccakp_chi (uint64_t *s)
{

	uint64_t s0, s1;

	/* The standard specifies the operation A XOR 1  
	* A XOR 1 == NOT A 
	* 
	* The y value of the state arrays element involved 
	* in the operation specified by the standard is always the same, 
	* meanwhile the x value changes. 
	* Here five operations (one for each x value) for each y value are performed.
	* It was not possible to perform to nested for-loops because 
	* the value of the element indicated by the indxes was referred
	* to old values. With two nested for-loops, some operation would be affected
	* because new values would be involved.
	* Old values that would have been affected by that operations
	* are saved at the beginning and then used.
	*/
	for (int y = 0; y < 5; y ++){
		s0 = s[mapping (0, y)]; //
		s1 = s[mapping (1, y)]; //
		s[mapping (0,y)] ^= ~s1 & s[mapping (2,y)];
		s[mapping (1,y)] ^= ~s[mapping (2,y)] & s[mapping (3,y)];
		s[mapping (2,y)] ^= ~s[mapping (3,y)] & s[mapping (4,y)];
		s[mapping (3,y)] ^= ~s[mapping (4,y)] & s0;
		s[mapping (4,y)] ^= ~s0 & s1;
	}
}

/* Iota step of Keccak-p function
* s      - pointer to the string representing the stare array
* nround - identification number of the current round
*/
void keccakp_iota (uint64_t *s, unsigned int nround)
{
	/* Just the first element of the state array is modified, 
	* according to the number of the current round. 
	*/
	s[0] ^= RC [nround];  
}


/* Main body of Kekkak-p function
*
* s        - Input string 
* nrounds  - Number of permutation rounds
*/
void keccakp (void *a)
{

	/* Casting to uint64_t
	* In this way the string can be treated as a set of lanes
	* Each uint64_t is a lane
	*/
	uint64_t *s = (uint64_t*)a; 
	/* Keccap is called for NROUNDS times*/
	for (int i = 0; i < NROUNDS; i++){
		/* All the various step of KeccakP are called*/
		/*Theta step*/
		keccakp_theta (s);
		/*Rho step*/
		keccakp_rho (s);
		/*Pi step*/
		keccakp_pi (s);
		/*Chi step*/
		keccakp_chi (s);
		/*Iota step*/
		keccakp_iota (s, i);
	}
}






