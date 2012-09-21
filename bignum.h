#pragma once

#ifdef __cplusplus
extern "C" {
#endif


#define	BIGNUM_MAXDIGITS	100		/* maximum length bignum */ 

typedef struct {
        char digits[BIGNUM_MAXDIGITS];         /* represent the number */
	int signbit;			/* 1 if positive, -1 if negative */ 
        int lastdigit;			/* index of high-order digit */
} bignum;

void byte_arr_to_bignum(unsigned char *s, int bytes, bignum *n);
int bignum_to_str(bignum *n, char *s, int l);
void print_bignum(bignum *n);


#ifdef __cplusplus
}
#endif
