#include <stdlib.h>
#include <string.h>
#include "ltrusted_app.h"
#include "luaconf.h"
#include "lauxlib.h"
#include "math_private.h"

char* strchr( const char* str, int character ) {
	while( *str && *str != character )
		str++;
	if( *str == character )
		return (char*) str;
	return NULL;
}

char* strcpy( char* destination, const char* source ) {
	char* dest0 = destination;
	
	while( ( *destination++ = *source++ ) );

	return dest0;
}

size_t strspn( const char* str1, const char *str2 ) {

	const char *s1 = str1;	
	const char *c;

	while( *s1 ) {
		for( c = str2; *c; c++ ) {
			if( *s1 == *c )
				break;
		}	

		if( *c == '\0' )
			break;
		s1++;
	}
		
	return s1 - str1;
}

int strcoll( const char* str1, const char* str2 ) {
	return strcmp( str1, str2 );
}

static int isneg( const char **s ) {
	if( **s == '-' ) { (*s)++; return 1; }
	else if( **s == '+' ) (*s)++;
	return 0;
}

static int hex2d( int c ) {
	if( isdigit(c) ) return c - '0';
	else return ( tolower(c) - 'a' ) + 10;
}

double strtod( const char* s, char** endptr ) {

#define MAXDIG 30

	int dot = lua_getlocaledecpoint();
	double r = 0.0; /* result accumulator */
	int neg; /* 1 if number is negative */
	int neg_exp; /* 1 if exponent is negative */
	int e = 0;
	int exp = 0;
	int hasdot = 0; /* true after seen a dot */
	int base = 0.0; /* decimal is 10, hex is 16 */
	int sigfig = 0; /* number of significant digits */
	*endptr = (char*)(void*) s;

	while (isspace(*s)) s++; /* skip initial spaces */
	neg = isneg( &s ); /* check sign */
	
	if( (*s =='0' && ( *(s+1) == 'x' || *(s+1) == 'X' )) ) {
		//printf("base is 16.0\n");
		base = 16.0; /* hex */
		s += 2;
	} else if( isdigit( *s ) ) {
		//printf("base is 10.0\n");
		base = 10.0; /* decimal */
	} else {
		return 0.0; /* invalid format */
	}

	/* Iteratively read the numerals */
	for( ;;s++ ) {
		//printf("r: %f, e: %d, *s: %c\n", r, e, *s );
		if( *s == dot ) {
			if( hasdot ) break;
			else hasdot = 1;
		} else if( (base == 16.0 && isxdigit(*s)) ||
				   (base == 10.0 && isdigit(*s)) ) {
			if( *s == '0' && sigfig == 0 ) continue;  
			else if( ++sigfig <= MAXDIG ) 
				r = r * base + ( base == 16.0 ? hex2d( *s ) : (*s) - '0' ); 
			else e++; /* On overflow, we just keep track of exponents */
			if (hasdot) e--;

		}
		else break;
	}	

	*endptr = (char*)(void*) s;

	if( base == 16.0 && (*s == 'p' || *s == 'P') ) {
		s++;
		neg_exp = isneg( &s );
		if( !isdigit(*s) )
			return 0.0;
		while( isdigit(*s) )
			exp = exp * 10 + *(s++) -'0';
		if ( neg_exp ) exp = -exp;
		*endptr = (char*)(void*) s;		
	}
	if (neg) r = -r;

	//printf("r: %f\n", r);

	while( e > 0 ) {
		r *= base == 16.0 ? 16.0 : 10.0;
		e--;
	}

	while( e < 0 ) {
		r /= base == 16.0 ? 16.0 : 10.0;
		e++;
	}

	while( exp > 0 ) {
		r *= 2.0;
		exp--;
	}
	
	while( exp < 0 ) {
		r /= 2.0;
		exp--;
	}


	return r;
}

const char* strpbrk_me( const char* str1, const char* str2 ) {
	const char *c = str2;
	
	if( !*str1 )
		return NULL;

	while( *str1 ) {
		for( c = str2; *c; c++ ) {
			if( *str1 == *c )
				break;
		}

		if( *c )
			break;
		str1++;
	}

	if( *c == '\0' )
		str1 = NULL;

	return str1;
}

int isalpha( int c ) {
	return( islower(c) || isupper(c) );
}

int isalnum( int c ) {
	return( isalpha(c) || isdigit(c) );
}

int isdigit( int c ) {
	return( c >= '0' && c <= '9' );
}

int iscntrl( int c ) {
	return( c >= 0x00 && c <= 0x1F); 
}

int isgraph( int c ) {
	return( c >= 0x21 && c <= 0x7E );
}

int islower( int c ) {
	return( c >= 'a' && c <= 'z' );
}

int isspace( int c ) {
	return( c == ' ' || c == '\f' || c == '\n' ||
			 c == '\r' || c == '\t' || c == '\v' );
}

int isupper( int c ) {
	return( c >= 'A' && c <= 'Z' );
}

int isxdigit( int c ) {
	return( isdigit(c) || ( c >= 'a' && c <= 'f' ) ||
			 ( c >= 'A' && c <= 'F' ) );
}

int ispunct( int c ) {
	return( (c >= 0x21 && c <= 0x2F) || (c >= 0x3a && c <= 0x40) ||
			(c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7E) );
}

int toupper( int c ) {
	if( c >= 'a' && c <= 'z' )
		return 'A' + ( c - 'a' );
	return c;
}

int tolower( int c ) {
	if( c >= 'A' && c <= 'Z' )
		return 'a' + ( c - 'A' );
	return c;
}

int abs( int c ) {
	return c  < 0 ? -c : c;
}

double floor( double x ) {
	int32_t 	 i0,i1,_j0;
	uint32_t	 i,j;
	double       huge = HUGE_VAL;
	
	EXTRACT_WORDS(i0,i1,x);
	_j0 = ((i0>>20)&0x7ff)-0x3ff;
	if(_j0<20) {
	    if(_j0<0) { 	/* raise inexact if x != 0 */
		if(huge+x>0.0) {/* return 0*sign(x) if |x|<1 */
		    if(i0>=0) {i0=i1=0;}
		    else if(((i0&0x7fffffff)|i1)!=0)
			{ i0=0xbff00000;i1=0;}
		}
	    } else {
		i = (0x000fffff)>>_j0;
		if(((i0&i)|i1)==0) return x; /* x is integral */
		if(huge+x>0.0) {	/* raise inexact flag */
		    if(i0<0) i0 += (0x00100000)>>_j0;
		    i0 &= (~i); i1=0;
		}
	    }
	} else if (_j0>51) {
	    if(_j0==0x400) return x+x;	/* inf or NaN */
	    else return x;		/* x is integral */
	} else {
	    i = ((uint32_t)(0xffffffff))>>(_j0-20);
	    if((i1&i)==0) return x;	/* x is integral */
	    if(huge+x>0.0) { 		/* raise inexact flag */
		if(i0<0) {
		    if(_j0==20) i0+=1;
		    else {
			j = i1+(1<<(52-_j0));
			if(j<i1) i0 +=1 ; 	/* got a carry */
			i1=j;
		    }
		}
		i1 &= (~i);
	    }
	}
	INSERT_WORDS(x,i0,i1);
	return x;
}

double ceil( double x ) {
	int32_t 	 i0,i1,_j0;
	uint32_t 	 i,j;
	double       huge = HUGE_VAL;
	
	EXTRACT_WORDS(i0,i1,x);
	_j0 = ((i0>>20)&0x7ff)-0x3ff;
	if(_j0<20) {
	    if(_j0<0) { 	/* raise inexact if x != 0 */
		if(huge+x>0.0) {/* return 0*sign(x) if |x|<1 */
		    if(i0<0) {i0=0x80000000;i1=0;}
		    else if((i0|i1)!=0) { i0=0x3ff00000;i1=0;}
		}
	    } else {
		i = (0x000fffff)>>_j0;
		if(((i0&i)|i1)==0) return x; /* x is integral */
		if(huge+x>0.0) {	/* raise inexact flag */
		    if(i0>0) i0 += (0x00100000)>>_j0;
		    i0 &= (~i); i1=0;
		}
	    }
	} else if (_j0>51) {
	    if(_j0==0x400) return x+x;	/* inf or NaN */
	    else return x;		/* x is integral */
	} else {
	    i = ((uint32_t)(0xffffffff))>>(_j0-20);
	    if((i1&i)==0) return x;	/* x is integral */
	    if(huge+x>0.0) { 		/* raise inexact flag */
		if(i0>0) {
		    if(_j0==20) i0+=1;
		    else {
			j = i1 + (1<<(52-_j0));
			if(j<i1) i0+=1;	/* got a carry */
			i1 = j;
		    }
		}
		i1 &= (~i);
	    }
	}
	INSERT_WORDS(x,i0,i1);
	return x;
}

/* Not Implemented */
double pow( double base, double exponent ) {
	return base * exponent;
}

/* Not Implemented */
double fmod( double num, double denom ) {
	return num * denom;
}

double frexp( double x, int* eptr ) {
	/* 0x43500000, 0x00000000 */
	const double two54 =  1.80143985094819840000e+16; 

	int32_t hx, ix, lx;
	EXTRACT_WORDS(hx,lx,x);
	ix = 0x7fffffff&hx;
	*eptr = 0;
	if(ix>=0x7ff00000||((ix|lx)==0)) return x;	/* 0,inf,nan */
	if (ix<0x00100000) {		/* subnormal */
	    x *= two54;
	    GET_HIGH_WORD(hx,x);
	    ix = hx&0x7fffffff;
	    *eptr = -54;
	}
	*eptr += (ix>>20)-1022;
	hx = (hx&0x800fffff)|0x3fe00000;
	SET_HIGH_WORD(x,hx);
	return x;
}
