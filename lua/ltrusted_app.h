#ifndef LTRUSTED_APP_H
#define LTRUSTED_APP_H

#define HUGE_VAL (__builtin_huge_val())
#define __HI(x)  *(1+(int*)&x)
#define __LO(x)  *(int*)&x


#undef strspn
size_t strspn( const char* str1, const char *str2 );

#undef strchr
char* strchr( const char* str, int character );

char* strcpy( char* destination, const char* source );

double strtod(const char* str, char** endptr);

const char* strpbrk_me( const char* str1, const char* str2 );

int strcoll( const char* str1, const char* str2 );

#undef isalnum
int isalnum( int c );

#undef isdigit
int isdigit( int c );

#undef toupper
int toupper( int c );

#undef tolower
int tolower( int c );

#undef isalpha
int isalpha( int c );

#undef iscntrl
int iscntrl( int c );

#undef isgraph
int isgraph( int c );

#undef islower
int islower( int c );

#undef ispunct
int ispunct( int c );

#undef isspace
int isspace( int c );

#undef isupper
int isupper( int c );

#undef isxdigit
int isxdigit( int c );

int abs( int c );


double floor( double c );

double ceil( double c );

double pow( double base, double exponent );

double fmod( double num, double denom );

double frexp( double x, int* exp );


#ifdef TRUSTED_APP_BUILD
int rand(void);
void abort( void );
#endif


#endif 
