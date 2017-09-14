#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TRUSTED_APP
#include <ltrusted_app.h>
#else
#include <math.h>
#include <ctype.h>
#endif

/* We test our own libc functions in ltrusted_app.c.
 * The makefile produces two binaries:
 * 		main_libc -> uses standard c library
 * 		main_ta -> uses ltrusted_app.c
 *
 * 	To compare, we run both files and check if their
 * 	output is the same using diff.
 *
 * 	e.g.  ./main_libc > out1
 * 	      ./main_ta > out2
 * 	      diff out1 out2
 */

static void test_stdlib_functions() {
	/* abs */
	printf( "abs(): %d %d\n", abs(2), abs(-1) );

	/* strtod */
	double a, b, c;
	char todtext1[] = "0x00b0.a1p2 hellow world";
	char todtext2[] = "  -2.8pfg";
	char todtext3[] = " d12x";
	char *ptr1, *ptr2, *ptr3;

	a = strtod( todtext1, &ptr1 );
	b = strtod( todtext2, &ptr2 );
	c = strtod( todtext3, &ptr3 );

	printf( "strtod(): %f %lu %f %lu %f %lu\n", 
			a, ptr1 - todtext1,
			b, ptr2 - todtext2,
			c, ptr3 - todtext3 );	 
}

/* The return value might differ in value, but it is its
 * signedness that matters */
static void test_ctype_functions() {
	
	/* toupper */
	printf( "toupper(): %c %c %c\n", 
			toupper('a'), toupper('B'), toupper('/') );
	
	/* tolower */
	printf( "tolower(): %c %c %c\n", 
			tolower('a'), tolower('B'), tolower('/') );
	
	/* isalnum */
	printf( "isalnum(): %s %s %s %s %s\n", 
			isalnum('0') > 0 ? "true" : "false", 
			isalnum('9') > 0 ? "true" : "false",
		    isalnum('a') > 0 ? "true" : "false",	
			isalnum('Z') > 0 ? "true" : "false",
		   	isalnum('^') > 0 ? "true" : "false" );

	/* isdigit */
	printf( "isdigit(): %s %s %s\n", 
			isdigit('0') > 0 ? "true" : "false", 
			isdigit('9') > 0 ? "true" : "false", 
			isdigit('a') > 0 ? "true" : "false" );

	/* isxdigit */
	printf( "isxdigit(): %s %s %s %s %s\n", 
			isxdigit('0') > 0 ? "true" : "false", 
			isxdigit('9') > 0 ? "true" : "false", 
			isxdigit('a') > 0 ? "true" : "false", 
			isxdigit('F') > 0 ? "true" : "false", 
			isxdigit('g') > 0 ? "true" : "false" );

	/* isalpha */
	printf( "%s %s %s\n", 
			isalpha('a') > 0 ? "true" : "false", 
			isalpha('Z') > 0 ? "true" : "false", 
			isalpha('0') > 0 ? "true" : "false" );

	/* iscntrl */
	printf( "%s %s %s\n", 
			iscntrl('\0') > 0 ? "true" : "false", 
			iscntrl('\n') > 0 ? "true" : "false", 
			iscntrl(' ') > 0 ? "true" : "false" );

	/* isgraph */
	printf( "%s %s\n", 
			isgraph('+') > 0 ? "true" : "false", 
			isgraph(' ') > 0 ? "true" : "false" );

	/* isspace */
	printf( "%s %s %s\n", 
			isspace(' ') > 0 ? "true" : "false", 
			isspace('\t') > 0 ? "true" : "false", 
			isspace('&') > 0 ? "true" : "false" );

	/* ispunct */
	printf( "%s %s %s\n", 
			ispunct('.') > 0 ? "true" : "false", 
			ispunct(',') > 0 ? "true" : "false", 
			ispunct('a') > 0 ? "true" : "false" );
	
	/* islower */
	printf( "%s %s %s\n", 
			islower('a') > 0 ? "true" : "false", 
			islower('A') > 0 ? "true" : "false", 
			islower('/') > 0 ? "true" : "false" );
	
	/* isupper */
	printf( "%s %s %s\n", 
			isupper('a') > 0 ? "true" : "false", 
			isupper('A') > 0 ? "true" : "false", 
			isupper('/') > 0 ? "true" : "false" );
}	

static void test_string_functions() {
	/* strspn() */
	char spntext[] = "129th";
	char spncset1[] = "12345689";
	char spncset2[] = "abc";

	printf( "strspn(): %lu %lu\n", strspn( spntext, spncset1 ), 
								 strspn( spntext, spncset2 ) );

	/* strchr */
	char chrtext[] = "This is a sample string";
	char *chr1, *chr2;
	chr1 = strchr( chrtext, 's' );
	chr2 = strchr( chrtext, 'c' );
	printf( "strchar(): %lu %lu\n", chr1 == NULL ? 0 : chr1-chrtext+1, 
								  chr2 == NULL ? 0 : chr2-chrtext+1 );

	/* strcpy */
	char cpytext[] = "What is this in the name of the king";
	char restext[128];
	char *res = strcpy( restext, cpytext );
	printf( "strcpy(): %s %s\n", res, restext );

	/* strpbrk */
	char pbrktext[] = "This is a sample string";
    char key1[] = "aeiou";
	char key2[] = "bdf";
	const char *ch1, *ch2;
#ifdef TRUSTED_APP
	ch1 = strpbrk_me( pbrktext, key1 );
	ch2 = strpbrk_me( pbrktext, key2 );	
#else
	ch1 = strpbrk( pbrktext, key1 );
	ch2 = strpbrk( pbrktext, key2 );
#endif
	printf( "strpbrk(): %c %c\n", ch1 == NULL ? '\0' : *ch1,
								  ch2 == NULL ? '\0' : *ch2 );

	/* strcoll */
	char str1[] = "a bit small";
	char str2[] = "A bit small";
	char str3[] = "BDFA";

	printf( "strcoll(): %d %d %d %d\n", strcoll( str1, str1 ),
										strcoll( str1, str2 ),
										strcoll( str1, str3 ),
										strcoll( str3, str2 ) );
}

static void test_math_functions() {
	int e1, e2, e3;
	double a, b, c;
	/* test floor */
	printf( "floor(): %f %f %f\n", floor(0.5), floor(1.5), floor(-0.3) );
	/* test ceil */
	printf( "ceil(): %f %f %f\n", ceil(0.5), ceil(1.5), ceil(-0.3) ); 
	/* test frexp */
	a = frexp( 0.52, &e1 );
	b = frexp( 102341.212, &e2 );
	c = frexp( -1923.2512, &e3 );
	printf( "frexp(): %f %d %f %d %f %d\n", a, e1, b, e2, c, e3 );
}

int main() {

	test_math_functions();
	test_string_functions();
	test_ctype_functions();
	test_stdlib_functions();	
	
	return 0;
}
