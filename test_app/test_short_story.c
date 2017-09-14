#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "test_app.h"
#include "test_helper.h"

/* Runs tests on the short_story capsule */
static char capsule_dir[] = "/etc";
static char capsule_short_story[] = "short_story.capsule";
static char capsule_short_story_copy[] = "short_story_copy.capsule";
static char data_short_story[] = "short_story.data";
static char data_short_story_copy[] = "short_story_copy.data";

/* Launch two processes, one reads and writes to short_story_copy
 * capsule, another reads and writes to the short_story_capsule */
static int test_short_story_multi_3(void) {

	int    		 child_pid;
	int    		 fd, res, status, file_control;
	int          nr, nw, ns, whence;
	char   		 file_cap_abs[MAX_PATH];
	char         file_copy_abs[MAX_PATH];
	int    		 run_sec = 2;
	unsigned int endTime = time(0) + run_sec;
	char         write_proc[] = "abcdefghijklmnopqrstuvwxyz";
	char         read_buf[25];
	int          ret = 0;

	abs_construct( file_cap_abs, capsule_dir, capsule_short_story );
	abs_construct( file_copy_abs, capsule_dir, capsule_short_story_copy );

	/* Start first process */
	file_control = 1;
	child_pid = fork();
	if( child_pid < 0 ) {
		printf( "test_short_story_multi_3(): error, unable to fork 1st process," 
				"ret %d\n", child_pid );
		return -1;
	} 

	/* Start second process */
	if( child_pid > 0 ) {
		file_control = 0;
		child_pid = fork();
		if( child_pid < 0 ) {
			printf( "test_short_story_multi_3(): error, unable to fork 2nd process"
					", ret %d\n", child_pid );
			wait( &status );
			return -1;
		} 
	}
	

	if( child_pid == 0 ) {
		if( file_control == 1 ) {
			fd = open_file( file_cap_abs, O_RDWR );
		} else {
			fd = open_file( file_copy_abs, O_RDWR );
		}
			
		CHECK_EXIT( fd, "test_short_story_multi_3(): parent pid %d cannot open"
				    	" abs path %s\n", getpid(), file_control == 1 ?
						file_cap_abs : file_copy_abs );	

		nr = 25;
		nw = 25;
		ns = 100;	
		whence = SEEK_SET;
		
		while( time(0) < endTime ) {	

			write_file( fd, ns, whence, write_proc, nw );
			read_file( fd, ns, whence, read_buf, nr );
			
			if( strncmp( read_buf, write_proc, nw ) != 0 ) {
				printf( "test_short_story_multi_3(): PID %d read %s but written"
						" %s in file %s\n", getpid(), read_buf, write_proc,
					    file_control == 1 ? file_cap_abs : file_copy_abs );
				exit(-1);
			}
		}

		res = close( fd );
		CHECK_EXIT( fd, "test_short_story_multi_3(): parent pid %d cannot close"
					     " abs path %s\n", getpid(), file_control == 1 ?
						 file_cap_abs : file_copy_abs );	
	
		exit(0);
	}

	/* Wait for the first process to finish */
	if( wait( &status ) == -1 ) {
		printf( "test_short_story_multi_3(): error, unable to wait on SIGCHLD\n" );
		return -1;		
	}

	if( WIFEXITED( status ) ) {
		if( WEXITSTATUS( status ) != 0 ) {
			ret = -1;
		}
	}

	/* Wait for the second process to finish */
	if( wait( &status ) == -1 ) {
		printf( "test_short_story_multi_3(): error, unable to wait on SIGCHLD\n" );
		return -1;		
	}

	if( WIFEXITED( status ) ) {
		if( WEXITSTATUS( status ) != 0 ) {
			ret = -1;
		}
	}

	return ret;
}
/* Launch two processes, one reads and writes
 * to the short_story_capsule and other reads and writes 
 * to another file */
static int test_short_story_multi_2(void) {

	int    		 child_pid;
	int    		 fd, res, status, file_control;
	int          nr, nw, ns, whence;
	char   		 file_cap_abs[MAX_PATH];
	char         file_data_abs[MAX_PATH];
	int    		 run_sec = 2;
	unsigned int endTime = time(0) + run_sec;
	char         write_proc[] = "abcdefghijklmnopqrstuvwxyz";
	char         read_buf[25];
	int          ret = 0;

	abs_construct( file_cap_abs, capsule_dir, capsule_short_story );
	abs_construct( file_data_abs, capsule_dir, data_short_story );

	/* Start first process */
	file_control = 1;
	child_pid = fork();
	if( child_pid < 0 ) {
		printf( "test_short_story_multi_2(): error, unable to fork 1st process," 
				"ret %d\n", child_pid );
		return -1;
	} 

	/* Start second process */
	if( child_pid > 0 ) {
		file_control = 0;
		child_pid = fork();
		if( child_pid < 0 ) {
			printf( "test_short_story_multi_2(): error, unable to fork 2nd process"
					", ret %d\n", child_pid );
			wait( &status );
			return -1;
		} 
	}
	

	if( child_pid == 0 ) {
		if( file_control == 1 ) {
			fd = open_file( file_cap_abs, O_RDWR );
		} else {
			fd = open_file( file_data_abs, O_RDWR );
		}
		
		CHECK_EXIT( fd, "test_short_story_multi_2(): parent pid %d cannot open"
				    	" abs path %s\n", getpid(), file_control == 1 ?
						file_cap_abs : file_data_abs );	

		nr = 25;
		nw = 25;
		ns = 100;	
		whence = SEEK_SET;
		
		while( time(0) < endTime ) {	

			write_file( fd, ns, whence, write_proc, nw );
			read_file( fd, ns, whence, read_buf, nr );
			
			if( strncmp( read_buf, write_proc, nw ) != 0 ) {
				printf( "test_short_story_multi_2(): PID %d read %s but written"
						" %s in file %s\n", getpid(), read_buf, write_proc,
					    file_control == 1 ? file_cap_abs : file_data_abs );
				exit(-1);
			}
		}

		res = close( fd );
		CHECK_EXIT( fd, "test_short_story_multi_2(): parent pid %d cannot close"
					     " abs path %s\n", getpid(), file_control == 1 ?
						 file_cap_abs : file_data_abs );	
	
		exit(0);
	}

	/* Wait for the first process to finish */
	if( wait( &status ) == -1 ) {
		printf( "test_short_story_multi_2(): error, unable to wait on SIGCHLD\n" );
		return -1;		
	}

	if( WIFEXITED( status ) ) {
		if( WEXITSTATUS( status ) != 0 ) {
			ret = -1;
		}
	}

	/* Wait for the second process to finish */
	if( wait( &status ) == -1 ) {
		printf( "test_short_story_multi_2(): error, unable to wait on SIGCHLD\n" );
		return -1;		
	}

	if( WIFEXITED( status ) ) {
		if( WEXITSTATUS( status ) != 0 ) {
			ret = -1;
		}
	}

	return ret;
}
/* Launch two processes, both which reads and writes
 * to the short_story_capsule */
static int test_short_story_multi_1(void) {

	int    		 child_pid;
	int    		 fd, res, status, write_control;
	int          nr, nw, ns, whence;
	char   		 file_cap_abs[MAX_PATH];
	int    		 run_sec = 5;
	unsigned int endTime = time(0) + run_sec;
	char         write_proc1[] = "abcdefghijklmnopqrstuvwxyz";
	char         write_proc2[] = "zyxwvutsrqponmlkjihgfedcba";
	char         read_buf[25];
	int          ret = 0;

	abs_construct( file_cap_abs, capsule_dir, capsule_short_story );

	/* Start first process */
	write_control = 1;
	child_pid = fork();
	if( child_pid < 0 ) {
		printf( "test_short_story_multi_1(): error, unable to fork 1st process," 
				"ret %d\n", child_pid );
		return -1;
	} 

	/* Start second process */
	if( child_pid > 0 ) {
		write_control = 2;
		child_pid = fork();
		if( child_pid < 0 ) {
			printf( "test_short_story_multi_1(): error, unable to fork 2nd process"
					", ret %d\n", child_pid );
			wait( &status );
			return -1;
		} 
	}
	

	if( child_pid == 0 ) {
		fd = open_file( file_cap_abs, O_RDWR );
		CHECK_EXIT( fd, "test_short_story_multi_1(): parent pid %d cannot open"
				     " abs path %s\n", getpid(), file_cap_abs );	

		nr = 25;
		nw = 25;
		ns = 100;	
		whence = SEEK_SET;
		
		while( time(0) < endTime ) {	

			if( write_control == 1 ) 	
				write_file( fd, ns, whence, write_proc1, nw );
		
			if( write_control == 2 )
				write_file( fd, ns, whence, write_proc2, nw );
		
			read_file( fd, ns, whence, read_buf, nr );
			if( strncmp( read_buf, write_proc1, nw ) != 0 &&
				strncmp( read_buf, write_proc2, nw ) != 0 ) {
				printf( "test_short_story_multi_1(): PID %d read %s but written either"
						" %s or %s\n", getpid(), read_buf, write_proc1, write_proc2 );
				exit(-1);
			}
		}

		res = close( fd );
		CHECK_EXIT( fd, "test_short_story_multi_1(): parent pid %d cannot close"
					     " abs path %s\n", getpid(), file_cap_abs );	
	
		exit(0);
	}

	/* Wait for the first process to finish */
	if( wait( &status ) == -1 ) {
		printf( "test_short_story_multi_1(): error, unable to wait on SIGCHLD\n" );
		return -1;		
	}

	if( WIFEXITED( status ) ) {
		if( WEXITSTATUS( status ) != 0 ) {
			ret = -1;
		}
	}

	/* Wait for the second process to finish */
	if( wait( &status ) == -1 ) {
		printf( "test_short_story_multi_1(): error, unable to wait on SIGCHLD\n" );
		return -1;		
	}

	if( WIFEXITED( status ) ) {
		if( WEXITSTATUS( status ) != 0 ) {
			ret = -1;
		}
	}

	return ret;
}


int test_short_story_multi() {
	
	int res;
	int child;
	
	res = test_short_story_multi_1();
	CHECK_ERROR( res, "test_short_story_multi_1(): failed\n" );
	PRINT_INFO( "test_short_story_multi_1(): passed\n" );
	
	res = test_short_story_multi_2();
	CHECK_ERROR( res, "test_short_story_multi_2(): failed\n" );
	PRINT_INFO( "test_short_story_multi_2(): passed\n" );

	res = test_short_story_multi_3();
	CHECK_ERROR( res, "test_short_story_multi_3(): failed\n" );
	PRINT_INFO( "test_short_story_multi_3(): passed\n" );
	
	return 0;
}

/* We perform write on the short_story capsule. We also perform
 * a write on a regular file. Finally we perform a write 
 * on short_story_copy capsule */
static int test_short_story_single_3(void) {

	int   fd_cap, fd_copy, fd_data;
	int   nr, nw, ns, whence;
	int   res, i;
	char  file_cap_abs[MAX_PATH];
	char  file_data_abs[MAX_PATH];
	char  file_copy_abs[MAX_PATH];
	char  buf_cap[1024];
	char  buf_data[1024];
	char  buf_copy[1024];

	char  write_buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";

	abs_construct( file_cap_abs, capsule_dir, capsule_short_story );
	abs_construct( file_data_abs, capsule_dir, data_short_story );
	abs_construct( file_copy_abs, capsule_dir, capsule_short_story_copy);

	fd_cap = open_file( file_cap_abs, O_RDWR );
	CHECK_ERROR( fd_cap, "test_short_story_single_3(): cannot open abs path cap %s\n",
					      file_cap_abs );
	fd_data = open_file( file_data_abs, O_RDWR );
	CHECK_ERROR( fd_data, "test_short_story_single_3(): cannot open abs path data %s\n",
						  file_data_abs );
	fd_copy = open_file( file_copy_abs, O_RDWR );
	CHECK_ERROR( fd_data, "test_short_story_single_3(): cannot open abs path copy %s\n",
						  file_copy_abs );

	/* Write 30 bytes from offset 100 of capsule */
	nw = 30;
	ns = 100;	
	whence = SEEK_SET;
	
	nw = write_file( fd_cap, ns, whence, write_buf, nw );
	nw = write_file( fd_copy, ns, whence, write_buf, nw );
	nw = write_file( fd_data, ns, whence, write_buf, nw );

	/* Write 40 bytes to the end of the capsule */
	nw = 40;
	ns = 0;	
	whence = SEEK_END;
	nw = write_file( fd_cap, ns, whence, write_buf, nw );
	nw = write_file( fd_copy, ns, whence, write_buf, nw );
	nw = write_file( fd_data, ns, whence, write_buf, nw );

	/* Read the beginning of file */
	nr = 200;
	ns = 0;
	whence = SEEK_SET;
	
	nr = read_file( fd_cap, ns, whence, buf_cap, nr );
	nr = read_file( fd_copy, ns, whence, buf_copy, nr );
	nr = read_file( fd_data, ns, whence, buf_data, nr );

	COMPARE_TEXT( "test_short_story_single_3", 1, i, buf_cap, buf_data, nr ); 
	COMPARE_TEXT( "test_short_story_single_3", 2, i, buf_copy, buf_data, nr );

	/* Read the ending of file */
	nr = 200;
	ns = -100;
	whence = SEEK_END;
	
	nr = read_file( fd_cap, ns, whence, buf_cap, nr );
	nr = read_file( fd_copy, ns, whence, buf_copy, nr );
	nr = read_file( fd_data, ns, whence, buf_data, nr );

	COMPARE_TEXT( "test_short_story_single_3", 1, i, buf_cap, buf_data, nr ); 
	COMPARE_TEXT( "test_short_story_single_3", 2, i, buf_copy, buf_data, nr );
	
	res = close( fd_data );
	CHECK_ERROR( res, "test_short_story_single_2(): cannot close abs path data %s\n",
					  file_data_abs );
	res = close( fd_copy );
	CHECK_ERROR( res, "test_short_story_single_2(): cannot close abs path copy %s\n",
					  file_copy_abs );
	res = close( fd_cap );
	CHECK_ERROR( res, "test_short_story_single_2(): cannot close abs path cap %s\n",
					  file_cap_abs );
	return 0;
}

/* We perform read on the short_story capsule. We also perform
 * a read on a regular file. Finally we perform a read 
 * on short_story_copy capsule */
static int test_short_story_single_2(void) {
	int   fd_cap, fd_copy, fd_data;
	int   nr, ns, whence;
	int   res, i;
	char  file_cap_abs[MAX_PATH];
	char  file_data_abs[MAX_PATH];
	char  file_copy_abs[MAX_PATH];
	char  buf_cap[1024];
	char  buf_data[1024];
	char  buf_copy[1024];

	abs_construct( file_cap_abs, capsule_dir, capsule_short_story );
	abs_construct( file_data_abs, capsule_dir, data_short_story );
	abs_construct( file_copy_abs, capsule_dir, capsule_short_story_copy);

	fd_cap = open_file( file_cap_abs, O_RDWR );
	CHECK_ERROR( fd_cap, "test_short_story_single_2(): cannot open abs path cap %s\n",
					      file_cap_abs );
	fd_data = open_file( file_data_abs, O_RDWR );
	CHECK_ERROR( fd_data, "test_short_story_single_2(): cannot open abs path data %s\n",
						  file_data_abs );
	fd_copy = open_file( file_copy_abs, O_RDWR );
	CHECK_ERROR( fd_data, "test_short_story_single_2(): cannot open abs path copy %s\n",
						  file_copy_abs );

	/* Read 10 bytes from start */

	nr = 10;
	ns = 0;
	whence = SEEK_SET;
	
	nr = read_file( fd_cap, ns, whence, buf_cap, nr );
	nr = read_file( fd_copy, ns, whence, buf_copy, nr );
	nr = read_file( fd_data, ns, whence, buf_data, nr );

	COMPARE_TEXT( "test_short_story_single_2", 1, i, buf_cap, buf_data, nr ); 
	COMPARE_TEXT( "test_short_story_single_2", 2, i, buf_copy, buf_data, nr );

	/* Read 20 bytes from end */
	nr = 30;
	ns = -20;
	whence = SEEK_END;
	
	nr = read_file( fd_cap, ns, whence, buf_cap, nr );
	nr = read_file( fd_copy, ns, whence, buf_copy, nr );
	nr = read_file( fd_data, ns, whence, buf_data, nr );

	COMPARE_TEXT( "test_short_story_single_2", 3, i, buf_cap, buf_data, nr ); 
	COMPARE_TEXT( "test_short_story_single_2", 4, i, buf_copy, buf_data, nr );

	res = close( fd_data );
	CHECK_ERROR( res, "test_short_story_single_2(): cannot close abs path data %s\n",
					  file_data_abs );
	res = close( fd_copy );
	CHECK_ERROR( res, "test_short_story_single_2(): cannot close abs path copy %s\n",
					  file_copy_abs );
	res = close( fd_cap );
	CHECK_ERROR( res, "test_short_story_single_2(): cannot close abs path cap %s\n",
					  file_cap_abs );

    return 0;
}
/* Simply open and close a trusted capsule file
 * and a regular file. We test it opening the same
 * capsule file twice and opening a regular file
 * before and after it has accessed a trusted
 * capsule */
static int test_short_story_single_1(void) {
	int   fd_reg_before, fd_reg_after, fd_cap, fd_cap_rel;
	int   res_close;
	char  file_cap_abs[MAX_PATH];
	char  file_reg_abs[MAX_PATH];
	char *file_cap_rel = capsule_short_story;

	abs_construct( file_cap_abs, capsule_dir, capsule_short_story );
	abs_construct( file_reg_abs, capsule_dir, data_short_story );
	
	fd_reg_before = open_file( file_reg_abs, O_RDWR );
	CHECK_ERROR( fd_reg_before, "test_short_story_single_1(): cannot open abs path reg "
					            "%s before\n", file_reg_abs );

	fd_cap = open_file( file_cap_abs, O_RDWR );
	CHECK_ERROR( fd_cap, "test_short_story_single_1(): cannot open abs path cap %s\n",
					      file_cap_abs );

	chdir( capsule_dir );

	fd_cap_rel = open_file( file_cap_rel, O_RDWR );
	CHECK_ERROR( fd_cap_rel, "test_short_story_single_1(): cannot open rel path cap "
				             "%s\n", file_cap_rel );
   
    fd_reg_after = open_file( file_reg_abs, O_RDWR );
	CHECK_ERROR( fd_reg_after, "test_short_story_single_1(): cannot open abs path reg %s "
				               "after\n", file_reg_abs );

	res_close = close( fd_reg_before );
	CHECK_ERROR( res_close, "test_short_story_single_1(): cannot close abs path reg %s "
					        " before\n", file_reg_abs );

	res_close = close( fd_cap );
	CHECK_ERROR( res_close, "test_short_story_single_1(): cannot close abs path cap %s\n",
					         file_cap_abs );

	res_close = close( fd_reg_after );
	CHECK_ERROR( res_close, "test_short_story_single_1(): cannot close abs path reg %s "
					        "after\n", file_reg_abs );

	res_close = close( fd_cap_rel );
	CHECK_ERROR( res_close, "test_short_story_single_1(): cannot close rel path %s\n",
					         file_cap_rel );

    return 0;
}

int test_short_story_single() {

	int res;

	res = test_short_story_single_1();
	CHECK_ERROR( res, "test_short_story_single_1(): failed\n" );
	PRINT_INFO( "test_short_story_single_1(): passed\n" );

	res = test_short_story_single_2();
	CHECK_ERROR( res, "test_short_story_single_2(): failed\n" );
	PRINT_INFO( "test_short_story_single_2(): passed\n" );
	
	res = test_short_story_single_3();
	CHECK_ERROR( res, "test_short_story_single_3(): failed\n" );
	PRINT_INFO( "test_short_story_single_3(): passed\n" );
	return 0;
}
