#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <stdlib.h>
#include <string.h>
#include <capsule.h>
#include <amessage.pb-c.h>
#include <serialize_common.h>
#include <lua.h>
#include "capsule_structures.h"
#include "capsule_helper.h"
#include "capsule_op.h"
#include "capsule_ta.h"

TEE_Result do_write_new_policy_network( int dst_fd, unsigned char* policy, 
										uint32_t len ) {
	
	TEE_Result    res = TEE_SUCCESS;
	uint32_t      cnt = 0, nw;

	do_lseek( 0, 0, 0, START, false );

	while( cnt < len ) {
	
		nw = len - cnt;

		res = do_write( dst_fd, 0, 0, policy, &nw, true, false );	
		CHECK_SUCCESS( res, "Do_write() Error" );

		cnt += nw;
	}

	return res;	
}

TEE_Result do_write_new_policy( int src_fd, int dst_fd, uint32_t len ) {
	
	TEE_Result    res = TEE_SUCCESS;
	unsigned char databuf[BLOCK_LEN];
	size_t        dlen = BLOCK_LEN;
	uint32_t      cnt = 0;
	uint32_t      nr, nw;

	do_lseek( 0, 0, 0, START, false );

	while( cnt < len ) {
		
		nr = read_block( src_fd, databuf, dlen );

		if( (int) nr < 0 ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Read_block() Error" );
		}

		nw = nr;

		res = do_write( dst_fd, 0, 0, databuf, &nw, true, false );
		CHECK_SUCCESS( res, "Do_write() Error" );

		if( nw != nr ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Do_write() wrote only %u/%u B",
							    nw, nr );
		}

		cnt += nw;
	}

	return res;	
}

TEE_Result do_move_data_up( int fd, uint32_t newp_len ) {
	
	TEE_Result    		   res = TEE_SUCCESS;
	unsigned char 		   databuf[BLOCK_LEN];
	size_t 		 		   oldp_len, datalen = BLOCK_LEN;
	uint32_t      		   pfd_off, cfd_off, diff_off;
	uint32_t      		   r_len, w_len;
	struct cap_text_entry *temp_entry;

	/* Any operation on the common data must have a cap_text_entry.
	 * Therefore, to get around this and not have to write two different
	 * sets of do_read, do_write and do_lseek, whenever these functions
	 * are called, internally we temporarily allocate an entry into the
	 * list. To be removed at the end of the operation. 
	 */

	temp_entry = TEE_Malloc( sizeof( struct cap_text_entry ), 0 );
	initialize_capsule_entries( temp_entry, 0, 0, cap_head.data_begin );
	LIST_INSERT_END( temp_entry, &cap_head.proc_entries, entries );
	
	oldp_len = cap_head.policy_end - cap_head.policy_begin;
	if( newp_len > oldp_len ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Do_move_data_up()-> should not be called"
						    " new policy length %u B is longer than"
							" current policy length %u B", newp_len,
							oldp_len );
	} else if( newp_len == oldp_len ) {
		return res;
	}

	datalen = datalen / (symm_key_len/8) * (symm_key_len/8); 

	diff_off = oldp_len - newp_len;
	cap_head.policy_end -= diff_off;
	cap_head.data_begin -= ( diff_off + DELIMITER_SIZE );
	pfd_off = diff_off;	
	cfd_off = 0;

	//MSG( "datalen: %u, diff_off: %u (%u/%u), data: %u/%u,policy: %u/%u,"
	//	 " length: %u, pfd_off: %u, cfd_off: %u", datalen, diff_off, 
	//	 newp_len, oldp_len, cap_head.data_begin, cap_head.data_end,
	//	 cap_head.policy_begin, cap_head.policy_end, 
	//	 cap_head.file_len, pfd_off, cfd_off ); 

	while( pfd_off < cap_head.data_end - newp_len ) {
		r_len = ( cap_head.data_end - pfd_off ) > datalen ? 
				datalen : cap_head.data_end - pfd_off;	
	
		do_lseek( 0, 0, pfd_off, START, true );
		res = do_read( fd, 0, 0, databuf, &r_len, true, true );
		CHECK_SUCCESS( res, "Do_read() Error" );

		w_len = r_len;

		do_lseek( 0, 0, cfd_off, START, true );
		res = do_write( fd, 0, 0, databuf, &w_len, true, true );
		CHECK_SUCCESS( res, "Do_write() Error" );

		if( w_len != r_len ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Do_write() wrote only %u/%u B",
							    w_len, r_len );
		}

		pfd_off += w_len;
		cfd_off += w_len;		
	
		//MSG( "r_len: %u, w_len: %u, pfd_off: %u, cfd_off: %u," 
		//	 "  cap_head.data_end: %u", r_len, w_len, pfd_off, 
		//	 cfd_off, cap_head.data_end );
	}

	cap_head.data_begin += DELIMITER_SIZE;	

	/* We also have to remove the rest of the hash_entry in the hash
	 * list if we had truncated the data down */
	res = truncate_data( fd, &hash_head, diff_off, symm_chunk_size,
					     &cap_head );
	
	/* The last chunk would not be hashed correctly when we shorten
	 * the file, so do an empty write on the last chunk after we
	 * have fixed the cap_head.data_end */
	w_len = 0;
	temp_entry->data_pos = cap_head.data_end;
	res = do_write( fd, 0, 0, NULL, &w_len, true, true );
	CHECK_SUCCESS( res, "Do_write() Error" );
	
	//MSG( "policy: %u/%u, data: %u/%u, length: %u", 
	//	 cap_head.policy_begin, cap_head.policy_end, 
	//	 cap_head.data_begin, cap_head.data_end, 
	//	 cap_head.file_len );
	
	LIST_REMOVE( temp_entry, &cap_head.proc_entries, entries );
	TEE_Free( temp_entry );

	return res;
}

TEE_Result do_move_data_down( int fd, uint32_t newp_len ) {
	
	TEE_Result    			res = TEE_SUCCESS;
	unsigned char 			databuf[BLOCK_LEN];
	size_t 		  			oldp_len, datalen = BLOCK_LEN;
	uint32_t      			pfd_off, cfd_off, diff_off;
	uint32_t      			r_len, w_len;
	struct cap_text_entry  *temp_entry;

	/* Any operation on the common data must have a cap_text_entry.
	 * Therefore, to get around this and not have to write two different
	 * sets of do_read, do_write and do_lseek, whenever these functions
	 * are called, internally we temporarily allocate an entry into the
	 * list. To be removed at the end of the operation. 
	 */

	temp_entry = TEE_Malloc( sizeof( struct cap_text_entry ), 0 );
	initialize_capsule_entries( temp_entry, 0, 0, cap_head.data_begin );
	LIST_INSERT_END( temp_entry, &cap_head.proc_entries, entries );

	oldp_len = cap_head.policy_end - cap_head.policy_begin;
	if( newp_len < oldp_len ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Do_move_data_down()-> should not be called"
						    " new policy length %u B is shorter than"
							" current policy length %u B", newp_len,
							oldp_len );
	} else if( newp_len == oldp_len ) {
		return res;
	}

	datalen = datalen / (symm_key_len/8) * (symm_key_len/8); 
	diff_off = newp_len - oldp_len;

	cap_head.data_begin -= DELIMITER_SIZE;
	pfd_off = cap_head.data_end - cap_head.data_begin;
	cfd_off = pfd_off + diff_off;

	//MSG( "datalen: %u, diff_off: %u (%u/%u), data: %u/%u,policy: %u/%u,"
	//	 " length: %u, pfd_off: %u, cfd_off: %u", datalen, diff_off, 
	//	 newp_len, oldp_len, cap_head.data_begin, cap_head.data_end,
	//	 cap_head.policy_begin, cap_head.policy_end, 
	//	 cap_head.file_len, pfd_off, cfd_off ); 

	while( pfd_off > 0 ) {
		r_len = pfd_off > datalen ? datalen : pfd_off;	
		pfd_off -= r_len;
		cfd_off -= r_len;
		
		do_lseek( 0, 0, pfd_off, START, true );
		res = do_read( fd, 0, 0, databuf, &r_len, true, true );
		CHECK_SUCCESS( res, "Do_read() Error" );

		w_len = r_len;

		do_lseek( 0, 0, cfd_off, START, true );
		res = do_write( fd, 0, 0, databuf, &w_len, true, true );
		CHECK_SUCCESS( res, "Do_write() Error" );

		if( w_len != r_len ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Do_write() wrote only %u/%u B",
							    w_len, r_len );
		}	
	}
	
	cap_head.data_begin += ( diff_off + DELIMITER_SIZE );
	cap_head.policy_end += diff_off;

	//MSG( "policy: %u/%u, data: %u/%u, length: %u", 
	//	 cap_head.policy_begin, cap_head.policy_end, 
	//	 cap_head.data_begin, cap_head.data_end, 
	//	 cap_head.file_len );
	LIST_REMOVE( temp_entry, &cap_head.proc_entries, entries );
	TEE_Free( temp_entry );

	return res;
}

int do_lseek( int state_tgid, int state_fd, int offset, 
  			  FILE_POS flag, bool is_data ) {

	struct cap_text_entry *cap_entry = NULL;
	if( is_data ) {
		cap_entry = find_capsule_entry( &cap_head.proc_entries, 
						                state_tgid, state_fd );
		if( cap_entry == NULL ) {
			MSG( "Find_capsule_entry()-> tgid/fd %d/%d not found",
				  state_tgid, state_fd );
			return -1;
		}
	}

	if( flag == START ) {
		if( offset < 0 )
			offset = 0;
		if( is_data ) {
			cap_entry->data_pos = cap_head.data_begin + offset;
		} else {
			cap_head.policy_pos = cap_head.policy_begin + offset;
		}	
	} else if( flag == CUR ) {
		if( is_data ) {
			cap_entry->data_pos += cap_entry->data_pos + offset > 0 ?
								  offset : - (int) cap_entry->data_pos;
		} else {
			cap_head.policy_pos += cap_head.policy_pos + offset > 0 ?
								 offset : (int) -cap_head.policy_pos;
		}
	} else if( flag == END ) {
		if( is_data ) {
			cap_entry->data_pos = cap_head.data_end + offset > 0 ?
								  cap_head.data_end + offset : 0;
		} else {
			if( offset > 0 ) {
				cap_head.policy_pos = cap_head.policy_end;
			} else if( cap_head.policy_end + offset > 0 ) {
				cap_head.policy_pos = cap_head.policy_end + offset;
			} else {
				cap_head.policy_pos = 0;
			}
		}
	}

	if( is_data ) {
		return cap_entry->data_pos;
	}

	return 0;
}

TEE_Result do_read( int fd, int state_tgid, int state_fd, 
				    unsigned char* bp, uint32_t* len, 
				    bool hash_read, bool is_data ) {
	
	TEE_Result				res = TEE_SUCCESS;
	unsigned char   		hash[HASH_LEN];
	unsigned char   		ptx[BLOCK_LEN];
	size_t				    ptxlen = sizeof(ptx);
	size_t       		    plen, hlen = HASH_LEN;
	uint32_t        	    start, end;
	uint32_t			    ch_start, ch_curr, ch_end, ch_last;
    uint32_t 			    bl_curr, bl_end, bl_last_len;
	unsigned char  		   *temp = bp;
	struct cap_text_entry  *cap_entry;
	if( is_data ) {
		cap_entry = find_capsule_entry( &cap_head.proc_entries, 
						                state_tgid, state_fd );
		if( cap_entry == NULL ) {
			MSG( "Find_capsule_entry()-> tgid/fd %d/%d not found",
				  state_tgid, state_fd );
			return -1;
		}
		
		// Calculate the offsets for the data partition
		start = cap_entry->data_pos;
		if( start > cap_head.data_end ) {
			start = cap_head.data_end;
		}
	
		//MSG( "do_read() start:%u len: %u", start, *len);
	
		end = start + *len;
		if( end > cap_head.data_end ) {
			end = cap_head.data_end;
			*len = end - start;
		}
	} else {
		start = cap_head.policy_pos;
		if( start > cap_head.policy_end ) {
			start = cap_head.policy_end;
		}
		
		end = start + *len;
		if( end > cap_head.policy_end ) {
			end = cap_head.policy_end;
			*len = end - start;
		}
	}

	//MSG( "do_read() start: %u, end: %u", start, end);

	ch_start = start / symm_chunk_size;
	ch_end = calc_chk_num( end, symm_chunk_size ); 
	
	ch_last = calc_chk_num( cap_head.data_end,
							symm_chunk_size );	
	bl_last_len = calc_chk_len( cap_head.data_end, 
								symm_chunk_size );

	/* 1. Break the read into multiple chunks 
	 * 2. Call read_enc_file_block() on each chunk to get the
	 *    bytes we want
	 * 3. Calculate the hash for each chunk read
	 */

	//MSG( "Performing a read of %u B starting at %u and ending at"
	//	 " %u into the file %s", *len, start, end, capsule_name );

	for( ch_curr = ch_start; ch_curr <= ch_end; ch_curr++ ) {
		bl_curr = ch_curr == ch_start ? start % symm_chunk_size : 0;
		bl_end = ( ch_curr != ch_end || end % symm_chunk_size == 0 ) ?
				 symm_chunk_size : end % symm_chunk_size;
		
		while( bl_curr < bl_end ) {
			res = read_enc_file_block( fd, ptx, ptxlen, &plen, ch_curr,
									   symm_chunk_size, symm_key_len/8,
									   bl_curr, bl_end - bl_curr, 
									   symm_iv, symm_iv_len, 
									   decrypt_op );
			CHECK_SUCCESS( res, "Read_enc_file_block() Error" );
            if (plen <= 0) {
                return TEE_ERROR_GENERIC; // why?
            }
			memcpy( bp, ptx, plen );
			
			//MSG( "bl_curr: %u, bl_end: %u, plen: %u, ch_curr: %u,"
			//	 " ch_start: %u, ch_end: %u, ptx: %s", bl_curr, bl_end,
			//	 plen, ch_curr, ch_start, ch_end, ptx );
			
			bl_curr += plen;
			bp += plen;
		}
	}


	if( hash_read ) {
		for( ch_curr = ch_start; ch_curr <= ch_end; ch_curr++ ) {
			bl_curr = 0;
	    	bl_end = ch_curr == ch_last ? 
					 bl_last_len : symm_chunk_size; 	

			//MSG( "ch_start: %u, ch_curr: %u, ch_last: %u, ch_end: %u, " 
			//	 "bl_curr: %u, bl_end: %u\n", ch_start, ch_curr, ch_last,
			//	 ch_end, bl_curr, bl_end );

			while( bl_curr < bl_end ) {
				res = read_enc_file_block( fd, ptx, ptxlen, &plen, 
										   ch_curr, symm_chunk_size, 
										   symm_key_len/8, bl_curr, 
										   bl_end - bl_curr, symm_iv, 
										   symm_iv_len, decrypt_op );
				CHECK_SUCCESS( res, "Read_enc_file_block() Error" );
				res = hash_block( ptx, plen, NULL, hlen, false, 
								  hash_op );
				CHECK_SUCCESS( res, "Hash_block() Update Error" );
				bl_curr += plen;
			}

			res = hash_block( NULL, 0, hash, hlen, true, hash_op );
			CHECK_SUCCESS( res, "Hash_block() Do Final Error" );

			if( !verify_hash( ch_curr, &hash_head, hash, hlen ) ) {
				memset( temp, 0, *len );
				res = TEE_ERROR_CORRUPT_OBJECT;
				CHECK_SUCCESS( res, "Verify_hash()-> hash of chunk %u"
								    " does not match", ch_curr );
			}
		}	
	}

	if( is_data ) {
		cap_entry->data_pos += *len;
	} else {
		cap_head.policy_pos += *len;
	}

	return res;
}

TEE_Result do_write( int fd, int state_tgid, int state_fd, 
				     unsigned char* bp, uint32_t* len, 
				     bool hash_write, bool is_data ) {

	TEE_Result		  		res = TEE_SUCCESS;
	uint32_t   		  		start, end;
	uint32_t          		ch_start, ch_curr, ch_end;
	uint32_t          		ch_last_size, ch_last, ch_last_prev;
	uint32_t          		al_start, al_curr, al_end;
	uint32_t				al_read_start, al_read_curr, al_read_end;
	uint32_t				al_write_start, al_write_curr, al_write_end;
	uint32_t 	      		wr_start, wr_curr, wr_end;
	uint32_t          		rlen, wlen;
	uint32_t				write_size;
	uint32_t				increment, write_increment;
	unsigned char     		ptx[symm_chunk_size]; // Change to symm_chunk_size, might need TEE_Malloc
	size_t            		ptxlen = sizeof(ptx) / symm_key_len * symm_key_len;
	size_t					blocklen = BLOCK_LEN / symm_key_len * symm_key_len;
	uint8_t		      		hash[HASH_LEN];
	size_t			  		hlen = sizeof(hash);
	uint8_t					oldhash[HASH_LEN];
	size_t					oldhlen = sizeof(oldhash);
	struct TrustedCap 		header;
	struct cap_text_entry  *cap_entry;
	
	if( is_data ) {
		cap_entry = find_capsule_entry( &cap_head.proc_entries, 
						                state_tgid, state_fd );
		if( cap_entry == NULL ) {
			MSG( "Find_capsule_entry()-> tgid/fd %d/%d not found",
				  state_tgid, state_fd );
			return -1;
		}
		start = cap_entry->data_pos;
		end = start + *len;
		ch_last_prev = calc_chk_num( cap_head.data_end, 
									 symm_chunk_size );
		if( end > cap_head.data_end ) {
			cap_head.file_len += end - cap_head.data_end;
			cap_head.data_end = end;
		}
	} else {
		start = cap_head.policy_pos;
		end = start + *len;
		if( end > cap_head.policy_end ) {
			cap_head.policy_end = end;
		}
	}
	
	//MSG( "Writing message of len %u to off %u", *len, start );
	ch_start = start / symm_chunk_size;
	ch_end = calc_chk_num( end, symm_chunk_size );
	ch_last = calc_chk_num( cap_head.data_end, symm_chunk_size );	
	ch_last_size = calc_chk_len( cap_head.data_end, symm_chunk_size );
	
	//MSG( "ch_start: %u, ch_end: %u, ch_last: %u, ch_last_size: %u",
	//	 ch_start, ch_end, ch_last, ch_last_size );

	/* 1) break the write into blocks that do not extend past chunks
	 * 2) for each block, call read_enc_file_block() to read in the
	 *    aligned block. Modify the contents and then call 
	 *    write_enc_file_block() to write the changes to the block.
	 *
	 * 	  This is a simplified view. The absolute method should be
	 *	  to read in the entire chunk and check its hash first. If it
	 *	  is corrupt, stop the write and return error. Then store 
	 *	  the chunk in memory. Then call read_enc_file_block() on the
	 *	  in memory chunk. Then modify the contents of the in-memory
	 *	  chunk and write the changes back to the block to ensure
	 *	  integrity. This should be a slight modification, although
	 *	  still troublesome. Just leaving note here for future if
	 *	  I ever get around to this.
	 *
	 * 3) read each block and recalculate its hash and modify header
	 */

	// For chunk	
	for( ch_curr = ch_start; ch_curr <= ch_end; ch_curr++ ) {
		increment = 0;
		wr_start = ch_start == ch_curr ? start % symm_chunk_size : 0;
		wr_end = ( ch_curr != ch_end || end % symm_chunk_size == 0 ) ?
				  symm_chunk_size : end % symm_chunk_size;
		
		// al_start is wr_start aligned to 32 bit
		al_start = wr_start / (symm_key_len/8) * (symm_key_len/8);
		// al_end is wr_end aligned to 32 bit
	   	al_end = ( wr_end + ( symm_key_len/8 - 1 ) ) / 
				 ( symm_key_len/8 ) * ( symm_key_len/8 );	
		
		al_curr = al_start;
		wr_curr = wr_start;

		al_read_start = 0;
		al_read_end = ch_curr == ch_last ?
					  ch_last_size : symm_chunk_size;
		al_read_curr = al_read_start;

		//MSG( "wr_start: %u, wr_end: %u, al_start: %u, al_end: %u"
		//	 " al_curr: %u, wr_curr: %u, start: %u, end: %u,"
		//	 " ch_curr: %u, ch_start: %u, ch_end: %u, symm_chunk_size: %u"
		//	 " al_read_start: %u, al_read_end: %u, al_read_curr: %u", wr_start, 
		//	 wr_end, al_start, al_end, al_curr, wr_curr, start, 
		//	 end, ch_curr, ch_start, ch_end, symm_chunk_size, 
		//  	 al_read_start, al_read_end, al_read_curr );

		// Read entire chunk 
		do {
			//MSG ( "al_read_curr: %u, al_read_end: %u, increment: %u",
			//	  al_read_curr, al_read_end, increment );
			// increase ptx by rlen every time around do while (stolen from below)
			res = read_enc_file_block( fd, ptx + increment, blocklen, &rlen, 
								 	   ch_curr, symm_chunk_size, 
								 	   symm_key_len/8, al_read_curr, 
									   al_read_end - al_read_curr, symm_iv, 
									   symm_iv_len, decrypt_op );
			CHECK_SUCCESS( res, "Read_enc_file_block() Error" );
			if (rlen == 0) {
				// This means we are writing to a chunk that doesn't exist yet, so we can't read it
				break;
			}	
			increment += rlen;
			al_read_curr += rlen;
		} while( al_read_curr < al_read_end);

		// Read hash
		read_hash( fd, oldhash, oldhlen, ch_curr, symm_chunk_size );

		// Verify hash
		if ( !verify_hash( ch_curr, &hash_head, oldhash, oldhlen ) ) {
			res = TEE_ERROR_CORRUPT_OBJECT;
			CHECK_SUCCESS( res, "Compare_hashes()-> hash of chunk %u"
								" does not match", ch_curr );
		}

		// Edit - should only need one copy
		// TODO See which cases this is necessary
		if( al_curr + ptxlen < wr_end ) {
			wlen = ptxlen - ( wr_curr - al_curr );
			rlen = ptxlen;
		} else {
			wlen = wr_end - wr_curr;
			if( al_curr + rlen < wr_end ) {
				rlen = wr_end - al_curr;	
			}
		}
		//MSG( "wr_curr: %u, wlen: %u, al_curr: %u ", wr_curr, wlen, al_curr );

		memcpy( ptx + ( wr_curr ), bp, wlen ); // - al_curr
		bp += wlen;

		//MSG( "wlen: %u, rlen: %u, wr_curr: %u, wr_end: %u" 
		//	 " After: %c%c%c%c%c%c%c%c%c%c%c%c", wlen, rlen, 
		//	 wr_curr, wr_end, ptx[0+wr_curr], ptx[1+wr_curr], ptx[2+wr_curr], ptx[3+wr_curr], 
		//	 ptx[4+wr_curr], ptx[5+wr_curr], ptx[6+wr_curr], ptx[7+wr_curr], ptx[8+wr_curr], ptx[9+wr_curr], 
		//	 ptx[10+wr_curr], ptx[11+wr_curr] );

		//MSG( "ch_curr: %u, old hash: %02x%02x%02x%02x", ch_curr,
		//	 oldhash[0], oldhash[1], oldhash[2], oldhash[3] );

		//MSG( "ptx len: %u, read_end: %u", ptxlen, al_read_end);

		// Hash chunk
		res = hash_block( ptx, al_read_end, NULL, hlen,
						  false, hash_op );
		res = hash_block( NULL, 0, hash, hlen, true, hash_op );

		//MSG("ch_curr: %u hash: %02x%02x%02x%02x ", ch_curr,
		//	hash[0], hash[1], hash[2], hash[3]);

		// Write hash
		if ( write_hash( fd, hash, hlen, &hash_head,
						 ch_curr, symm_chunk_size )
						 != (int) hlen ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Write_hash() did not write %u B",
						   hlen );
		}


		// Should just be do while like read?
		al_write_start = 0;
		al_write_end = ch_curr == ch_last ?
					   ch_last_size : symm_chunk_size;
		al_write_curr = al_write_start;
		write_increment = 0;

		// print base values, print pointers address and value
		//MSG( "al_write_start: %u, al_write_end: %u, al_write_curr: %u, write_increment: %u",
		//	 al_write_start, al_write_end, al_write_curr, write_increment );
		//MSG( "ptx addr: %p", (unsigned char *) &ptx);

		do {
			write_size = (al_write_end - al_write_curr) < blocklen ? al_write_end - al_write_curr : blocklen;
			//MSG( "write_size: %u", write_size);
			//MSG( "al_write_start: %u, al_write_end: %u, al_write_curr: %u, write_increment: %u",
			//	 al_write_start, al_write_end, al_write_curr, write_increment );
			res = write_enc_file_block( fd, ptx + write_increment, write_size, &wlen, 
										al_write_curr, ch_curr, 
										symm_chunk_size, 
										symm_key_len/8, 
										symm_iv, symm_iv_len, 
										encrypt_op );
			CHECK_SUCCESS( res, "Write_enc_file_block() Error" );

			write_increment += wlen;
			al_write_curr += wlen;
		} while (al_write_curr < al_write_end);
		//MSG("write_size: %u", write_size);
		//MSG("wlen: %u", wlen);
		//MSG("al_write_start: %u, al_write_end: %u, al_write_curr:%u, write_increment: %u",
		//	 al_write_start, al_write_end, al_write_curr, write_increment);
	}
	
	// Might not need this recalculation of offsets because the chunk is read in its entirety
	// al_curr += rlen > wlen ? rlen : wlen;
	// wr_curr = al_curr;

	/* If the starting point is past the previous last chunk, then
	 * there will be a file hole. Previously the hash contained only
	 * part of the chunk that had data, which now would be zero
	 * extended. So between the previous last chunk and the first 
* chunk, we need to add hashes. Basically we are filling the file
	 * holes with random garbage.
	 */

	if( hash_write ) {
		ch_end = ch_start - 1;

		if( ch_start > ch_last_prev )
			ch_start = ch_last_prev;

		//MSG( "ch_start: %u, ch_end: %d, ch_last_prev: %u", ch_start, (int) ch_end, ch_last_prev );

		// For chunk 
		for( ch_curr = ch_start; (int) ch_curr <= (int) ch_end; ch_curr++ ) {
			al_start = 0;
			al_end = ch_curr == ch_last ? 
					 ch_last_size : symm_chunk_size; 
			al_curr = al_start;
			// Read chunk
			do{
				res = read_enc_file_block( fd, ptx, ptxlen, &rlen, 
										   ch_curr, symm_chunk_size,
										   symm_key_len/8, al_curr,
										   al_end - al_curr, symm_iv,
										   symm_iv_len, decrypt_op );
				CHECK_SUCCESS( res,	"Read_enc_file_block() Error" );
				// continuously passes data to the hash block function
				res = hash_block( ptx, rlen, NULL, hlen, 
								  false, hash_op );
				al_curr += rlen;
			} while( al_curr < al_end ); 

			// Gives the hash back (b/c of params)
			res = hash_block( NULL, 0, hash, hlen, true, hash_op );

			//MSG( "chnum %u: %02x%02x", ch_curr, hash[0], hash[1] );			
	
			// Write hash
			if( write_hash( fd, hash, hlen, &hash_head, 
						    ch_curr, symm_chunk_size ) 
							!= (int) hlen ) {
				res = TEE_ERROR_NOT_SUPPORTED;
				CHECK_SUCCESS( res, "Write_hash() did not write %u B", 
							   	    hlen );	
			};
		}
	
		// Rewrite the header
		res = hash_hashlist( &hash_head, hash, hlen, hash_op );
		CHECK_SUCCESS( res, "Hash_hashlist() Error" );
		fill_header( &header, encrypt_op, symm_iv, symm_iv_len, 
					 symm_id, hash, hlen,
					 cap_head.file_len + ( ch_last + 1 ) * hlen );

		//MSG( "Hash: %02x%02x%02x%02x Header Size: %u", 
		//	  hash[0], hash[1], hash[2], hash[3], header.capsize );

		if( write_header( fd, &header ) != 
						sizeof( struct TrustedCap ) ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Write_header()-> Did not write %u B",
						        sizeof( struct TrustedCap ) );
		}
	}

	if( is_data ) {
		cap_entry->data_pos += *len;
	} else {
		cap_head.policy_pos += *len;
	}

	return res;
}

TEE_Result do_open( int fd, int state_tgid, int state_fd ) {

	TEE_Result				res = TEE_SUCCESS;
	struct TrustedCap   	header;
	unsigned char       	ptx[BLOCK_LEN];
	unsigned char       	hash[HASH_LEN];
	size_t              	ptxlen = BLOCK_LEN;
	size_t              	hlen = HASH_LEN;
	uint32_t 				ch_start, ch_end, ch_curr, ch_cnt, ch_size;
    uint32_t       	    	plen, ch_last_len;
	uint8_t             	match_state = 0;
	bool			    	matched = false;
	unsigned char       	delimiter[DELIMITER_SIZE] = DELIMITER;
	struct cap_text_entry  *new_entry;


	/* Initalize the capsule's text index structure and header if this is the first
	 * open call. Otherwise, we create a new capsule_text_entries struct and add it
	 * to the list */
	if( cap_head.proc_entries.first == NULL ) {
	    // TODO JAMES: caching	
		initialize_capsule_text( &cap_head );

		if( read_header(fd, &header) < (int) sizeof(struct TrustedCap) ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Read_header() Error" );		
		}

		if( aes_key_setup == false ) {
			res = find_key( &header, keyFile, &decrypt_op, &encrypt_op,
						    &hash_op, &symm_id, &symm_iv_len, &symm_key_len,
							&symm_chunk_size, &symm_iv );
			CHECK_SUCCESS( res, "Find_key() Error" );	
			aes_key_setup = true;
		}
			
		/* 1) Decrypt the text one chunk at a time. Separate policy text
	 	*    from data to mark the start and end of different sections.
	 	* 2) Check the hashes and construct the hashlist.
	 	*/ 
		ch_start = 0;
		ch_end = calc_chk_num( header.capsize, symm_chunk_size + hlen );
		ch_last_len = header.capsize - hlen - 
				      ch_end * ( symm_chunk_size + hlen );

		//MSG( "ch_start: %u, ch_end: %u, ch_last_len: %u, header: %u", 
		//	 ch_start, ch_end, ch_last_len, header.capsize );

		//MSG( "ptx: %s", ptx);

		for( ch_curr = ch_start; ch_curr <= ch_end; ch_curr++ ) {
			
			if( !is_in_hashlist( &hash_head, ch_curr ) ) {	
				if( read_hash( fd, hash, hlen, ch_curr, symm_chunk_size ) !=
					(int) hlen ) {
					res = TEE_ERROR_NOT_SUPPORTED;
					CHECK_SUCCESS( res, "Read_hash()-> Incorrect format" );
				}
				//MSG( "About to call add_to_hashlist" );
				add_to_hashlist( hash, hlen, &hash_head, ch_curr );
			}

			ch_cnt = 0;
			ch_size = ch_curr == ch_end ? ch_last_len : symm_chunk_size; 

			while( ch_cnt < ch_size ) {
				// TODO: might not need this clear of PTX
				memset(&ptx[0], 0, sizeof(ptx));
				res = read_enc_file_block( fd, ptx, ptxlen, &plen,
								           ch_curr, symm_chunk_size, 
										   symm_key_len/8, ch_cnt, 
										   ch_size - ch_cnt,
										   symm_iv, symm_iv_len, 
										   decrypt_op );
		   		CHECK_SUCCESS( res, "Read_enc_file_block() Error" );
                if (plen <= 0){
                    return TEE_ERROR_GENERIC; // why?
                }
				res = hash_block( ptx, plen, NULL, hlen, 
								  false, hash_op );
		   		CHECK_SUCCESS( res, "Hash_block() Update Error" );

				//MSG( "ch_cnt: %u, ch_size: %u, plen: %u, ptx: %02x%02x%02x"
				//	 " %02x%02x%02x", ch_cnt, ch_size, plen, ptx[0], ptx[1], 
				//	 ptx[2], ptx[1021], ptx[1022], ptx[1023]);
		
				/*Index the contents of the file*/
 				sep_policy_and_data( ptx, plen, &cap_head,
					                 &match_state, &matched, delimiter );
				ch_cnt += plen;			
			}
		
			res = hash_block( NULL, 0, hash, hlen, true, hash_op );
			CHECK_SUCCESS( res, "Hash_block() Final Error" );

			if( !verify_hash( ch_curr, &hash_head, hash, hlen ) ) {
				res = TEE_ERROR_CORRUPT_OBJECT;
				CHECK_SUCCESS( res, "Compare_hashes()-> hash of chunk %u"
								    " does not match", ch_curr );
			}
		}	

		/* Verify the hash of hashes */
		hash_hashlist( &hash_head, hash, hlen, hash_op );
		//MSG( "Hash: %02x%02x%02x%02x", 
		//	 hash[0], hash[1], hash[2], hash[3]  );
		if( !compare_hashes( hash, header.hash, hlen ) ) {
			res = TEE_ERROR_CORRUPT_OBJECT;
			CHECK_SUCCESS( res, "Compare_hashes()-> hash of hashes"
							    " does not match" );
		}
	}

	new_entry = TEE_Malloc( sizeof( struct cap_text_entry ), 0 );
	initialize_capsule_entries( new_entry, state_tgid, state_fd, 
					            cap_head.data_begin );
	LIST_INSERT_END( new_entry, &cap_head.proc_entries, entries );
	
	//MSG( "tgid/fd %d/%d: policy %d/%d, data %d/%d, file len %d",
	//	 new_entry->state_tgid, new_entry->state_fd,
	//	 cap_head.policy_begin, cap_head.policy_end,
	//	 cap_head.data_begin, cap_head.data_end,
	//	 cap_head.file_len );

	return res;
}

/* Run the Lua policy function - if the policy was changed,
 *                               run it again */
TEE_Result do_run_policy( int fd, lua_State *L, const char* policy, SYSCALL_OP n ) { 

	int  res = TEE_SUCCESS, ret = LUA_OK;
	int  cur_stack = lua_gettop(L);
	bool eval, pol_changed;
	uint64_t cnt_a, cnt_b;

	cnt_a = read_cntpct();
	do {
		/* Call lua policy function */
		lua_getglobal( L, policy );
		lua_pushnumber( L, n ); /* policy takes a number argument */
		ret = lua_pcall( L, 1, 2, 0 );
		if( ret != LUA_OK ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "error running func '%s:%d': %s",
						        policy, n, lua_tostring( L, -1 ) );	
		}

		if( !lua_isboolean( L, -1 ) ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Func '%s:%d' must return a boolean",
								policy, n );
		}

		pol_changed  = lua_toboolean( L, -1 );
		//MSG( "Function '%s:%d' pol_changed is %s", policy, n,
		//	 pol_changed == true ? "true" : "false" );
		
		if( pol_changed ) {
			/* reload the policy since it has changed */
			do_load_policy( fd );
		}
	
	} while( pol_changed == true );

	if( !lua_isboolean( L, -2 ) ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Func '%s:%d' must return a boolean",
							policy, n );
	}

	eval = lua_toboolean( L, -2 );
	//MSG( "Function '%s:%d' evaluated to %s", policy, n,
	//	 eval == true ? "true" : "false" );
	if( eval == false ) {
		res = TEE_ERROR_POLICY_FAILED;
	}
	
	/* Clear the effects of this function */
	lua_settop( L, cur_stack );

	cnt_b = read_cntpct(); 
	timestamps[curr_ts].policy_eval += cnt_b - cnt_a;
	return res;
}

TEE_Result do_load_policy( int fd ) {
	
	TEE_Result     res = TEE_SUCCESS;
	size_t         sz = cap_head.policy_end - cap_head.policy_begin;
	unsigned char  buffer[POLICY_MAX_SIZE];
	uint64_t       cnt_a, cnt_b;

	cnt_a = read_cntpct();
	/* We load the policy  */
	if( sz > POLICY_MAX_SIZE ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Policy is too large" );
	}

	/* Read the policy into buffer */
	memset( buffer, 0, POLICY_MAX_SIZE );
	do_lseek( 0, 0, 0, START, false );
	res = do_read( fd, 0, 0, buffer, &sz, true, false );
	CHECK_SUCCESS( res, "do_read() Error" );

	/* Load the policy into Lua */
	res = lua_load_policy( Lstate, (const char*) buffer );
	CHECK_SUCCESS( res, "load_policy() Error" );

	cnt_b = read_cntpct();
	timestamps[curr_ts].policy_eval += cnt_b - cnt_a;
	return res;
}

/* Creates a new capsule identified by pfd from currently
 * opened capsule cfd */
TEE_Result do_create( int pfd, int cfd ) {

	TEE_Result 		  res = TEE_SUCCESS;
	unsigned char     databuf[BLOCK_LEN];
	unsigned char     hash[HASH_LEN];
	unsigned char     delimiter[DELIMITER_SIZE] = DELIMITER;
	size_t            datalen = BLOCK_LEN, hlen = HASH_LEN;
	uint32_t          p_len, d_len, t_len, r_len;
	uint32_t          pfd_off, cfd_off, del_off = 0, f_off, del_written = 0;
	uint32_t          ch_cnt, ch_off, ch_b_data_size = 0;
	uint32_t          ch_start, ch_curr, ch_end, ch_size, ch_boundary;
	uint32_t          nr, ns, nw, nt;
	struct TrustedCap header;


	UNUSED( ns );

	datalen = datalen / (symm_key_len/8) * (symm_key_len/8);

	p_len = cap_head.policy_end - cap_head.policy_begin;
	res = TEE_SimpleLseek( pfd, 0, TEE_DATA_SEEK_END, &d_len );
    CHECK_SUCCESS( res, "TEE_SimpleLseek(%d, %d, %d, %p) error", pfd, 0, TEE_DATA_SEEK_END, (void*) &d_len);
	t_len = p_len + d_len + DELIMITER_SIZE; // Policy + data + delimiter

	ch_start = 0;
	ch_end = calc_chk_num( t_len, symm_chunk_size );
	ch_boundary = calc_chk_num( p_len + DELIMITER_SIZE, 
					            symm_chunk_size ); 

	pfd_off = d_len;

	//MSG( "datalen: %u, p_len: %u, d_len: %u, t_len: %u,"
	//	 " ch_start: %u, ch_end: %u, ch_boundary: %u, pfd_off: %u",
	//	 datalen, p_len, d_len, t_len, ch_start, ch_end, ch_boundary,
	//	 pfd_off );

	/* 1) Backward pass to shift a chunk worth of data downwards 
	 *    in the file to make room for policy, chunk hashes and 
	 *    capsule headers. Forward pass to encrypt and hash the 
	 *    chunk along the way.
	 * 2) In forward pass, read remaining policy from capsule 
	 *    and copy it to the new capsule. Re-encrypting and 
	 *    hashing along the way. 
	 * 3) When we reach the data-policy boundary, we construct
	 *    a chunk from the remainder of data, policy and delimiter.
	 *    	a. Read the remainder of data for this chunk in a
	 *    	   backward pass
	 *      b. In forward pass, write the policy and delimiter
	 *         in encrypted form and then the remainder of the 
	 *         data to the file. We encrypt and hash along the
	 *         way
	 * 4) Add header. Obtain a hash of all the hashes in this 
	 *    file. Calculate the capsule length from t_len.
	 */
	
	/* Read and write out the data for this capsule */

	for(ch_curr=ch_end; (int) ch_curr >= (int)ch_boundary; ch_curr--) {
	
		ch_size = ch_curr == ch_end ? 
				  calc_chk_len( t_len, symm_chunk_size ) : 
				  symm_chunk_size;
		cfd_off = sizeof( struct TrustedCap ) + HASH_LEN + ch_size + 
				  ch_curr * ( symm_chunk_size + HASH_LEN );

		if( ch_curr == ch_boundary ) {
			ch_size = pfd_off;
			ch_b_data_size = ch_size;
		}
		
		/* Backward pass to copy data */
		ch_cnt = ch_size;
	
		//MSG( "ch_curr: %u, ch_size/ch_cnt: %u, pfd_off: %u, cfd_off: %u"
		//	 , ch_curr, ch_size, pfd_off, cfd_off );

		while( ch_cnt > 0 ) {
			/* Read the maximum number of bytes that is aligned to 
			 * keylength that fits in the buffer */	
		
			r_len = ch_cnt > datalen ? ch_cnt + datalen - 
				    ( ch_cnt + ( symm_key_len/8 ) - 1 ) / 
					( symm_key_len/8 ) * ( symm_key_len/8 ) : ch_cnt; 

			pfd_off -= r_len;

			cfd_off -= r_len; 	
				
			res = TEE_SimpleLseek( pfd, pfd_off, TEE_DATA_SEEK_SET, &ns ); 
			nr = read_block( pfd, databuf, r_len );
			res = TEE_SimpleLseek( pfd, cfd_off, TEE_DATA_SEEK_SET, &ns );	
			nw = write_block( pfd, databuf, nr );
	

			/* Sanity check */
			if( nr != nw ) {
				res = TEE_ERROR_NOT_SUPPORTED;
				CHECK_SUCCESS( res, "Write_block() wrote only %u/%u B",
								    nw, nr );
			}

			ch_cnt -= nw;
			//MSG( "ch_curr: %u, ch_cnt/ch_size: %u/%u, r_len: %u,"
			//	 " nr: %u, nw: %u, pfd_off: %u, cfd_off: %u", 
			//	 ch_curr, ch_cnt, ch_size, r_len, nr, nw, pfd_off, 
			//	 cfd_off );
		}
		/* Forward pass to encrypt and hash for every chunk except
		 * the boundary chunk which is not complete yet */
		if( ch_curr != ch_boundary ) {
			ch_cnt = 0;

			while( ch_cnt < ch_size ) {
				res = TEE_SimpleLseek( pfd, cfd_off + ch_cnt, 
								      TEE_DATA_SEEK_SET, &ns );
				nr = read_block( pfd, databuf, datalen );
				//MSG( "data_block: %s", databuf );	
				ch_off = cfd_off + ch_cnt - HASH_LEN - 
						 sizeof( struct TrustedCap ) -
				 	 	 ch_curr * ( symm_chunk_size + HASH_LEN );
				res = write_enc_file_block( pfd, databuf, nr, &nw, 
											ch_off, ch_curr, 
											symm_chunk_size, 
											symm_key_len/8, symm_iv, 
											symm_iv_len, encrypt_op );
		    	CHECK_SUCCESS( res, "Write_enc_file_block Error" );
	
				/* Advance only as far as the last aligned write */
				res = hash_block( databuf, nw, NULL, hlen, 
								  false, hash_op );
				CHECK_SUCCESS( res, "Hash_block() Update Error" );
				ch_cnt += nw;
				//MSG( "ch_curr: %u, ch_off: %u, ch_cnt/ch_size: %u/%u,"
				//	 " nw/nr: %u/%u, cfd_off: %u", ch_curr, ch_off,
			    //		ch_cnt, ch_size, nw, nr, cfd_off ); 
			}	
		
			res = hash_block( NULL, 0, hash, hlen, true, hash_op );
			CHECK_SUCCESS( res, "Hash_block() Final Error" );
	
			f_off = sizeof( struct TrustedCap ) + ch_curr * 
					( hlen + symm_chunk_size );	
			res = TEE_SimpleLseek( pfd, f_off, TEE_DATA_SEEK_SET, &ns );
		    nw = write_block( pfd, hash, hlen );	
			if( (int) nw != (int) hlen ) {
				res = TEE_ERROR_NOT_SUPPORTED;		
				CHECK_SUCCESS( res, "Write_hash()-> did not write %u B",
							        hlen );	
			}	
		}
	}

	//MSG( "Moved data down to make room for policy." );

	/* Read the policy from cfd and write it to pfd in a forward 
	 * pass */
	cfd_off = sizeof( struct TrustedCap );
	res = TEE_SimpleLseek( pfd, cfd_off, TEE_DATA_SEEK_SET, &ns );
	res = TEE_SimpleLseek( cfd, cfd_off, TEE_DATA_SEEK_SET, &ns );

	//MSG( "pfd_off: %u, cfd_off: %u, ch_start: %u, ch_end: %u, " 
    //		 "ch_boundary: %u, ch_b_data_size: %u", pfd_off, cfd_off, 
	//	 ch_start, ch_end, ch_boundary, ch_b_data_size );

	for( ch_curr = ch_start; ch_curr <= ch_boundary; ch_curr++ ) {
		
		ch_cnt = 0;

		/* If the entire chunk is just policy, we can just copy and
		 * paste */	
		if( ( ch_curr + 1 ) * symm_chunk_size < p_len ) {
			ch_size = symm_chunk_size + hlen;
			while( ch_cnt < ch_size ) {
				nr = read_block( cfd, databuf, 
								 ( ch_size - ch_cnt ) > datalen ? 
								 datalen : ch_size - ch_cnt );
				nw = write_block( pfd, databuf, nr );
				cfd_off += nw;
				ch_cnt += nw;	
			
				//MSG( "nw/nr: %u/%u, ch_cnt/ch_size: %u/%u, cfd_off: %u",
				//	 nw, nr, ch_cnt, ch_size, cfd_off );
			}
		} else {
			
			ch_size = ch_curr != ch_boundary ? symm_chunk_size :        
				   	  p_len + DELIMITER_SIZE + ch_b_data_size - 
				  	  ch_curr * symm_chunk_size;	  
			cfd_off = ch_curr * ( hlen + symm_chunk_size ) + hlen + 
					  sizeof( struct TrustedCap ) + ch_size;
			do_lseek( 0, 0, ch_curr * symm_chunk_size, START, false );
			
			//MSG( "ch_cnt: %u, ch_size: %u, cfd_off: %u, del_off: %u,"
			//	 " ch_b_data_size: %u", ch_cnt, ch_size, cfd_off, 
			//	 del_off, ch_b_data_size );
			
			while( ch_cnt < ch_size ) {
				memset(&databuf[0], 0, sizeof(databuf));
				// TODO: issue, it's reusing the buffer? so that causes many issues. 

				/* We read in the remainder of policy first */
				if( del_off == 0 ) {
					nr = datalen;
					res = do_read( cfd, 0, 0, databuf, &nr, false, false );
					CHECK_SUCCESS( res, "Do_read() Error" );
				} else {
					nr = 0;
				}

				//MSG( "Do_read()-> %u/%u B (total %u/%u B)", 
				//	  nr, datalen, ch_cnt, ch_size );

				// TODO: math wrong, adds delimiter to 252 B which makes it 256 B (only 4 can fit)
				// then attempts to add the rest, but adds 6 B. Needs to fill buffer with delimiter
				// then any overflow, add to the next buffer.

				// TODO: del_off didn't get updated properly.  

				//MSG( "nr: %u, datalen: %u, del_off: %u, DELIMITER_SIZE: %u",
				//	 nr, datalen, del_off, DELIMITER_SIZE );

				/* Then we add the delimiter */
				if( nr < datalen && del_off < DELIMITER_SIZE ) {
					size_t to_write = (datalen - nr) >= DELIMITER_SIZE - del_written ?
									  DELIMITER_SIZE - del_written : datalen - nr;
					//MSG( "to_write: %u", to_write ); 
					//MSG( "copy amt: %u", (datalen - nr) >= DELIMITER_SIZE - del_written ?
					//	 DELIMITER_SIZE - del_written : datalen - nr );
					memcpy( databuf + nr, delimiter + del_off, 
							(datalen - nr) >= DELIMITER_SIZE - del_written ?
							DELIMITER_SIZE - del_written : datalen - nr );
					nr += (datalen - nr) >= DELIMITER_SIZE ? 
						  DELIMITER_SIZE - del_written : datalen - nr;
					//MSG( "nr: %u", nr );
					//MSG( "condition: %u", (datalen - nr) >= DELIMITER_SIZE - del_written ?
				    //		 DELIMITER_SIZE - del_written : datalen - nr );
					del_off += (datalen - nr) >= DELIMITER_SIZE - del_written ?
						      DELIMITER_SIZE - del_written : datalen - nr;
					//MSG( "del_off: %u", del_off );
					del_written += to_write;
				} 
	
				//MSG( "Copy Delimiter-> %u/%u B", nr, datalen );

				/* We then read the data */	
				if( nr < datalen && ch_b_data_size > 0 ) {
					res = TEE_SimpleLseek( pfd, cfd_off - ch_b_data_size,
									 	  TEE_DATA_SEEK_SET, &ns );
					nt = read_block( pfd, databuf + nr, 
									 datalen - nr < ch_b_data_size ? 
									 datalen - nr : ch_b_data_size );
					ch_b_data_size -= nt; 
					nr += nt;		
				}

				//MSG( "Copy Data-> %u/%u B", nr, datalen );

				//MSG( "nr: %u, ch_cnt: %u, ch_curr:%u", nr, ch_cnt, ch_curr);

				res = write_enc_file_block( pfd, databuf, nr, &nw, 
											ch_cnt, ch_curr, 
											symm_chunk_size, 
											symm_key_len/8, symm_iv, 
											symm_iv_len, encrypt_op );
		    	CHECK_SUCCESS( res, "Write_enc_file_block Error" );
	
				//MSG( "Write_enc_file_block()-> %u/%u B (%s)", nw, nr, 
				//	 databuf );

				/* Advance only as far as the last aligned write */
				res = hash_block( databuf, nw, NULL, hlen, 
								  false, hash_op );
				CHECK_SUCCESS( res, "Hash_block() Update Error" );
				ch_cnt += nw;
				//MSG( "ch_cnt: %u", ch_cnt);
			}
			res = hash_block( NULL, 0, hash, hlen, true, hash_op );
			CHECK_SUCCESS( res, "Hash_block() Final Error" );
		
			//MSG( "Hash: %02x%02x%02x%02x", hash[0], hash[1], hash[2], 
			//		 hash[3] );

			f_off = sizeof( struct TrustedCap ) + ch_curr * 
					( hlen + symm_chunk_size );	
			res = TEE_SimpleLseek( pfd, f_off, TEE_DATA_SEEK_SET, &ns );
		    nw = write_block( pfd, hash, hlen );	
			if( (int) nw != (int) hlen ) {
				res = TEE_ERROR_NOT_SUPPORTED;		
				CHECK_SUCCESS( res, "Write_hash()-> did not write %u B",
							        hlen );	
			}	
			//MSG( "databuf: %s", databuf);
		}
	}	

	//MSG( "Finished appending policy. Creating header..." );

	/* Create Trusted Capsule Header */
	for( ch_curr = ch_start; ch_curr <= ch_end; ch_curr++ ) {
		f_off = sizeof( struct TrustedCap ) + 
				ch_curr * ( hlen + symm_chunk_size );
		
		res = TEE_SimpleLseek( pfd, f_off, TEE_DATA_SEEK_SET, &ns );
		nr = read_block( pfd, hash, hlen );	
		if( (int) nr != (int) hlen ) {
			res = TEE_ERROR_NOT_SUPPORTED;		
			CHECK_SUCCESS( res, "Write_hash()-> did not write %u B",
						        hlen );	
		}
		hash_block( hash, hlen, NULL, hlen, false, hash_op );	
	}
	hash_block( NULL, 0, hash, hlen, true, hash_op );

	res = fill_header( &header, encrypt_op, symm_iv, symm_iv_len,
					   symm_id, hash, hlen, (ch_end + 1)*hlen + t_len );
	CHECK_SUCCESS( res, "Fill_header() Error" );

	//MSG( "Header size: %d", ( ch_end + 1 ) * hlen + t_len );

	if( write_header( pfd, &header ) != sizeof( struct TrustedCap ) ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Write_header()-> did not write %u B", 
						   sizeof( struct TrustedCap ) );
	}
	
	/* Reset the policy pos */
	do_lseek( 0, 0, 0, START, false );
	return res;
}

/* We use this to change policy over the network */
TEE_Result do_change_policy_network( int cfd, unsigned char* policy, 
									 size_t newlen ) {
	
	TEE_Result 	  	  		res = TEE_SUCCESS;
	unsigned char 	  		hash[HASH_LEN];
	size_t        	  		hlen = HASH_LEN;
	size_t     	  	  		oldlen = cap_head.policy_end - 
					    			 cap_head.policy_begin;
	uint32_t      	  		t_len;
	struct TrustedCap		header;	
	struct cap_text_entry  *p;
	
	/* 1) Two scenarios: newlen > oldlen
	 *	                 newlen <= oldlen
	 *
	 * Scenario 1: We make backward pass over the capsule and copy data 
	 * 			   down to make room. At each data chunk except the 
	 * 			   boundary chunk, we make a forward pass to produce
	 * 			   the hash. Then we read and write in the new policy
	 *             in a forward pass producing the hash at the same
	 *             time. At the boundary chunk, we write in the new 
	 *             policy until it is finish, then write the delimiter 
	 *             and call hash the boundary chunk since the remainder
	 *             data will already have been written.  
	 *
	 * Scenario 2: We overwite the old policy. We make forward pass over
	 *             the data to move data up. We re-encrypt and hash one
	 *             chunk at a time. Finally, we ftruncate the capsule to
	 *             its new length.  
	 */
	
	if( newlen > oldlen ) {
		//MSG( "newlen %u > oldlen %u", newlen, oldlen );
		res = do_move_data_down( cfd, newlen );
		CHECK_SUCCESS( res, "Do_move_data_down() Error" );
	} else if( newlen < oldlen ) {
		//MSG( "newlen %u < oldlen %u", newlen, oldlen );
		res = do_move_data_up( cfd, newlen );
		CHECK_SUCCESS( res, "Do_move_data_up() Error" );
	}

	/* Read in and write out the new policy */
	//MSG( "Writing new policy of length %u B", newlen );	
	res = do_write_new_policy_network( cfd, policy, newlen );
	CHECK_SUCCESS( res, "Write_new_policy() Error" );

	/* Rewrite the header */
	//MSG( "Writing new header" );
	res = hash_hashlist( &hash_head, hash, hlen, hash_op );
	CHECK_SUCCESS( res, "Hash_hashlist() Error" );
	
	t_len = cap_head.file_len + HASH_LEN * 
			( calc_chk_num( cap_head.file_len, symm_chunk_size ) + 1 );	
	//MSG( "t_len: %u, file_len: %u", t_len, cap_head.file_len );
	
	res = fill_header( &header, encrypt_op, symm_iv, symm_iv_len, 
					   symm_id, hash, hlen, t_len );
	CHECK_SUCCESS( res, "Fill_header() Error" );
	
	if( write_header( cfd, &header ) != sizeof( struct TrustedCap ) ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Write_header()-> wrote less than %u B",
						    sizeof( struct TrustedCap ) );
	}

	/* Go through the proc_entries list to modify each entry's data_pos
	 * by the difference in new and old policy length */
	LIST_FOREACH( p, &cap_head.proc_entries, entries ) {
		p->data_pos += newlen - oldlen;
	}	

	return res;
}
/* Change the policy of a capsule. We write this using helper 
 * functions, so that later this can be re-used for I/O over the
 * network - THIS IS A TEMPLATE for testing*/
TEE_Result do_change_policy( int pfd, int cfd, size_t newlen ) {
	
	TEE_Result 	  	  		res = TEE_SUCCESS;
	unsigned char 	  		hash[HASH_LEN];
	size_t        	  		hlen = HASH_LEN;
	size_t     	  	  		oldlen = cap_head.policy_end - 
					    			 cap_head.policy_begin;
	uint32_t      	  		t_len;
	struct TrustedCap		 header;	
	struct cap_text_entry	*p;
	
	/* 1) Two scenarios: newlen > oldlen
	 *	                 newlen <= oldlen
	 *
	 * Scenario 1: We make backward pass over the capsule and copy data 
	 * 			   down to make room. At each data chunk except the 
	 * 			   boundary chunk, we make a forward pass to produce
	 * 			   the hash. Then we read and write in the new policy
	 *             in a forward pass producing the hash at the same
	 *             time. At the boundary chunk, we write in the new 
	 *             policy until it is finish, then write the delimiter 
	 *             and call hash the boundary chunk since the remainder
	 *             data will already have been written.  
	 *
	 * Scenario 2: We overwite the old policy. We make forward pass over
	 *             the data to move data up. We re-encrypt and hash one
	 *             chunk at a time. Finally, we ftruncate the capsule to
	 *             its new length.  
	 */
	
	if( newlen > oldlen ) {
		//MSG( "newlen %u > oldlen %u", newlen, oldlen );
		res = do_move_data_down( cfd, newlen );
		CHECK_SUCCESS( res, "Do_move_data_down() Error" );
	} else if( newlen < oldlen ) {
		//MSG( "newlen %u < oldlen %u", newlen, oldlen );
		res = do_move_data_up( cfd, newlen );
		CHECK_SUCCESS( res, "Do_move_data_up() Error" );
	}

	/* Read in and write out the new policy */
	//MSG( "Writing new policy of length %u B", newlen );	
	res = do_write_new_policy( pfd, cfd, newlen );
	CHECK_SUCCESS( res, "Write_new_policy() Error" );

	/* Rewrite the header */
	//MSG( "Writing new header" );
	res = hash_hashlist( &hash_head, hash, hlen, hash_op );
	CHECK_SUCCESS( res, "Hash_hashlist() Error" );
	
	t_len = cap_head.file_len + HASH_LEN * 
			( calc_chk_num( cap_head.file_len, symm_chunk_size ) + 1 );	
	//MSG( "t_len: %u, file_len: %u", t_len, cap_head.file_len );
	
	res = fill_header( &header, encrypt_op, symm_iv, symm_iv_len, 
					   symm_id, hash, hlen, t_len );
	CHECK_SUCCESS( res, "Fill_header() Error" );
	
	if( write_header( cfd, &header ) != sizeof( struct TrustedCap ) ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Write_header()-> wrote less than %u B",
						    sizeof( struct TrustedCap ) );
	}

	/* Go through the proc_entries list to modify each entry's data_pos
	 * by the difference in new and old policy length */
	LIST_FOREACH( p, &cap_head.proc_entries, entries ) {
		p->data_pos += newlen - oldlen;
	}	

	return res;
}

void do_close( int state_tgid, int state_fd ) {
	
	struct cap_text_entry *p;
	int                    found = 0;

	/* Remove the cap_text_entry in the capsule_text list */
	LIST_FOREACH( p, &cap_head.proc_entries, entries ) {
		if( p->state_tgid == state_tgid && 
			p->state_fd == state_fd ) {
			LIST_REMOVE( p, &cap_head.proc_entries, entries );
			found = 1;
			break;
		}
	}
	
	if( found == 1 ) {
		TEE_Free( p );
	}
	
	if( cap_head.proc_entries.first == NULL ) {
		free_hashlist( &hash_head );
		LIST_INIT( &hash_head );
	}		
}

TEE_Result do_register_aes( uint32_t keyType, uint32_t id, 
						    uint32_t chSize, uint32_t keyLen, 
							uint8_t* attr, uint32_t attrlen,
							uint8_t* iv, uint32_t ivlen ) {

	TEE_Result 		res = TEE_SUCCESS;
	uint32_t 	    total_size;
	uint8_t        *data_buffer;
	uint8_t        *it;

	if( keyType != TEE_TYPE_AES ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Non-AES keys are not supported" ); 
	}
	
	/* Add the key to persistent storage in a serial manner.
	 * => Total size, ch size, key size, key id, iv size, iv, attrs 
	 */
	if( keyFile != TEE_HANDLE_NULL ) {

		res = TEE_SeekObjectData( keyFile, 0, TEE_DATA_SEEK_END );
		CHECK_SUCCESS( res, "TEE_SeekObjectData() Error" );
		
		total_size = attrlen + ivlen + 5*sizeof(uint32_t);
		
		MSG( "Write %u B of AES key 0x%08x to sec. storage",
			 total_size, id );

		data_buffer = TEE_Malloc( total_size, 0 );
		it = data_buffer;

		//total_size less size of total_size 
		*(uint32_t*) (void*) it = total_size - sizeof(uint32_t);
		//MSG( "First 4 bytes: %u", *(uint32_t*)(void*) it );		
		it += sizeof(uint32_t);
		//chunk_size
		*(uint32_t*) (void*) it = chSize;
		//MSG( "Second 4 bytes: %u", *(uint32_t*)(void*) it );
		it += sizeof(uint32_t);
		//key_len
		*(uint32_t*) (void*) it = keyLen;                
		//MSG( "Third 4 bytes: %u", *(uint32_t*)(void*) it );		
		it += sizeof(uint32_t);
		//key_id
		*(uint32_t*) (void*) it = id;               
		//MSG( "Fourth 4 bytes: %08x", *(uint32_t*)(void*) it );	
		it += sizeof(uint32_t);
		//iv_size
		*(uint32_t*) (void*) it = ivlen;            
		//MSG( "Fourth 4 bytes: %u", *(uint32_t*)(void*) it );		
		it += sizeof(uint32_t);
		//iv
		memcpy( it, iv, ivlen );
		it += ivlen;
		//aes key_attr
		memcpy( it, attr, attrlen ); 

		res = TEE_WriteObjectData( keyFile, data_buffer, total_size );
		CHECK_SUCCESS( res, "TEE_WriteObjectData() Error" );
		
		TEE_Free( data_buffer );
	}

	return res;

}

TEE_Result do_register_rsa( uint32_t keyType, uint32_t keySize,
	                       	uint8_t *buf, uint32_t blen ) {
	TEE_Result 	      res = TEE_SUCCESS;
	TEE_ObjectHandle *o;
	TEE_Attribute    *attrs;
	uint32_t          attr_count;

	if( keyType == TEE_TYPE_RSA_PUBLIC_KEY ) {
		o = &curr_pub;
	} else if ( keyType == TEE_TYPE_RSA_KEYPAIR ) {
	    o = &curr_priv;
	} else {
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	res = TEE_AllocateTransientObject( keyType, keySize, o ); 
	CHECK_SUCCESS( res, "TEE_AllocateTranientObject() Error" );

	res = unpack_attrs( buf, blen, &attrs, &attr_count );
	CHECK_SUCCESS( res, "UNPACK_ATTRS() Error" );

	res = TEE_PopulateTransientObject( *o, attrs, attr_count );
	TEE_Free( attrs );	
	CHECK_SUCCESS( res, "TEE_PopulateTransientObject() Error" );

	return res;	
}

TEE_Result do_open_connection( char* ip_addr, int port, int* fd ) {
	TEE_Result res = TEE_SUCCESS;
	uint64_t   cnt_a, cnt_b;
	/* For now, we crash the program if errors are encountered.
	 * This may change as we build out the network protocol
	 */	
	cnt_a = read_cntpct();
	res = TEE_SimpleOpenConnection( ip_addr, port, fd );
	cnt_b = read_cntpct();
	timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
	if( res != TEE_SUCCESS ) {
		MSG( "TEE_SimpleOpenConnection() Error: fd is %d", *fd );
	}

	/* Currently we do not maintain the state (e.g., open fd) in the
	 * optee ap or the optee os. This is left for future work.
	 */

	//MSG( "IP Addr: %s, Port: %d\n, fd: %d", ip_addr, port, *fd );
	return res;
}

TEE_Result do_close_connection( int fd ) {
	TEE_Result res = TEE_SUCCESS;
	uint64_t   cnt_a, cnt_b;
	/* For now, we crash the program if errors are encountered.
	 * This may change as we build out the network protocol
	 */	
	cnt_a = read_cntpct();
	if( TEE_SimpleCloseConnection( fd ) != TEE_SUCCESS ) {
		MSG( "TEE_SimpleCloseConnection() error: fd->%d", fd );
	}
	cnt_b = read_cntpct();
	timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;

	return res;
}

TEE_Result do_recv_connection( int fd, void *buf, int *len ) {
	TEE_Result res = TEE_SUCCESS;
	uint64_t   cnt_a, cnt_b;
	if( len == 0 ) {
		return res;	
	}

	cnt_a = read_cntpct();
	res = TEE_SimpleRecvConnection( fd, buf, *len, len );
	cnt_b = read_cntpct();
	timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
	if( *len == 0 ) {
		do_close_connection( fd );
	}

	/* For now, we crash the program if errors are encountered.
	 * This may change as we build out the network protocol
	 */	
	if( *len < 0 || res != TEE_SUCCESS ) {
		CHECK_SUCCESS( res, "TEE_SimpleRecvConnection error" );
	}

	return res;
}

TEE_Result do_send_connection( int fd, void *buf, int *len ) {
	TEE_Result res = TEE_SUCCESS;
	int        orig_len = *len;
	uint64_t   cnt_a, cnt_b;

	if( len == 0 ) {
		return res;
	}
	
	cnt_a = read_cntpct();
	res = TEE_SimpleSendConnection( fd, buf, *len, len );
	cnt_b = read_cntpct();
	timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
	if( *len < orig_len ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "do_send_connection() sent only %d/%d B",
						    *len, orig_len );
	}

	if( *len == 0 ) {
		do_close_connection( fd );
	}

	/* For now, we crash the program if errors are encountered.
	 * This may change as we build out the network protocol. We
	 * operate using client->server model. So server should never
	 * be the first to close a connection, unless something 
	 * went wrong (connection broken or header/payload was 
	 * incorrect ).
	 */	
	if( *len <= 0 || res != TEE_SUCCESS ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "do_send_connection() connection error" );
	}
	
	return res;
}

	
TEE_Result do_send( int fd, void *buf, int *len, int op_code, int rv ){
	
	TEE_Result res = TEE_SUCCESS;
	uint8_t    header[HEADER_SIZE];
	int        hdr_len = HEADER_SIZE;
	size_t     hlen = HEADER_SIZE;
	size_t     plen = *len;

	//MSG( "hdr_len %d B", hdr_len );

	serialize_hdr( symm_id, op_code, buf, *len, rv, curr_cred,
				   header, hdr_len );	
	
	//MSG( "header decrypted: %02x%02x%02x%02x %02x%02x%02x%02x", 
	//	  header[0], header[1], header[2], header[3],
	//  	  header[48], header[49], header[50], header[51] );
	
	process_aes_block( header, &hlen, header, hlen, symm_iv, 
					   symm_iv_len, 0, true, true, encrypt_op );

	//MSG( "header encrypted: %02x%02x%02x%02x %02x%02x%02x%02x", 
	//	  header[0], header[1], header[2], header[3],
	//	  header[48], header[49], header[50], header[51] );


	res = do_send_connection( fd, header, &hdr_len );
   	CHECK_SUCCESS( res, "do_send_connection() header failed" );	

	//MSG( "payload: %s len %d", (char*) buf, *len );
	if( *len > 0 ) {
		process_aes_block( buf, &plen, buf, plen, symm_iv, symm_iv_len,
						   0, true, true, encrypt_op );

		res = do_send_connection( fd, buf, len );
   		CHECK_SUCCESS( res, "do_send_connection() payload failed" );	
	}

	return res;		
}

TEE_Result do_recv_payload( int fd, void* hash, int hlen, 
				            void* buf, int len ) {
	
	TEE_Result 	  res = TEE_SUCCESS;
	int        	  nr = len;
	int        	  read = 0;
	size_t        plen = len;
	unsigned char hash_p[HASH_LEN];

	do {
		res = do_recv_connection( fd, ( (char*) buf ) + read, &nr );
		CHECK_SUCCESS( res, "do_recv_connection() failed" );	
		read += nr;
		nr = len - read;
	} while( read < len && nr > 0 );

	process_aes_block( buf, &plen, buf, plen, symm_iv, 
					   symm_iv_len, 0, true, true, decrypt_op );
	
	res = hash_block( buf, read, hash_p, hlen, true, hash_op );
	CHECK_SUCCESS( res, "hash_block() error" );

	if( !compare_hashes( hash, hash_p, HASH_LEN ) ) {
		res = TEE_ERROR_COMMUNICATION;
		CHECK_SUCCESS( res, "compare_hashes() header hash does not"
						    " match the hash of the payload" );
	}

	return res;
}

TEE_Result do_recv_header( int fd, AMessage **msg ) {
	
	TEE_Result  res = TEE_SUCCESS;
	uint8_t     header[HEADER_SIZE];
	int         nr = HEADER_SIZE;
	size_t      hlen = HEADER_SIZE;
	int         read = 0;

	//MSG( "Getting the response header..." );

	do {
		res = do_recv_connection( fd, header + read, &nr );
		CHECK_SUCCESS( res, "do_recv_connection() failed" );
		read += nr;
		nr = HEADER_SIZE - read;
	} while( read < HEADER_SIZE && nr > 0 );

	process_aes_block( header, &hlen, header, hlen, symm_iv, 
					   symm_iv_len, 0, true, true, decrypt_op );

	deserialize_hdr( msg, header, HEADER_SIZE );
	if( *msg == NULL ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "deserialize() failed" );
	}

	if( (*msg)->tz_id != curr_cred || (*msg)->capsule_id != (int) symm_id ) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		CHECK_SUCCESS( res, "received message for TZ id 0x%08x capsule id 0x%08x"
					        " (this TZ id is 0x%08x capsule id 0x%08x)", 
							(*msg)->tz_id, curr_cred, (*msg)->capsule_id, symm_id );
	}

	return res;		
}

/* Format: KEY size -> 128 B 
 *         VALUE size -> 128 B
 * 		KEY1 VALUE1 VALID/INVALID
 * 		KEY2 VALUE2 VALID/INVALID
 * 		...
 */

/* Search the stateFile and write the value to a key. If it does not exist,
 * append to the end of the state file or next available */
TEE_Result do_set_state( unsigned char* key, uint32_t klen, 
						 unsigned char* val, uint32_t vlen ) {

	TEE_Result res = TEE_SUCCESS;
	uint32_t   count;
	uint8_t    state[2*STATE_SIZE + 1];
	uint8_t   *key_state = &state[0];
	uint8_t   *val_state = &state[STATE_SIZE];
	uint8_t   *valid = &state[2*STATE_SIZE];
	uint32_t   write_off = 0;
	uint32_t   new_write_pos = 0;
	uint64_t   cnt_a, cnt_b;

	//MSG( "Setting key: %s val: %s", key, val );

	if( vlen > STATE_SIZE || klen > STATE_SIZE ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "val/key buffer %u/%u B too large"
					        "(need to be less than %u B", 
							vlen, klen, STATE_SIZE );
	}

	cnt_a = read_cntpct();
	res = TEE_SeekObjectData( stateFile, 0, TEE_DATA_SEEK_SET );
	cnt_b = read_cntpct();
	timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
	CHECK_SUCCESS( res, "TEE_SeekObjectData() Error" );

	/* First check to see if this state already exists */
	while( 1 ) {
		cnt_a = read_cntpct();
		res = TEE_ReadObjectData( stateFile, state, sizeof(state), &count ); 
		cnt_b = read_cntpct();
		timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
		CHECK_SUCCESS( res, "TEE_ReadObjectData Error" );

		if( count == 0 ) {
			new_write_pos = write_off * ( sizeof(state) );		
			//MSG( "Writing to end of file %u", new_write_pos );
			break;
		}
	
		if( strcmp( (const char*) key, (const char*) key_state ) == 0 ) {
			new_write_pos = write_off * ( sizeof(state) );
			//MSG( "Writing to offset %u, key found", new_write_pos );
			break;
		}
		
		if( new_write_pos == 0 && *valid == 0 ) {
			new_write_pos = write_off * ( sizeof(state) );
			//MSG( "Write to first invalid entry %u", new_write_pos );
		}

		write_off++;
	}

	/*  Add the state in at the first available slot */
	memset( state, 0, sizeof(state) );
	memcpy( key_state, key, klen );
	memcpy( val_state, val, vlen );
	*valid = 1;

	cnt_a = read_cntpct();
	res = TEE_SeekObjectData( stateFile, new_write_pos, TEE_DATA_SEEK_SET );
	res = TEE_WriteObjectData( stateFile, state, sizeof(state) );
	cnt_b = read_cntpct();
	timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
	CHECK_SUCCESS( res, "TEE_WriteObjectData Error" );

	return res;
}

TEE_Result do_get_state( unsigned char* key, unsigned char* val, 
						 uint32_t vlen ) {
	TEE_Result res = TEE_SUCCESS;
	uint32_t   count;
	bool       found = false;
	uint8_t    state[2*STATE_SIZE+1];
	uint8_t   *key_state = &state[0];
	uint8_t   *val_state = &state[STATE_SIZE];
	uint8_t   *valid = &state[2*STATE_SIZE];
	uint64_t  cnt_a, cnt_b;

	//MSG( "Looking for key: %s", key );

	if( vlen < STATE_SIZE ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "val buffer %u B too small" 
						    "(need to be larger than %u B", 
							vlen, STATE_SIZE );
	}

	cnt_a = read_cntpct();
	res = TEE_SeekObjectData( stateFile, 0, TEE_DATA_SEEK_SET );
	cnt_b = read_cntpct();
	timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
	CHECK_SUCCESS( res, "TEE_SeekObjectData() Error" );

	while( 1 ) {
		cnt_a = read_cntpct();
		res = TEE_ReadObjectData( stateFile, state, 2*STATE_SIZE+1, &count );
		cnt_b = read_cntpct();
		timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
		CHECK_SUCCESS( res, "TEE_ReadObjectData Error" );

		if( count == 0 ) break;
		if( strcmp( (const char*) key, (const char*) key_state ) == 0 
			&& *valid != 0 ) {
			found = true;
			memcpy( val, val_state, STATE_SIZE );
			break;
		}
	}

	if( found == false ) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		CHECK_SUCCESS( res, "key %s not found", key );
	}
	return res;	
}

TEE_Result do_ftruncate( int fd, uint32_t new_data_length ) {
	
	uint32_t 				current_data_length = cap_head.data_end - 
								   				  cap_head.data_begin;
	int                     diff_length = new_data_length - 
										  current_data_length;
	int                     extended = 0;
	struct cap_text_entry   temp_entry;
	TEE_Result              res = TEE_SUCCESS;
	unsigned char           fill[BLOCK_LEN];
	unsigned char           hash[HASH_LEN];
	size_t                  hlen = HASH_LEN;
	struct TrustedCap       header;
	uint32_t                t_len, wr_len = 0;
	/* (1) If new_data_length > current_data_length
	 *    - Call do_write to fill it up to the desired length
	 *      with '\0'
	 * (2) If new_data_length < current_data_length
	 * 	  - Calculate the length that should be shortened, 
	 * 	    accounting for trusted capsule hashes, delimiter,
	 * 	    policy and headers.
	 * 	  - Call TEE_SimpleFtruncate() to shorten the file
	 * 	    Rehash the last chunk
	 *
	 * 	  Corner case, data size is ftruncated to 0
	 *    - Call TEE_SimpleFtruncate() to remove all data
	 *    - Modify do_open(), do_read(), do_write(), do_move_data_up(),
	 *      do_move_data_down() accordingly (not sure what exactly 
	 *      needs to be done, should add this to our capsule_test 
	 *      cases - might not
	 *      need to change anythign at all) 
	 *    Update capsule_text states
	 *    Rewrite header. 	  
	 */

	initialize_capsule_entries(&temp_entry, 0, 0, cap_head.data_begin);
	LIST_INSERT_END( &temp_entry, &cap_head.proc_entries, entries );

	if( diff_length > 0 ) {
		memset( fill, '\0', sizeof(fill) );
		while( extended < diff_length ) { 
			wr_len = (int) sizeof(fill) > diff_length - extended ? 
					 diff_length - extended : (int) sizeof(fill);
			res = do_write( fd, 0, 0, fill, &wr_len, true, true );
			if( res != TEE_SUCCESS ) {
				MSG( "Do_write() error" );
				goto do_ftruncate_exit;
			}
			extended += wr_len;
		}
	} else if( diff_length < 0 ) {
		res = truncate_data( fd, &hash_head, current_data_length -
						     new_data_length, symm_chunk_size,
						     &cap_head );

		t_len = cap_head.file_len + HASH_LEN * 
				(calc_chk_num(cap_head.file_len, symm_chunk_size) + 1);

		res = hash_hashlist( &hash_head, hash, hlen, hash_op );
		if( res != TEE_SUCCESS ) {
			MSG( "Hash_hashlist() Error" );
			goto do_ftruncate_exit;
		}	
		res = fill_header( &header, encrypt_op, symm_iv, symm_iv_len,
						   symm_id, hash, hlen, t_len );
		if( res != TEE_SUCCESS ) {
			MSG( "Fill_header() Error" );
			goto do_ftruncate_exit;
		}
		if( write_header(fd, &header) != sizeof(struct TrustedCap) ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			MSG( "Write_header() -> wrote less than %u B", 
				 sizeof( struct TrustedCap ) );
			goto do_ftruncate_exit;
		}
	}	

do_ftruncate_exit:
	LIST_REMOVE( &temp_entry, &cap_head.proc_entries, entries );
	return res;
}

TEE_Result do_fstat( uint32_t* data_length ) {
	*data_length = cap_head.data_end - cap_head.data_begin;
	return TEE_SUCCESS;	
}
