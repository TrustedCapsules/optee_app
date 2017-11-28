#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <capsule.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "capsule_ta.h"
#include "capsule_lua_ext.h"
#include "capsule_structures.h"
#include "capsule_helper.h"


unsigned long long read_cntpct(void) {
	unsigned long long ts;
//#ifdef HIKEY
//	asm volatile( "mrs %0, cntpct_el0" : "=r" (ts) );
//#else
	asm volatile( "mrrc p15, 0, %Q0, %R0, c14" : "=r" (ts) );
//#endif
	return ts;
}


int getfield( lua_State *L, int key, int tindex ) {
	int result;
	lua_geti( L, tindex, key ); /* Pops key, puts t[key] */
	if( !lua_isinteger( L, -1 ) ) 
		luaL_error( L, "Redact array must be integers" );
	result = lua_tointeger( L, -1 );
	lua_pop( L, 1 ); /* Remove number */
	return result;
}


TEE_Result lua_read_redact( lua_State *L, int state_tgid, int state_fd,
							unsigned char *bp, uint32_t len ) {

	int						 cur_stack = lua_gettop( L );
	int         			 start, end, table, table_start, table_end;
	unsigned int             i;
	char					 replace_char[2];
	TEE_Result				 res = TEE_SUCCESS;
	struct cap_text_entry   *cap_entry;

	/* Default replacement character */
	replace_char[0] = ' ';
	replace_char[1] = '\0';

	res = lua_get_replacement_char( L, replace_char );
	CHECK_SUCCESS( res, "lua_get_replacement_char() error" );

	lua_getglobal( L, REDACT_OFFSETS );

	if( !lua_isnil( L, -1 ) ) {
		if( !lua_istable( Lstate, -1 ) ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "'%s' should be a table", REDACT_OFFSETS );
		}

		table = lua_gettop( L );

		cap_entry = find_capsule_entry( &cap_head.proc_entries, state_tgid, state_fd );
	   	if( cap_entry == NULL ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "find_capsule_entry() -> tgid/fd %d/%d not found", 
						   state_tgid, state_fd );	
		}

		start = cap_entry->data_pos - cap_head.data_begin - len;
		end = cap_entry->data_pos - cap_head.data_begin;

		// MSG( "start: %d, end: %d", start, end );

		for( i = 1; i <= lua_rawlen( L, table ); i=i+2 ) {
			table_start = getfield( L, i, table );
			table_end = getfield( L, i+1, table );
			// MSG( "table_start: %d, table_end: %d", table_start, table_end );
	
			if( start > table_start && end > table_end && table_end >= start ) {	
				/* <------------>
			 	*		 <----------------------------> */
				memset( bp, replace_char[0], table_end - start + 1 );
			} else if( table_start > start && table_end > end && end >= table_start ) {
				/*                                <------------>
			 	*       <----------------------------> */
				memset( bp + table_start - start, replace_char[0], end - table_start + 1);
				break;
			} else if( table_start >= start && table_end <= end ) {
				/*                 <-------->
			 	*       <-----------------------------> */
				memset( bp + table_start - start, replace_char[0], table_end - table_start + 1 ); 
			} else if( table_start < start && table_end > end ) {
				/*  <------------------------------------------>
			 	*       <-----------------------------> */
				memset( bp, replace_char[0], len );
				break;
			}
			/* <-->
			 *        <----------------------------> */	
		
			/*                                        <---->
			 *        <----------------------------> */
		}
	}

	lua_settop( L, cur_stack );

	return res;
}


TEE_Result lua_get_replacement_char( lua_State *L, char* replace ) {
    int res = TEE_SUCCESS;
    const char* temp;
    size_t len;

    lua_getglobal( L, REPLACE_CHAR );
    if ( !lua_isstring( L, -1 ) ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "'%s' should be a string", REPLACE_CHAR );
    }

    temp = lua_tolstring( L, -1, &len );
    memcpy( replace, temp, len );

    lua_pop( L, 1);

    return TEE_SUCCESS;
}

/* Get the secure server address */
TEE_Result lua_get_server_ip_port( lua_State *L, char* ts, int* port ) {

	int res = TEE_SUCCESS;	
	const char* temp;
	size_t      len;

	lua_getglobal( L, SERVER_IP );
	if( !lua_isstring( L, -1 ) ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "'%s' should be a string", SERVER_IP );
	}

	temp = lua_tolstring( L, -1, &len );
	memcpy( ts, temp, len );
	lua_pop( L, 1 );

	lua_getglobal( L, SERVER_PORT );
	if( !lua_isinteger( L, -1 ) ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "'%s' should be an integer", SERVER_PORT );
	}

	*port = lua_tointeger( L, -1 );
	lua_pop( L, 1 );

	return TEE_SUCCESS;
}

/* Load a policy file into Lua interpreter */
TEE_Result lua_load_policy( lua_State *L, const char* buf ) {

	int res = TEE_SUCCESS;
	int ret = luaL_loadstring( L, buf ) || 
			  lua_pcall( L, 0, 0, 0 );
	if( ret != LUA_OK ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "policy Lua file cannot be run >> error"
						    " code %d", ret );
	}

	return res;
}	

/* Start a new Lua context */
void lua_start_context( lua_State **L ) {
	*L = luaL_newstate();
	luaL_openlibs( *L );
}

/* Close a Lua context */
void lua_close_context( lua_State **L ) {
	if( *L != NULL )
		lua_close( *L );
	*L = NULL;
}

/* Read a chunk of data */
// TODO JAMES: caching
uint32_t read_block( int fd, void* buf, size_t blen, uint32_t off ) {
	uint32_t nr = 0, read = 0;
	uint64_t cnt_a, cnt_b;
	do {
		cnt_a = read_cntpct();
		TEE_SimpleRead( fd, ( (unsigned char*) buf ) + read, 
						     blen - read, &nr, off );
	   	cnt_b = read_cntpct();
		timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
		if( (int) nr < 0 ) {
			return nr;
		}
		
		read += nr;	
	} while( read < blen && nr > 0 );
	return read;
}

/* Write a chunk of data */
uint32_t write_block( int fd, void* buf, size_t blen, uint32_t off ) {
	uint32_t nw = 0, written = 0;
	uint64_t cnt_a, cnt_b;
	do {
		cnt_a = read_cntpct();
		TEE_SimpleWrite( fd, ( (unsigned char*) buf ) + written, 
							  blen - written, &nw, off );
		cnt_b = read_cntpct();
		timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
		if( (int) nw < 0 ) {
			return nw;
		}
		written += nw;
	} while( written < blen && nw > 0 );
	return written;
}

/* Calculate the chunk length from an offset */
uint32_t calc_chk_len( uint32_t off, uint32_t chlen ) {
	uint32_t len = off % chlen;
	if( len == 0 && off != 0 ) {
		len = chlen;
	}
	return len;
}

/* Calculate the chunk number from an offset */
uint32_t calc_chk_num( uint32_t off, uint32_t chlen ) {
	uint32_t ch = off / chlen;
	if( off % chlen == 0 && off != 0 ) {
		ch -= 1;
	}
	return ch;
}

/* Add a policy of a plain text file and transform it into capsule */
/*
TEE_Result add_policy() {

}
*/
/* Modify the policy of a capsule */
/*
TEE_Result modify_policy() {

}
*/
/* Performs encryption and decryption for a piece of data */
TEE_Result process_aes_block( unsigned char* ptx, size_t *plen,
							  unsigned char* ctx, size_t clen,
							  uint8_t *iv, uint32_t iv_len, uint32_t ctr,
							  bool first, bool last,
							  TEE_OperationHandle op ) {
	TEE_Result res = TEE_SUCCESS;
	uint64_t   cnt_a, cnt_b;

	cnt_a = read_cntpct();
	
	if( first ) {
		TEE_CipherInit( op, iv, iv_len, ctr );
	}

	if( last ) {
		res = TEE_CipherDoFinal( op, ctx, clen, ptx, plen );
		CHECK_SUCCESS( res, "TEE_CipherDoFinal() Error" );
	} else {
		res = TEE_CipherUpdate( op, ctx, clen, ptx, plen );
		CHECK_SUCCESS( res, "TEE_CipherUpdate() Error" );
	}

	cnt_b = read_cntpct();

	timestamps[curr_ts].encryption += cnt_b - cnt_a;

	return res;
}

/* Wrapper for network hashing */
TEE_Result hash_data( unsigned char* payload, size_t payload_len,
				 	  unsigned char* hash, size_t hlen ) {
	return hash_block( payload, payload_len, hash, hlen, 1, hash_op );
}

/* Hashes a block of data */
TEE_Result hash_block( unsigned char* ptx, size_t plen,
					   unsigned char* hash, size_t hlen, 
					   bool last, TEE_OperationHandle op ) {
	
	TEE_Result res = TEE_SUCCESS;
	uint64_t	cnt_a, cnt_b;

	cnt_a = read_cntpct();

	if( hlen != HASH_LEN ) {
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if( last ) {
		res = TEE_DigestDoFinal( op, ptx, plen, hash, &hlen );
		CHECK_SUCCESS( res, "TEE_DigestDoFinal() Error" );
	} else {
		TEE_DigestUpdate( op, ptx, plen );
	}

	cnt_b = read_cntpct();

	timestamps[curr_ts].hashing += cnt_b - cnt_a;

	return res;
}

/* Writes a block of encrypted data to the file. This block does not
 * extend past a chunk boundary */
TEE_Result write_enc_file_block( int fd, unsigned char* ptx,
								 size_t plen, size_t *written, 
			   					 uint32_t bl_off, uint32_t chnum, 
								 uint32_t chsize, uint32_t keylen,
								 unsigned char* iv, uint32_t ivlen,
								 TEE_OperationHandle op	) {
	
	TEE_Result 	    res = TEE_SUCCESS;
	uint32_t        init_ctr = 0, p_off = 0, f_off = 0;
	unsigned char   ctx[BLOCK_LEN];
	size_t          ctxlen = sizeof(ctx)/keylen * keylen;
    size_t       	len;
	bool		    first, last = false;
	uint32_t        nw = 0, ns = 0;
	

	UNUSED( nw );
	UNUSED( ns );

	/* bl_off must be aligned to keylen */
	if( bl_off % keylen != 0 ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Bl_off %u is not aligned with"
					        " key length %u", bl_off, keylen );
	}
	
	init_ctr = bl_off / keylen;
	f_off = bl_off + sizeof( struct TrustedCap ) + HASH_LEN +
			chnum * ( chsize + HASH_LEN );
	// res = TEE_SimpleLseek( fd, f_off, TEE_DATA_SEEK_SET, &ns );
    // TODO: add check for result

	//MSG( "BEFORE LOOP bl_off: %u, plen: %u, p_off: %u, ns: %d, nw: %d,"
	//	 " ctxlen: %u, len: %u, first: %s, last: %s, init_ctr: %u,"
	//	 " f_off: %u", bl_off, plen, p_off, ns, nw, ctxlen, len, 
	//	 first == true ? "true" : "false", 
	//	 last == true ? "true" : "false", init_ctr, f_off );

	/* Encrypt ptx to get the ctx */
	first = true;
	while( last == false ) {	
		ctxlen = ctxlen / keylen * keylen;
		if( plen - p_off > ctxlen ) {
			len = ctxlen;		
		} else {
			len = plen - p_off;
			last = true;
		}
		
		res = process_aes_block( ctx, &ctxlen, ptx + p_off, len, iv, 
						         ivlen, init_ctr, first, last, op );
		CHECK_SUCCESS( res, "Process_aes_block() Error" );
		nw = write_block( fd, ctx, ctxlen, f_off ); 
		if( nw != (int) ctxlen ) {
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Write_block() wrote only %u/%u B",
						   nw, ctxlen );
		}
		
		//MSG( "bl_off: %u, plen: %u, p_off: %u, ns: %d, nw: %d,"
		//	 " ctxlen: %u, len: %u, first: %s, last: %s, init_ctr: %u,"
		//	 " f_off: %u", bl_off, plen, p_off, ns, nw, ctxlen, len, 
		//	 first == true ? "true" : "false", 
		//	 last == true ? "true" : "false", init_ctr, f_off );
		
		p_off += ctxlen;
        f_off += ctxlen; // Update offset to write to
		first = false;
	}

	*written = p_off;
	return res;
}

/* Reads a block of encrypted data from the file. This block does not
 * extend past a chunk boundary */
TEE_Result read_enc_file_block( int fd, unsigned char* ptx, 
				                size_t ptxlen, size_t *plen, 
								uint32_t chnum, uint32_t chsize,
								uint32_t keylen, uint32_t bl_off, 
								uint32_t bl_len, unsigned char* iv, 
								uint32_t iv_len, 
								TEE_OperationHandle op ) {

	TEE_Result 		res = TEE_SUCCESS;
	uint32_t   		init_ctr = 0, f_off = 0;
	uint32_t   		aligned_off = 0;
	uint32_t   		aligned_end = 0;
	uint32_t        rlen;
	unsigned char   ctx[BLOCK_LEN];
	size_t			ctxlen = sizeof(ctx);
	uint32_t        nr;//, ns;
    int             i, before = 0, after = 0;

	UNUSED(nr);
	// UNUSED(ns);

	if( ptxlen < keylen || ptxlen < BLOCK_LEN ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Buffer is too small, we are too"
					        " lazy to calculate remainders" );
	}

	/* Align buffer size to keylen because we do not want to deal
	 * with calculating remainders in the cipher text buffer */
	ptxlen = ptxlen / keylen * keylen;
	ctxlen = ctxlen / keylen * keylen;

	if( ctxlen > ptxlen ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Buffer is too small, we really" 
							"  would like ptx buffer to be bigger" );
	}
	

	init_ctr = bl_off / keylen;

	aligned_off = bl_off / keylen * keylen;	
   	aligned_end = ( bl_off + bl_len + (keylen - 1) )/keylen  * keylen;	
	f_off = aligned_off + sizeof( struct TrustedCap ) + HASH_LEN +
			chnum*(chsize + HASH_LEN);
	
	// res = TEE_SimpleLseek( fd, f_off, TEE_DATA_SEEK_SET, &ns );
    // CHECK_SUCCESS( res, "TEE_SimpleLseek() Error" );

	rlen = aligned_end - aligned_off;
	if( rlen > ctxlen ) {
		rlen = ctxlen;
	} 

	nr = read_block( fd, ctx, rlen, f_off );
	if( nr < 0 ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Read_block() Error" );
	}
	
	res = process_aes_block( ptx, &ptxlen, ctx, nr, iv, iv_len, 
							 init_ctr, true, true, op );
	CHECK_SUCCESS( res, "Process_aes_block() Error" );

	/* Copy only the portion we asked for */
	before = bl_off - aligned_off;
	if( before > 0 ) {
		for( i = before; i < (int) ptxlen; i++ ) {
			ptx[i - before] = ptx[i];
		}
	}

	after = aligned_end - ( bl_off + bl_len ) > ( rlen - nr ) ?
			aligned_end - (bl_off + bl_len ) - ( rlen - nr ) : 0;

	*plen = ptxlen - ( before + after );

	//DMSG( "offset: %d, bl_off: %u, bl_len: %u, aligned_off: %u," 
	//	 " aligned_end: %u, ptxlen: %u, ctr: %u, before: %u, "
	//	 " after: %u, nr: %d, rlen: %u, plen: %u", 
	//	  ns, bl_off, bl_len, aligned_off, aligned_end, ptxlen, 
	//	  init_ctr, before, after, nr, rlen, *plen );
	return res;
}

TEE_Result truncate_data( int fd, struct HashList* head, 
						  uint32_t diff_off, uint32_t ch_sz, 
						  struct capsule_text* text	) {
	
	TEE_Result 		   res = TEE_SUCCESS;
	uint32_t 		   nchk_to_remove, orig_nchk, new_nchk, t_len;
	struct hash_entry *p = NULL;

	orig_nchk = calc_chk_num( text->file_len, ch_sz );	
	
	text->data_end -= diff_off;
	text->file_len -= diff_off;

	new_nchk = calc_chk_num( text->file_len, ch_sz );

	t_len = text->file_len + sizeof( struct TrustedCap ) + 
			HASH_LEN * ( new_nchk + 1 );
	if( TEE_SimpleFtruncate( fd, t_len ) != TEE_SUCCESS ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "TEE_SimpleFtruncate() Error" );
	}

	nchk_to_remove = orig_nchk - new_nchk;
	while( nchk_to_remove > 0 ) {
		LIST_REMOVE_END( p, head, entries ); 
		if( p != NULL ) 
			TEE_Free( p );
		p = NULL;
		nchk_to_remove--;
	}

	return res;
}

bool verify_hash( uint32_t ch, struct HashList *head, 
				  unsigned char* hash, size_t hlen ) {
	struct hash_entry *p = head->first;
	int                found = 0;

	/* Get the right hash in the hashlist */
	while( p != NULL ) {
		//MSG( "p->chnum %d, ch %d", p->chnum, ch );
		if( p->chnum == ch ) { 
			found = 1;
			break;
		}
		p = p->entries.next;
	}
	
	if( found == 0 ) {
		//MSG( "No hash for this chunk was found" );
		return true;
	}
	
	//MSG( "CHUNK %u, %02x%02x%02x%02x%02x%02x%02x%02x", ch,
	//	 p->hash[0], p->hash[1], p->hash[2], p->hash[3], p->hash[4],
	//	 p->hash[5], p->hash[6], p->hash[7] );

	//MSG( "CHUNK %u, %02x%02x%02x%02x%02x%02x%02x%02x", ch,
	//	 hash[0], hash[1], hash[2], hash[3], hash[4],
	//	 hash[5], hash[6], hash[7] );
	
	return compare_hashes( hash, p->hash, hlen );
}

int read_hash( int fd, unsigned char* hash, size_t hlen, 
				uint32_t chnum, uint32_t chSize ) {
    uint32_t f_off = sizeof( struct TrustedCap ) + 
			         chnum * ( hlen + chSize );
	/*
    uint64_t cnt_a, cnt_b;
    uint32_t ns;
	UNUSED( ns );
	cnt_a = read_cntpct();
	TEE_SimpleLseek( fd, f_off, TEE_DATA_SEEK_SET, &ns );
	cnt_b = read_cntpct();
	timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
    */
	return read_block( fd, hash, hlen, f_off );
}


/* Writes the new hash for a chunk. Changes or adds the hash to 
 * in-memory hashlist */
int write_hash( int fd, unsigned char* hash, size_t hlen, 
				 struct HashList *head, uint32_t chnum, 
				 uint32_t chSize ) {
	
	struct hash_entry *p = head->first;
	uint32_t    		   f_off = sizeof( struct TrustedCap ) + 
					 		   chnum * ( hlen + chSize );	
	uint32_t 		   ns;
	uint64_t           cnt_a, cnt_b;

	UNUSED(ns);

	/* Get the right hash in the hashlist */
	while( p != NULL ) {
		if( p->chnum == chnum ) {
			break;
		}
		p = p->entries.next;
	}

	//MSG( "CHUNK %u, F_OFF %u: %02x%02x%02x%02x%02x%02x%02x%02x", 
	//	 chnum, f_off,
	//	 hash[0], hash[1], hash[2], hash[3], hash[4],
	//	 hash[5], hash[6], hash[7] );

	if( p == NULL ) {
		add_to_hashlist( hash, hlen, head, chnum );
	} else {
		memcpy( p->hash, hash, hlen );
	}

	/* Write the hash to file */
	/*
    cnt_a = read_cntpct();
	TEE_SimpleLseek( fd, f_off, TEE_DATA_SEEK_SET, &ns );
	cnt_b = read_cntpct();
	timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
	*/
    return write_block( fd, hash, hlen, f_off );

	//MSG( "ns = %d, nw = %d", ns, nw );
}

/* Check if a chunk has a hash in hashlist */
bool is_in_hashlist( struct HashList *head, uint32_t chnum ) {
	struct hash_entry *p = head->first;

	LIST_FOREACH( p, head, entries ) {
		if( p->chnum == chnum ) return true; 	
	}
	return false;
}

/* Add hash to hashlist */
void add_to_hashlist( unsigned char* hash, size_t hlen, 
					  struct HashList *head, uint32_t chnum ) {
	//MSG( "In add_to_hashlist" );
	struct hash_entry *p = head->first;
	bool insert = false;

	// Create entry
	//MSG( "Create entry" ); 
	struct hash_entry *p_new;
	p_new = TEE_Malloc( sizeof( struct hash_entry ), 0 );
	memcpy( p_new->hash, hash, hlen );
	p_new->chnum = chnum;

	// Insert in order
	while( p != NULL ) {
		// If p is bigger than the new one (i.e. insert before p)
		if (p->chnum > chnum) {
			// if p == head then need to set the first value of head, if it's tail, we
			// inserted before it. 
			//MSG( "Set p_new prev" );
			p_new->entries.prev = p->entries.prev;

			//MSG( "Set p_new next " );
			p_new->entries.next = p;

			if (p->entries.prev == NULL) {
				//MSG("p is head");
				head -> first = p_new;
			} else {
				//MSG( "Set p.prev next" );
				p -> entries.prev -> entries.next = p_new;
			}

			//MSG( "Set p prev" );
			p->entries.prev = p_new;

			insert = true;
			break;
		}
		p = p->entries.next;
	}

	if (insert == false) {
		// We should insert at the end
		LIST_INSERT_END( p_new, head, entries); 
	}
}

/* Free all hash entries */
void free_hashlist( struct HashList *head ) {
	struct hash_entry *p, *q;
	p = head->first;
	while( p != NULL ) {
		q = p;
		p = p->entries.next;
		TEE_Free( q );
	}
}

void free_caplist( struct CapTextList *head ) {
	struct cap_text_entry *p, *q;
	p = head->first;
	while( p != NULL ) {
		q = p;
		p = p->entries.next;
		TEE_Free( q );
	}
}
/* Compare two hashes */
bool compare_hashes( unsigned char* hash1, unsigned char* hash2,
				     size_t hlen ) {
	size_t n;
	for( n = 0; n < hlen; n++ ) {
		if( hash1[n] != hash2[n] ) {
			MSG( "hash1: %02x%02x%02x%02x does not match hash2: %02x%02x%02x%02x", 
				 hash1[0], hash1[1], hash1[2], hash1[3], hash2[0], hash2[1], hash2[2], hash2[3]);
			return false;
		}
	}
	return true;
}

/* Calculate hash of hases */
TEE_Result hash_hashlist( struct HashList *head, 
				          unsigned char* hash, size_t hlen, 
						  TEE_OperationHandle op ) {
	
	TEE_Result         res = TEE_SUCCESS;
	struct hash_entry *p;

	if( hlen != HASH_LEN ) {
		return TEE_ERROR_NOT_SUPPORTED;
	}

	LIST_FOREACH( p, head, entries ) {
		//MSG( "chnum %u: %02x%02x", p->chnum, p->hash[0], p->hash[1] );
		TEE_DigestUpdate( op, p->hash, hlen );
	}
	res = TEE_DigestDoFinal( op, NULL, 0, hash, &hlen );
	CHECK_SUCCESS( res, "TEE_DigestDoFinal() Error" );

	return res;	
}

/* Initialize the capsule text buffer */
void initialize_capsule_text( struct capsule_text* p ) {
	p->policy_index = 0;
	p->policy_begin = 0;
	p->policy_end = 0;
	p->data_index = 0;
	p->data_begin = 0;
	p->data_end = 0;
	p->file_len = 0;
	p->policy_pos = 0;
}

/* Initialize the capsule_text_entries */
void initialize_capsule_entries( struct cap_text_entry *p,
			                     int state_tgid, int state_fd,
								 unsigned int d_pos	) {
	p->state_tgid = state_tgid;
	p->state_fd = state_fd;
	p->data_pos = d_pos;
}

/* Goes through all the cap_text_entry that exist in the linked list. 
	finds the one that matches the start and end offsets.
*/
struct cap_text_entry* find_capsule_entry( struct CapTextList *head, 
										   int state_tgid, int state_fd ) {
	struct cap_text_entry *p;

	LIST_FOREACH( p, head, entries ) {
		//MSG( "Find_capsule_entry()-> found %d/%d...looking for %d/%d",
		//	 p->state_tgid, p->state_fd, state_tgid, state_fd );
		if( p->state_tgid == state_tgid && p->state_fd == state_fd ) {
			return p;
		}
	}
	
	return NULL;
}

/* Check that a key was found */
bool key_not_found( uint8_t *gl_iv, uint32_t gl_id,
			        uint32_t gl_iv_len, uint32_t gl_key_len ) {
	if( gl_iv == NULL || gl_id == 0 || 
		gl_iv_len == 0 || gl_key_len == 0 ) {
		return true;
	}
	return false;
}

/* Find a key for trusted capsule */
TEE_Result find_key( struct TrustedCap *h, 
					 TEE_ObjectHandle file,
			   		 TEE_OperationHandle *dec_op,
					 TEE_OperationHandle *enc_op,
					 TEE_OperationHandle *sha_op,
					 uint32_t *gl_id, 
					 uint32_t *gl_iv_len,
					 uint32_t *gl_key_len, 
					 uint32_t *gl_chunk_size,
					 uint8_t **gl_iv ) {
	
	TEE_Result 	 	 res = TEE_SUCCESS;
	TEE_ObjectHandle handle = TEE_HANDLE_NULL;
	TEE_Attribute   *attrs = NULL;
	uint32_t   		 total_size, count, id, iv_len;
    uint32_t   		 key_attr_len, key_len, chunk_size;
	uint32_t         attr_count, cap_id;
	uint8_t   		*attr_buf = NULL, *it = NULL;
    uint8_t    	    *iv = NULL, *key_attr = NULL;
	size_t           id_len = 4;	
	uint64_t         cnt_a, cnt_b;

	cnt_a = read_cntpct();
	res = TEE_SeekObjectData( file, 0, TEE_DATA_SEEK_SET );
	cnt_b = read_cntpct();
	timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
	CHECK_SUCCESS( res, "TEE_SeekObjectData() Error" );

	while( 1 ) {
		cnt_a = read_cntpct();	
		res = TEE_ReadObjectData( file, &total_size, 
						 		  sizeof(uint32_t), &count );
		cnt_b = read_cntpct();
		timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
		CHECK_GOTO( res, find_key_exit,
					  	"TEE_ReadObjectData() Error" );
		if( count == 0 ) { 
			res = TEE_ERROR_NOT_SUPPORTED;
			CHECK_SUCCESS( res, "Find_key() AES key not found" );
			goto find_key_exit;
		}
		//MSG( "Find_key()-> key data size: %u", total_size );

		attr_buf = TEE_Malloc( total_size, 0 );
		cnt_a = read_cntpct();
		res = TEE_ReadObjectData( file, attr_buf, 
								  total_size, &count );
		cnt_b = read_cntpct();
		timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
		if( count == 0 ) {
			MSG( "Find_key()-> key file seems to be corrupted" );
			res = TEE_ERROR_CORRUPT_OBJECT;
			goto find_key_exit;
		}

		it = attr_buf;

		chunk_size = *(uint32_t*) (void*) it;
		it += sizeof(uint32_t);
		key_len = *(uint32_t*) (void*) it;
		it += sizeof(uint32_t);
		id = *(uint32_t*) (void*) it;
		it += sizeof(uint32_t);
		iv_len = *(uint32_t*) (void*) it;
		it += sizeof(uint32_t);
		iv = TEE_Malloc( iv_len, 0 );
		memcpy( iv, it, iv_len );
		it += iv_len;
		
		key_attr_len = total_size - 4*sizeof(uint32_t) - iv_len;
		key_attr = TEE_Malloc( key_attr_len, 0 );
		memcpy( key_attr, it, key_attr_len );

		/* Check the header id vs. the key id */
		res = unpack_attrs( key_attr, key_attr_len, 
						   &attrs, &attr_count );
		CHECK_GOTO( res, find_key_exit, 
					"Unpack_attrs() Error" );
		res = TEE_AllocateTransientObject( TEE_TYPE_AES, 
										   key_len,
										   &handle );
		CHECK_GOTO( res, find_key_exit, 
					"TEE_AllocateTransientObject() Error" );
	
		res = TEE_PopulateTransientObject( handle, attrs, 
										   attr_count );
		CHECK_GOTO( res, find_key_exit, 
					"TEE_PopulateTransientObject() Error" );

		res = TEE_AllocateOperation( dec_op, TEE_ALG_AES_CTR,
									 TEE_MODE_DECRYPT, 
									 key_len );
		CHECK_GOTO( res, find_key_exit,
					"TEE_AllocateOperation() Error" );
			
		res = TEE_SetOperationKey( *dec_op, handle );
		CHECK_GOTO( res, find_key_exit, 
					"TEE_SetOperationKey() Error" );
	
		cnt_a = read_cntpct();
		TEE_CipherInit( *dec_op, iv, iv_len, 0 );

		res = TEE_CipherDoFinal( *dec_op, (void*) h->aes_id,
					   			 sizeof(uint32_t), 
								 (void*) &cap_id,
							 	 &id_len );
		cnt_b = read_cntpct();
		timestamps[curr_ts].encryption += cnt_b - cnt_a;
   		CHECK_GOTO( res, find_key_exit,
					"TEE_CipherDoFinal() Error" );		
	
		if( id == cap_id ) {
			//MSG( "Found AES Key %08x", id );
			*gl_id = id;
			*gl_iv_len = iv_len;
			*gl_key_len = key_len;
			*gl_iv = TEE_Malloc( *gl_iv_len, 0 );
			*gl_chunk_size = chunk_size;
			memcpy( *gl_iv, iv, iv_len );
			goto find_key_setup_keys;		
		}
	
		TEE_Free( attr_buf );
		TEE_Free( attrs );
		TEE_Free( key_attr ); 
		TEE_Free( iv );
		iv = NULL;
		attrs = NULL;
		attr_buf = NULL;
		key_attr = NULL;
		TEE_FreeOperation( *dec_op );
		TEE_FreeTransientObject( handle );
	}

	if( key_not_found( *gl_iv, *gl_id, *gl_iv_len, *gl_key_len ) ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Find_key() AES key not found" );
	}

	return res;

find_key_setup_keys:
	res = TEE_AllocateOperation( enc_op, TEE_ALG_AES_CTR,
								 TEE_MODE_ENCRYPT, *gl_key_len );
	CHECK_GOTO( res, find_key_exit, 
				"TEE_AllocateOperation Error %02x", res );

	res = TEE_SetOperationKey( *enc_op, handle );
	CHECK_GOTO( res, find_key_exit, 
				   "TEE_SetOperationKey() Error" );

	res = TEE_AllocateOperation( sha_op, TEE_ALG_SHA256,
								 TEE_MODE_DIGEST, 0 );
	CHECK_GOTO( res, find_key_exit, 
					"TEE_AllocateOperation() Error" );

find_key_exit:
	TEE_FreeTransientObject( handle );
	if( iv != NULL )
		TEE_Free( iv );
	if( attrs != NULL )
		TEE_Free( attrs );
	if( attr_buf != NULL )
		TEE_Free( attr_buf );
	if( key_attr != NULL )
		TEE_Free( key_attr );
	return res;
}

/* Constructs the TrustedCap header*/
TEE_Result fill_header( struct TrustedCap* cap, 
						TEE_OperationHandle op,
						uint8_t *iv, uint32_t iv_len, uint32_t id,
			   			unsigned char* hash, size_t hashlen, size_t
						fsize ) {
	TEE_Result res = TEE_SUCCESS;
	uint32_t   id_len = 4;
	uint64_t   cnt_a, cnt_b;

	memset( cap, 0, sizeof( struct TrustedCap ) );
	memcpy( cap->pad, "TRUSTEDCAP\0", sizeof( cap->pad ) );
	
	/* Encrypt the capsule ID */
	cnt_a = read_cntpct();
	TEE_CipherInit( op, iv, iv_len, 0 );
	res = TEE_CipherDoFinal( op, ( char*) &id, sizeof(uint32_t), 
					         cap->aes_id, &id_len );
	cnt_b = read_cntpct();
	timestamps[curr_ts].encryption += cnt_b - cnt_a;
	CHECK_SUCCESS( res, "TEE_CipherDoFinal() Error" );

	//MSG( "ID: %02x%02x%02x%02x\n", cap->aes_id[0], cap->aes_id[1], 
	//				               cap->aes_id[2], cap->aes_id[3] );
	cap->capsize = fsize;
	memcpy( cap->hash, hash, hashlen );

	return res;
}

/* Read the TrustedCap header */
int read_header( int fd, struct TrustedCap* cap ) {
    /*
    uint32_t ns;
	uint64_t cnt_a, cnt_b;
	UNUSED( ns );
	cnt_a = read_cntpct();
	TEE_SimpleLseek( fd, 0, TEE_DATA_SEEK_SET, &ns );
	cnt_b = read_cntpct();
	timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
	*/
    return read_block( fd, cap, sizeof( struct TrustedCap ), 0 );
	//MSG( "ns: %d, nr: %d", ns, nr );
}

/* Write the TrustedCap header */
int write_header( int fd, struct TrustedCap* cap ) {
    /*
    uint32_t ns;
	uint64_t cnt_a, cnt_b;
	UNUSED( ns );
	cnt_a = read_cntpct();
	TEE_SimpleLseek( fd, 0, TEE_DATA_SEEK_SET, &ns );
	cnt_b = read_cntpct();
	timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
	*/
    return write_block( fd, cap, sizeof( struct TrustedCap ), 0 );
	//MSG( "ns: %d, nw: %d", ns, nw );
}

/* Separate the data and policy sections of the trusted capsule */
void sep_policy_and_data( unsigned char* input, size_t inlen, 
						  struct capsule_text* cap, 
						  uint8_t *match_state, bool *matched, 
						  unsigned char* delimiter ) {
	size_t n;

	if ( *matched == false ) {
		for( n = 0; n < inlen; n++ ) {
			if( *match_state == DELIMITER_SIZE ) {
				cap->policy_end = cap->file_len + n - DELIMITER_SIZE;
				cap->data_begin = cap->file_len + n;
				*matched = true;
				*match_state = 0;
				break;
			}

			if( input[n] == delimiter[*match_state] ) {
				(*match_state)++;
			} else {
				if( input[n] == delimiter[0] ) {
					*match_state = 1;
				} else {
					*match_state = 0;
				}
			}		
		}
	}

	cap->file_len += inlen;
	cap->data_end = cap->file_len;
}

/* De-serialize the AES key */
TEE_Result unpack_attrs( const uint8_t* buf, uint32_t blen,
		                 TEE_Attribute **attrs, 
						 uint32_t *attrs_count ) {
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute* a = NULL;
	uint32_t num_attrs = 0;
	const size_t num_attrs_size = sizeof( uint32_t );
	const struct attr_packed *ap;

	if( blen == 0 ) 
		goto out;

	if( ( (uintptr_t) buf & 0x3 ) != 0 || blen < num_attrs_size )
		return TEE_ERROR_BAD_PARAMETERS;
	
	num_attrs = *(uint32_t*) (void *) buf;
	if( ( blen - num_attrs_size ) < ( num_attrs * sizeof(*ap) ) ) 
		return TEE_ERROR_BAD_PARAMETERS;

	ap = (const struct attr_packed*) \
		 (const void*) (buf+num_attrs_size);

	if( num_attrs > 0 ) {
		size_t n;

		a = TEE_Malloc( num_attrs * sizeof( TEE_Attribute ), 0 );
		if( !a )
			return TEE_ERROR_OUT_OF_MEMORY;
		for( n = 0; n < num_attrs; n++ ) {
			a[n].attributeID = ap[n].id;
			if( ap[n].id & TEE_ATTR_BIT_VALUE ) {
				a[n].content.value.a = ap[n].a;
				a[n].content.value.b = ap[n].b;
				continue;
			}

			a[n].content.ref.length = ap[n].b;

			if( ap[n].a ) {
				if( ap[n].a + ap[n].b > blen ) {
					res = TEE_ERROR_BAD_PARAMETERS;
					goto out;
				}
			}

			a[n].content.ref.buffer = (void*) ( (uintptr_t) buf + 
							          (uintptr_t) ap[n].a );
		}
	}

out:
	if( res == TEE_SUCCESS ) {
		*attrs = a;
		*attrs_count = num_attrs;
	} else {
		TEE_Free( a );
	}
	return res;
}
