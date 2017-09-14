#ifndef STRUCTURE_H
#define STRUCTURE_H

#define LIST_HEAD( name, type ) \
		struct name {			\
			struct type *first; \
			struct type *last;  \
		}

#define LIST_ENTRY(type) 		\
		struct {		 		\
			struct type *next;  \
			struct type *prev;  \
		}

#define LIST_INIT( head ) do {  \
		(head)->first = NULL;	\
		(head)->last = NULL;	\
} while( 0 )                   

#define LIST_REMOVE( var, head, field ) do {                           \
		if( (var)->field.prev == NULL && (var)->field.next == NULL ) { \
			(head)->first = NULL;									   \
			(head)->last = NULL;									   \
		} else if( (var)->field.prev == NULL ) {                       \
			(head)->first = (var)->field.next;                         \
			((var)->field.next)->field.prev = NULL;                    \
		} else if( (var)->field.next == NULL ) {                       \
			(head)->last = (var)->field.prev;                          \
			((var)->field.prev)->field.next = NULL;                    \
		} else {                                                       \
			((var)->field.prev)->field.next = (var)->field.next;       \
			((var)->field.next)->field.prev = (var)->field.prev;       \
		}															   \
} while( 0 )

#define LIST_REMOVE_END( var, head, field ) do {   \
		if( (head)->last != NULL ) {			   \
			(var) = (head)->last;				   \
			(head)->last = (var)->field.prev;	   \
			if( (head)->last != NULL ) {		   \
				(head)->last->field.next = NULL;   \
			}								       \
		}										   \
} while( 0 )

#define LIST_INSERT_END( elm, head, field ) do {   \
		if( (head)->last == NULL ) {			   \
			(elm)->field.prev = NULL;			   \
			(head)->first = (elm);				   \
		} else {								   \
			(head)->last->field.next = (elm);	   \
			(elm)->field.prev = (head)->last;	   \
		}                                          \
		(head)->last = (elm);				       \
		(elm)->field.next = NULL;				   \
} while( 0 )

#define LIST_FOREACH( var, head, field )       \
		for( (var) = ( (head)->first ); (var); \
			 (var) = ( (var)->field.next ) )   


LIST_HEAD( HashList, hash_entry );
LIST_HEAD( CapTextList, cap_text_entry );


struct hash_entry {
	LIST_ENTRY( hash_entry ) entries;
	unsigned char hash[32];
	uint32_t      chnum;
};

struct cap_text_entry{
	LIST_ENTRY( cap_text_entry ) entries;
	int  state_tgid;
	int  state_fd;
	
	/* capsule cursor */
	unsigned int    data_pos;
};

struct capsule_text {
	// CapTextList represents the head of a linked list 
	//	See capsule_structures.c for creation with LIST_HEAD	
	struct CapTextList  proc_entries;
		
	char* 				policy_buf;
	/* valid bytes in policy_buf */
	size_t 				policy_index;

	/* begin/end index of policy in capsule */
	unsigned int		policy_begin;
	unsigned int		policy_end;
	/* policy cursor */
	unsigned int    	policy_pos;
	

	char*       		data_buf;
	/* valid bytes in data_buf */
	size_t				data_index;
	
	/* begin/end index of data in capsule */
	unsigned int		data_begin;
	unsigned int		data_end;

	/* capsule length */
	unsigned int    	file_len;

};



#endif /*STRUCTURE_H*/
