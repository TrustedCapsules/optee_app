#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <capsuleCommon.h>

#define TA_UUID CAPSULE_UUID

/* These flags refer to section 4.5 of Internal API.
 * It appears that as long as TA_FLAG_SINGLE_INSTANCE 
 * is not set, then a separate instance should be created
 * for each new session
 */

#define TA_FLAGS            ( TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE       (64 * 1024)
#define TA_DATA_SIZE        (256 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "gp.ta.description", USER_TA_PROP_TYPE_STRING, "TrustedCap Secure World App" }, \
	{ "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }


#endif /* USER_TA_HEADER_DEFINES_H */
