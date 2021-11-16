/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_ForbiddenLAs_Item_H_
#define	_ForbiddenLAs_Item_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PLMNidentity.h"
#include "ForbiddenLACs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* ForbiddenLAs-Item */
typedef struct ForbiddenLAs_Item {
	PLMNidentity_t	 pLMN_Identity;
	ForbiddenLACs_t	 forbiddenLACs;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ForbiddenLAs_Item_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ForbiddenLAs_Item;
extern asn_SEQUENCE_specifics_t asn_SPC_ForbiddenLAs_Item_specs_1;
extern asn_TYPE_member_t asn_MBR_ForbiddenLAs_Item_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ProtocolExtensionContainer.h"

#endif	/* _ForbiddenLAs_Item_H_ */
#include <asn_internal.h>
