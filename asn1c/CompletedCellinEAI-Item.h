/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_CompletedCellinEAI_Item_H_
#define	_CompletedCellinEAI_Item_H_


#include <asn_application.h>

/* Including external dependencies */
#include "EUTRAN-CGI.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* CompletedCellinEAI-Item */
typedef struct CompletedCellinEAI_Item {
	EUTRAN_CGI_t	 eCGI;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CompletedCellinEAI_Item_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CompletedCellinEAI_Item;
extern asn_SEQUENCE_specifics_t asn_SPC_CompletedCellinEAI_Item_specs_1;
extern asn_TYPE_member_t asn_MBR_CompletedCellinEAI_Item_1[2];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ProtocolExtensionContainer.h"

#endif	/* _CompletedCellinEAI_Item_H_ */
#include <asn_internal.h>
