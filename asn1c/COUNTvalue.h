/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_COUNTvalue_H_
#define	_COUNTvalue_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PDCP-SN.h"
#include "HFN.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* COUNTvalue */
typedef struct COUNTvalue {
	PDCP_SN_t	 pDCP_SN;
	HFN_t	 hFN;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} COUNTvalue_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_COUNTvalue;
extern asn_SEQUENCE_specifics_t asn_SPC_COUNTvalue_specs_1;
extern asn_TYPE_member_t asn_MBR_COUNTvalue_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ProtocolExtensionContainer.h"

#endif	/* _COUNTvalue_H_ */
#include <asn_internal.h>
