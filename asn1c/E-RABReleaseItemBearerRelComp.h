/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "../asn1/S1AP-PDU-Contents.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_E_RABReleaseItemBearerRelComp_H_
#define	_E_RABReleaseItemBearerRelComp_H_


#include <asn_application.h>

/* Including external dependencies */
#include "E-RAB-ID.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* E-RABReleaseItemBearerRelComp */
typedef struct E_RABReleaseItemBearerRelComp {
	E_RAB_ID_t	 e_RAB_ID;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_RABReleaseItemBearerRelComp_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E_RABReleaseItemBearerRelComp;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ProtocolExtensionContainer.h"

#endif	/* _E_RABReleaseItemBearerRelComp_H_ */
#include <asn_internal.h>
