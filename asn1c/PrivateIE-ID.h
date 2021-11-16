/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-CommonDataTypes"
 * 	found in "../asn1/S1AP-CommonDataTypes.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_PrivateIE_ID_H_
#define	_PrivateIE_ID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <OBJECT_IDENTIFIER.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PrivateIE_ID_PR {
	PrivateIE_ID_PR_NOTHING,	/* No components present */
	PrivateIE_ID_PR_local,
	PrivateIE_ID_PR_global
} PrivateIE_ID_PR;

/* PrivateIE-ID */
typedef struct PrivateIE_ID {
	PrivateIE_ID_PR present;
	union PrivateIE_ID_u {
		long	 local;
		OBJECT_IDENTIFIER_t	 global;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PrivateIE_ID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PrivateIE_ID;
extern asn_CHOICE_specifics_t asn_SPC_PrivateIE_ID_specs_1;
extern asn_TYPE_member_t asn_MBR_PrivateIE_ID_1[2];
extern asn_per_constraints_t asn_PER_type_PrivateIE_ID_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _PrivateIE_ID_H_ */
#include <asn_internal.h>