/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_ENB_ID_H_
#define	_ENB_ID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ENB_ID_PR {
	ENB_ID_PR_NOTHING,	/* No components present */
	ENB_ID_PR_macroENB_ID,
	ENB_ID_PR_homeENB_ID
	/* Extensions may appear below */
	
} ENB_ID_PR;

/* ENB-ID */
typedef struct ENB_ID {
	ENB_ID_PR present;
	union ENB_ID_u {
		BIT_STRING_t	 macroENB_ID;
		BIT_STRING_t	 homeENB_ID;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ENB_ID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ENB_ID;
extern asn_CHOICE_specifics_t asn_SPC_ENB_ID_specs_1;
extern asn_TYPE_member_t asn_MBR_ENB_ID_1[2];
extern asn_per_constraints_t asn_PER_type_ENB_ID_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _ENB_ID_H_ */
#include <asn_internal.h>