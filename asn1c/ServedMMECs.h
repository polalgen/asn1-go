/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_ServedMMECs_H_
#define	_ServedMMECs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MME-Code.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ServedMMECs */
typedef struct ServedMMECs {
	A_SEQUENCE_OF(MME_Code_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ServedMMECs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ServedMMECs;
extern asn_SET_OF_specifics_t asn_SPC_ServedMMECs_specs_1;
extern asn_TYPE_member_t asn_MBR_ServedMMECs_1[1];
extern asn_per_constraints_t asn_PER_type_ServedMMECs_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _ServedMMECs_H_ */
#include <asn_internal.h>
