/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Descriptions"
 * 	found in "../asn1/S1AP-PDU-Descriptions.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_SuccessfulOutcome_H_
#define	_SuccessfulOutcome_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ProcedureCode.h"
#include "Criticality.h"
#include <ANY.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SuccessfulOutcome */
typedef struct SuccessfulOutcome {
	ProcedureCode_t	 procedureCode;
	Criticality_t	 criticality;
	ANY_t	 value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SuccessfulOutcome_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SuccessfulOutcome;
extern asn_SEQUENCE_specifics_t asn_SPC_SuccessfulOutcome_specs_1;
extern asn_TYPE_member_t asn_MBR_SuccessfulOutcome_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _SuccessfulOutcome_H_ */
#include <asn_internal.h>
