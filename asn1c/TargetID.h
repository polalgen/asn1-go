/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_TargetID_H_
#define	_TargetID_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TargeteNB-ID.h"
#include "TargetRNC-ID.h"
#include "CGI.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TargetID_PR {
	TargetID_PR_NOTHING,	/* No components present */
	TargetID_PR_targeteNB_ID,
	TargetID_PR_targetRNC_ID,
	TargetID_PR_cGI
	/* Extensions may appear below */
	
} TargetID_PR;

/* TargetID */
typedef struct TargetID {
	TargetID_PR present;
	union TargetID_u {
		TargeteNB_ID_t	 targeteNB_ID;
		TargetRNC_ID_t	 targetRNC_ID;
		CGI_t	 cGI;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TargetID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TargetID;

#ifdef __cplusplus
}
#endif

#endif	/* _TargetID_H_ */
#include <asn_internal.h>
