/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "../asn1/S1AP-PDU-Contents.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_E_RABReleaseCommand_H_
#define	_E_RABReleaseCommand_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ProtocolIE-Container.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* E-RABReleaseCommand */
typedef struct E_RABReleaseCommand {
	ProtocolIE_Container_122P16_t	 protocolIEs;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_RABReleaseCommand_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E_RABReleaseCommand;

#ifdef __cplusplus
}
#endif

#endif	/* _E_RABReleaseCommand_H_ */
#include <asn_internal.h>
