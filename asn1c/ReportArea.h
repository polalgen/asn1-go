/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_ReportArea_H_
#define	_ReportArea_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ReportArea {
	ReportArea_ecgi	= 0
	/*
	 * Enumeration is extensible
	 */
} e_ReportArea;

/* ReportArea */
typedef long	 ReportArea_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ReportArea_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ReportArea;
extern asn_INTEGER_specifics_t asn_SPC_ReportArea_specs_1;
asn_struct_free_f ReportArea_free;
asn_struct_print_f ReportArea_print;
asn_constr_check_f ReportArea_constraint;
ber_type_decoder_f ReportArea_decode_ber;
der_type_encoder_f ReportArea_encode_der;
xer_type_decoder_f ReportArea_decode_xer;
xer_type_encoder_f ReportArea_encode_xer;
per_type_decoder_f ReportArea_decode_uper;
per_type_encoder_f ReportArea_encode_uper;
per_type_decoder_f ReportArea_decode_aper;
per_type_encoder_f ReportArea_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _ReportArea_H_ */
#include <asn_internal.h>