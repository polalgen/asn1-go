/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_E_RAB_ID_H_
#define	_E_RAB_ID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* E-RAB-ID */
typedef long	 E_RAB_ID_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_E_RAB_ID_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_E_RAB_ID;
asn_struct_free_f E_RAB_ID_free;
asn_struct_print_f E_RAB_ID_print;
asn_constr_check_f E_RAB_ID_constraint;
ber_type_decoder_f E_RAB_ID_decode_ber;
der_type_encoder_f E_RAB_ID_encode_der;
xer_type_decoder_f E_RAB_ID_decode_xer;
xer_type_encoder_f E_RAB_ID_encode_xer;
per_type_decoder_f E_RAB_ID_decode_uper;
per_type_encoder_f E_RAB_ID_encode_uper;
per_type_decoder_f E_RAB_ID_decode_aper;
per_type_encoder_f E_RAB_ID_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _E_RAB_ID_H_ */
#include <asn_internal.h>