/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_CauseProtocol_H_
#define	_CauseProtocol_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CauseProtocol {
	CauseProtocol_transfer_syntax_error	= 0,
	CauseProtocol_abstract_syntax_error_reject	= 1,
	CauseProtocol_abstract_syntax_error_ignore_and_notify	= 2,
	CauseProtocol_message_not_compatible_with_receiver_state	= 3,
	CauseProtocol_semantic_error	= 4,
	CauseProtocol_abstract_syntax_error_falsely_constructed_message	= 5,
	CauseProtocol_unspecified	= 6
	/*
	 * Enumeration is extensible
	 */
} e_CauseProtocol;

/* CauseProtocol */
typedef long	 CauseProtocol_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CauseProtocol_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CauseProtocol;
extern asn_INTEGER_specifics_t asn_SPC_CauseProtocol_specs_1;
asn_struct_free_f CauseProtocol_free;
asn_struct_print_f CauseProtocol_print;
asn_constr_check_f CauseProtocol_constraint;
ber_type_decoder_f CauseProtocol_decode_ber;
der_type_encoder_f CauseProtocol_encode_der;
xer_type_decoder_f CauseProtocol_decode_xer;
xer_type_encoder_f CauseProtocol_encode_xer;
per_type_decoder_f CauseProtocol_decode_uper;
per_type_encoder_f CauseProtocol_encode_uper;
per_type_decoder_f CauseProtocol_decode_aper;
per_type_encoder_f CauseProtocol_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _CauseProtocol_H_ */
#include <asn_internal.h>