/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_ForbiddenInterRATs_H_
#define	_ForbiddenInterRATs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ForbiddenInterRATs {
	ForbiddenInterRATs_all	= 0,
	ForbiddenInterRATs_geran	= 1,
	ForbiddenInterRATs_utran	= 2,
	ForbiddenInterRATs_cdma2000	= 3
	/*
	 * Enumeration is extensible
	 */
} e_ForbiddenInterRATs;

/* ForbiddenInterRATs */
typedef long	 ForbiddenInterRATs_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ForbiddenInterRATs_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ForbiddenInterRATs;
extern asn_INTEGER_specifics_t asn_SPC_ForbiddenInterRATs_specs_1;
asn_struct_free_f ForbiddenInterRATs_free;
asn_struct_print_f ForbiddenInterRATs_print;
asn_constr_check_f ForbiddenInterRATs_constraint;
ber_type_decoder_f ForbiddenInterRATs_decode_ber;
der_type_encoder_f ForbiddenInterRATs_encode_der;
xer_type_decoder_f ForbiddenInterRATs_decode_xer;
xer_type_encoder_f ForbiddenInterRATs_encode_xer;
per_type_decoder_f ForbiddenInterRATs_decode_uper;
per_type_encoder_f ForbiddenInterRATs_encode_uper;
per_type_decoder_f ForbiddenInterRATs_decode_aper;
per_type_encoder_f ForbiddenInterRATs_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _ForbiddenInterRATs_H_ */
#include <asn_internal.h>
