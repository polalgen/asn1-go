/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_Cell_Size_H_
#define	_Cell_Size_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Cell_Size {
	Cell_Size_verysmall	= 0,
	Cell_Size_small	= 1,
	Cell_Size_medium	= 2,
	Cell_Size_large	= 3
	/*
	 * Enumeration is extensible
	 */
} e_Cell_Size;

/* Cell-Size */
typedef long	 Cell_Size_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Cell_Size_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Cell_Size;
extern asn_INTEGER_specifics_t asn_SPC_Cell_Size_specs_1;
asn_struct_free_f Cell_Size_free;
asn_struct_print_f Cell_Size_print;
asn_constr_check_f Cell_Size_constraint;
ber_type_decoder_f Cell_Size_decode_ber;
der_type_encoder_f Cell_Size_encode_der;
xer_type_decoder_f Cell_Size_decode_xer;
xer_type_encoder_f Cell_Size_encode_xer;
per_type_decoder_f Cell_Size_decode_uper;
per_type_encoder_f Cell_Size_encode_uper;
per_type_decoder_f Cell_Size_decode_aper;
per_type_encoder_f Cell_Size_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _Cell_Size_H_ */
#include <asn_internal.h>
