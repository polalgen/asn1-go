/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-CommonDataTypes"
 * 	found in "../asn1/S1AP-CommonDataTypes.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#ifndef	_ProtocolExtensionID_H_
#define	_ProtocolExtensionID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ProtocolExtensionID */
typedef long	 ProtocolExtensionID_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ProtocolExtensionID_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolExtensionID;
asn_struct_free_f ProtocolExtensionID_free;
asn_struct_print_f ProtocolExtensionID_print;
asn_constr_check_f ProtocolExtensionID_constraint;
ber_type_decoder_f ProtocolExtensionID_decode_ber;
der_type_encoder_f ProtocolExtensionID_encode_der;
xer_type_decoder_f ProtocolExtensionID_decode_xer;
xer_type_encoder_f ProtocolExtensionID_encode_xer;
per_type_decoder_f ProtocolExtensionID_decode_uper;
per_type_encoder_f ProtocolExtensionID_encode_uper;
per_type_decoder_f ProtocolExtensionID_decode_aper;
per_type_encoder_f ProtocolExtensionID_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _ProtocolExtensionID_H_ */
#include <asn_internal.h>
