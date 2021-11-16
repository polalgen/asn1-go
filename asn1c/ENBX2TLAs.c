/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#include "ENBX2TLAs.h"

asn_per_constraints_t asn_PER_type_ENBX2TLAs_constr_1 GCC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 1,  1,  1l,  2l }	/* (SIZE(1..2)) */,
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_ENBX2TLAs_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (3 << 2)),
		0,
		&asn_DEF_TransportLayerAddress,
		0,	/* Defer constraints checking to the member type */
		&asn_PER_type_TransportLayerAddress_constr_1,
		0,
		""
		},
};
static const ber_tlv_tag_t asn_DEF_ENBX2TLAs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SET_OF_specifics_t asn_SPC_ENBX2TLAs_specs_1 = {
	sizeof(struct ENBX2TLAs),
	offsetof(struct ENBX2TLAs, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_ENBX2TLAs = {
	"ENBX2TLAs",
	"ENBX2TLAs",
	&asn_OP_SEQUENCE_OF,
	SEQUENCE_OF_constraint,
	asn_DEF_ENBX2TLAs_tags_1,
	sizeof(asn_DEF_ENBX2TLAs_tags_1)
		/sizeof(asn_DEF_ENBX2TLAs_tags_1[0]), /* 1 */
	asn_DEF_ENBX2TLAs_tags_1,	/* Same as above */
	sizeof(asn_DEF_ENBX2TLAs_tags_1)
		/sizeof(asn_DEF_ENBX2TLAs_tags_1[0]), /* 1 */
	&asn_PER_type_ENBX2TLAs_constr_1,
	asn_MBR_ENBX2TLAs_1,
	1,	/* Single element */
	&asn_SPC_ENBX2TLAs_specs_1	/* Additional specs */
};
