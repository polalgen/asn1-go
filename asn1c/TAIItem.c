/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "../asn1/S1AP-PDU-Contents.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#include "TAIItem.h"

static asn_TYPE_member_t asn_MBR_TAIItem_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TAIItem, tAI),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TAI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tAI"
		},
	{ ATF_POINTER, 1, offsetof(struct TAIItem, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_173P61,
		0,	/* Defer constraints checking to the member type */
		&asn_PER_type_ProtocolExtensionContainer_173P61_constr_123,
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_TAIItem_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_TAIItem_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_TAIItem_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tAI */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_TAIItem_specs_1 = {
	sizeof(struct TAIItem),
	offsetof(struct TAIItem, _asn_ctx),
	asn_MAP_TAIItem_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_TAIItem_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	1,	/* Start extensions */
	3	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_TAIItem = {
	"TAIItem",
	"TAIItem",
	&asn_OP_SEQUENCE,
	SEQUENCE_constraint,
	asn_DEF_TAIItem_tags_1,
	sizeof(asn_DEF_TAIItem_tags_1)
		/sizeof(asn_DEF_TAIItem_tags_1[0]), /* 1 */
	asn_DEF_TAIItem_tags_1,	/* Same as above */
	sizeof(asn_DEF_TAIItem_tags_1)
		/sizeof(asn_DEF_TAIItem_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_TAIItem_1,
	2,	/* Elements count */
	&asn_SPC_TAIItem_specs_1	/* Additional specs */
};

