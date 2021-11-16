/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#include "S-TMSI.h"

asn_TYPE_member_t asn_MBR_S_TMSI_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct S_TMSI, mMEC),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MME_Code,
		0,	/* Defer constraints checking to the member type */
		&asn_PER_type_MME_Code_constr_1,
		0,
		"mMEC"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct S_TMSI, m_TMSI),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_M_TMSI,
		0,	/* Defer constraints checking to the member type */
		&asn_PER_type_M_TMSI_constr_1,
		0,
		"m-TMSI"
		},
	{ ATF_POINTER, 1, offsetof(struct S_TMSI, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_173P35,
		0,	/* Defer constraints checking to the member type */
		&asn_PER_type_ProtocolExtensionContainer_173P35_constr_71,
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_S_TMSI_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_S_TMSI_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_S_TMSI_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mMEC */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* m-TMSI */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_S_TMSI_specs_1 = {
	sizeof(struct S_TMSI),
	offsetof(struct S_TMSI, _asn_ctx),
	asn_MAP_S_TMSI_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_S_TMSI_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* Start extensions */
	4	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_S_TMSI = {
	"S-TMSI",
	"S-TMSI",
	&asn_OP_SEQUENCE,
	SEQUENCE_constraint,
	asn_DEF_S_TMSI_tags_1,
	sizeof(asn_DEF_S_TMSI_tags_1)
		/sizeof(asn_DEF_S_TMSI_tags_1[0]), /* 1 */
	asn_DEF_S_TMSI_tags_1,	/* Same as above */
	sizeof(asn_DEF_S_TMSI_tags_1)
		/sizeof(asn_DEF_S_TMSI_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_S_TMSI_1,
	3,	/* Elements count */
	&asn_SPC_S_TMSI_specs_1	/* Additional specs */
};

