/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#include "Cdma2000OneXSRVCCInfo.h"

static asn_TYPE_member_t asn_MBR_Cdma2000OneXSRVCCInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Cdma2000OneXSRVCCInfo, cdma2000OneXMEID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Cdma2000OneXMEID,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cdma2000OneXMEID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Cdma2000OneXSRVCCInfo, cdma2000OneXMSI),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Cdma2000OneXMSI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cdma2000OneXMSI"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Cdma2000OneXSRVCCInfo, cdma2000OneXPilot),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Cdma2000OneXPilot,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cdma2000OneXPilot"
		},
	{ ATF_POINTER, 1, offsetof(struct Cdma2000OneXSRVCCInfo, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_173P3,
		0,	/* Defer constraints checking to the member type */
		&asn_PER_type_ProtocolExtensionContainer_173P3_constr_7,
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_Cdma2000OneXSRVCCInfo_oms_1[] = { 3 };
static const ber_tlv_tag_t asn_DEF_Cdma2000OneXSRVCCInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Cdma2000OneXSRVCCInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cdma2000OneXMEID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cdma2000OneXMSI */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* cdma2000OneXPilot */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_Cdma2000OneXSRVCCInfo_specs_1 = {
	sizeof(struct Cdma2000OneXSRVCCInfo),
	offsetof(struct Cdma2000OneXSRVCCInfo, _asn_ctx),
	asn_MAP_Cdma2000OneXSRVCCInfo_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_Cdma2000OneXSRVCCInfo_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	3,	/* Start extensions */
	5	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_Cdma2000OneXSRVCCInfo = {
	"Cdma2000OneXSRVCCInfo",
	"Cdma2000OneXSRVCCInfo",
	&asn_OP_SEQUENCE,
	SEQUENCE_constraint,
	asn_DEF_Cdma2000OneXSRVCCInfo_tags_1,
	sizeof(asn_DEF_Cdma2000OneXSRVCCInfo_tags_1)
		/sizeof(asn_DEF_Cdma2000OneXSRVCCInfo_tags_1[0]), /* 1 */
	asn_DEF_Cdma2000OneXSRVCCInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_Cdma2000OneXSRVCCInfo_tags_1)
		/sizeof(asn_DEF_Cdma2000OneXSRVCCInfo_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_Cdma2000OneXSRVCCInfo_1,
	4,	/* Elements count */
	&asn_SPC_Cdma2000OneXSRVCCInfo_specs_1	/* Additional specs */
};

