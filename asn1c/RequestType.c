/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#include "RequestType.h"

static asn_TYPE_member_t asn_MBR_RequestType_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RequestType, eventType),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_EventType,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"eventType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RequestType, reportArea),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ReportArea,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"reportArea"
		},
	{ ATF_POINTER, 1, offsetof(struct RequestType, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_173P26,
		0,	/* Defer constraints checking to the member type */
		&asn_PER_type_ProtocolExtensionContainer_173P26_constr_53,
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_RequestType_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_RequestType_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RequestType_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* eventType */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* reportArea */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_RequestType_specs_1 = {
	sizeof(struct RequestType),
	offsetof(struct RequestType, _asn_ctx),
	asn_MAP_RequestType_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_RequestType_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* Start extensions */
	4	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RequestType = {
	"RequestType",
	"RequestType",
	&asn_OP_SEQUENCE,
	SEQUENCE_constraint,
	asn_DEF_RequestType_tags_1,
	sizeof(asn_DEF_RequestType_tags_1)
		/sizeof(asn_DEF_RequestType_tags_1[0]), /* 1 */
	asn_DEF_RequestType_tags_1,	/* Same as above */
	sizeof(asn_DEF_RequestType_tags_1)
		/sizeof(asn_DEF_RequestType_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RequestType_1,
	3,	/* Elements count */
	&asn_SPC_RequestType_specs_1	/* Additional specs */
};

