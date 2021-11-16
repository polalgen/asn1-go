/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-CommonDataTypes"
 * 	found in "../asn1/S1AP-CommonDataTypes.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#include "PrivateIE-ID.h"

static int
memb_local_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long long *)sptr;
	
	if((value >= 0LL && value <= 65535LL)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_local_constr_2 GCC_NOTUSED = {
	{ APC_CONSTRAINED,	 16,  16,  0l,  65535l }	/* (0..65535) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_per_constraints_t asn_PER_type_PrivateIE_ID_constr_1 GCC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0l,  1l }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_PrivateIE_ID_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PrivateIE_ID, choice.local),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_local_constraint_1,
		&asn_PER_memb_local_constr_2,
		0,
		"local"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PrivateIE_ID, choice.global),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OBJECT_IDENTIFIER,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"global"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_PrivateIE_ID_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* local */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* global */
};
asn_CHOICE_specifics_t asn_SPC_PrivateIE_ID_specs_1 = {
	sizeof(struct PrivateIE_ID),
	offsetof(struct PrivateIE_ID, _asn_ctx),
	offsetof(struct PrivateIE_ID, present),
	sizeof(((struct PrivateIE_ID *)0)->present),
	asn_MAP_PrivateIE_ID_tag2el_1,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_PrivateIE_ID = {
	"PrivateIE-ID",
	"PrivateIE-ID",
	&asn_OP_CHOICE,
	CHOICE_constraint,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_PrivateIE_ID_constr_1,
	asn_MBR_PrivateIE_ID_1,
	2,	/* Elements count */
	&asn_SPC_PrivateIE_ID_specs_1	/* Additional specs */
};
