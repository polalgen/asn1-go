/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../asn1/S1AP-IEs.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#include "LAC.h"

int
LAC_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	size = st->size;
	
	if((size == 2LL)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using OCTET_STRING,
 * so here we adjust the DEF accordingly.
 */
asn_per_constraints_t asn_PER_type_LAC_constr_1 GCC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  2l,  2l }	/* (SIZE(2..2)) */,
	0, 0	/* No PER value map */
};
static const ber_tlv_tag_t asn_DEF_LAC_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))
};
asn_TYPE_descriptor_t asn_DEF_LAC = {
	"LAC",
	"LAC",
	&asn_OP_OCTET_STRING,
	LAC_constraint,
	asn_DEF_LAC_tags_1,
	sizeof(asn_DEF_LAC_tags_1)
		/sizeof(asn_DEF_LAC_tags_1[0]), /* 1 */
	asn_DEF_LAC_tags_1,	/* Same as above */
	sizeof(asn_DEF_LAC_tags_1)
		/sizeof(asn_DEF_LAC_tags_1[0]), /* 1 */
	&asn_PER_type_LAC_constr_1,
	0, 0,	/* No members */
	&asn_SPC_OCTET_STRING_specs	/* Additional specs */
};
