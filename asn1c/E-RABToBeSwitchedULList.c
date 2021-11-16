/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "../asn1/S1AP-PDU-Contents.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#include "E-RABToBeSwitchedULList.h"

int
E_RABToBeSwitchedULList_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1LL && size <= 256LL)) {
		/* Perform validation of the inner elements */
		return td->check_constraints(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using ProtocolIE_ContainerList_159P0,
 * so here we adjust the DEF accordingly.
 */
static const ber_tlv_tag_t asn_DEF_E_RABToBeSwitchedULList_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_E_RABToBeSwitchedULList = {
	"E-RABToBeSwitchedULList",
	"E-RABToBeSwitchedULList",
	&asn_OP_SEQUENCE_OF,
	E_RABToBeSwitchedULList_constraint,
	asn_DEF_E_RABToBeSwitchedULList_tags_1,
	sizeof(asn_DEF_E_RABToBeSwitchedULList_tags_1)
		/sizeof(asn_DEF_E_RABToBeSwitchedULList_tags_1[0]), /* 1 */
	asn_DEF_E_RABToBeSwitchedULList_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_RABToBeSwitchedULList_tags_1)
		/sizeof(asn_DEF_E_RABToBeSwitchedULList_tags_1[0]), /* 1 */
	&asn_PER_type_ProtocolIE_ContainerList_159P0_constr_1,
	asn_MBR_ProtocolIE_ContainerList_159P0_1,
	1,	/* Single element */
	&asn_SPC_ProtocolIE_ContainerList_159P0_specs_1	/* Additional specs */
};

