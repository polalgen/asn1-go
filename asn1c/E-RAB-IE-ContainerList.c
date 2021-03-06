/*
 * Generated by asn1c-1.0.0 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "../asn1/S1AP-PDU-Contents.asn"
 * 	`asn1c -gen-PER -fcompound-names -S ../skeletons`
 */

#include "E-RAB-IE-ContainerList.h"

int
E_RAB_IE_ContainerList_261P0_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
int
E_RAB_IE_ContainerList_261P1_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
int
E_RAB_IE_ContainerList_261P2_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
int
E_RAB_IE_ContainerList_261P3_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
int
E_RAB_IE_ContainerList_261P4_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
int
E_RAB_IE_ContainerList_261P5_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
static const ber_tlv_tag_t asn_DEF_E_RAB_IE_ContainerList_261P0_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_E_RAB_IE_ContainerList_261P0 = {
	"E-RAB-IE-ContainerList",
	"E-RAB-IE-ContainerList",
	&asn_OP_SEQUENCE_OF,
	E_RAB_IE_ContainerList_261P0_constraint,
	asn_DEF_E_RAB_IE_ContainerList_261P0_tags_1,
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P0_tags_1)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P0_tags_1[0]), /* 1 */
	asn_DEF_E_RAB_IE_ContainerList_261P0_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P0_tags_1)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P0_tags_1[0]), /* 1 */
	&asn_PER_type_ProtocolIE_ContainerList_159P0_constr_1,
	asn_MBR_ProtocolIE_ContainerList_159P0_1,
	1,	/* Single element */
	&asn_SPC_ProtocolIE_ContainerList_159P0_specs_1	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_E_RAB_IE_ContainerList_261P1_tags_2[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_E_RAB_IE_ContainerList_261P1 = {
	"E-RAB-IE-ContainerList",
	"E-RAB-IE-ContainerList",
	&asn_OP_SEQUENCE_OF,
	E_RAB_IE_ContainerList_261P1_constraint,
	asn_DEF_E_RAB_IE_ContainerList_261P1_tags_2,
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P1_tags_2)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P1_tags_2[0]), /* 1 */
	asn_DEF_E_RAB_IE_ContainerList_261P1_tags_2,	/* Same as above */
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P1_tags_2)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P1_tags_2[0]), /* 1 */
	&asn_PER_type_ProtocolIE_ContainerList_159P0_constr_1,
	asn_MBR_ProtocolIE_ContainerList_159P0_1,
	1,	/* Single element */
	&asn_SPC_ProtocolIE_ContainerList_159P0_specs_1	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_E_RAB_IE_ContainerList_261P2_tags_3[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_E_RAB_IE_ContainerList_261P2 = {
	"E-RAB-IE-ContainerList",
	"E-RAB-IE-ContainerList",
	&asn_OP_SEQUENCE_OF,
	E_RAB_IE_ContainerList_261P2_constraint,
	asn_DEF_E_RAB_IE_ContainerList_261P2_tags_3,
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P2_tags_3)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P2_tags_3[0]), /* 1 */
	asn_DEF_E_RAB_IE_ContainerList_261P2_tags_3,	/* Same as above */
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P2_tags_3)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P2_tags_3[0]), /* 1 */
	&asn_PER_type_ProtocolIE_ContainerList_159P0_constr_1,
	asn_MBR_ProtocolIE_ContainerList_159P0_1,
	1,	/* Single element */
	&asn_SPC_ProtocolIE_ContainerList_159P0_specs_1	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_E_RAB_IE_ContainerList_261P3_tags_4[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_E_RAB_IE_ContainerList_261P3 = {
	"E-RAB-IE-ContainerList",
	"E-RAB-IE-ContainerList",
	&asn_OP_SEQUENCE_OF,
	E_RAB_IE_ContainerList_261P3_constraint,
	asn_DEF_E_RAB_IE_ContainerList_261P3_tags_4,
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P3_tags_4)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P3_tags_4[0]), /* 1 */
	asn_DEF_E_RAB_IE_ContainerList_261P3_tags_4,	/* Same as above */
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P3_tags_4)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P3_tags_4[0]), /* 1 */
	&asn_PER_type_ProtocolIE_ContainerList_159P0_constr_1,
	asn_MBR_ProtocolIE_ContainerList_159P0_1,
	1,	/* Single element */
	&asn_SPC_ProtocolIE_ContainerList_159P0_specs_1	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_E_RAB_IE_ContainerList_261P4_tags_5[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_E_RAB_IE_ContainerList_261P4 = {
	"E-RAB-IE-ContainerList",
	"E-RAB-IE-ContainerList",
	&asn_OP_SEQUENCE_OF,
	E_RAB_IE_ContainerList_261P4_constraint,
	asn_DEF_E_RAB_IE_ContainerList_261P4_tags_5,
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P4_tags_5)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P4_tags_5[0]), /* 1 */
	asn_DEF_E_RAB_IE_ContainerList_261P4_tags_5,	/* Same as above */
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P4_tags_5)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P4_tags_5[0]), /* 1 */
	&asn_PER_type_ProtocolIE_ContainerList_159P0_constr_1,
	asn_MBR_ProtocolIE_ContainerList_159P0_1,
	1,	/* Single element */
	&asn_SPC_ProtocolIE_ContainerList_159P0_specs_1	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_E_RAB_IE_ContainerList_261P5_tags_6[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_E_RAB_IE_ContainerList_261P5 = {
	"E-RAB-IE-ContainerList",
	"E-RAB-IE-ContainerList",
	&asn_OP_SEQUENCE_OF,
	E_RAB_IE_ContainerList_261P5_constraint,
	asn_DEF_E_RAB_IE_ContainerList_261P5_tags_6,
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P5_tags_6)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P5_tags_6[0]), /* 1 */
	asn_DEF_E_RAB_IE_ContainerList_261P5_tags_6,	/* Same as above */
	sizeof(asn_DEF_E_RAB_IE_ContainerList_261P5_tags_6)
		/sizeof(asn_DEF_E_RAB_IE_ContainerList_261P5_tags_6[0]), /* 1 */
	&asn_PER_type_ProtocolIE_ContainerList_159P0_constr_1,
	asn_MBR_ProtocolIE_ContainerList_159P0_1,
	1,	/* Single element */
	&asn_SPC_ProtocolIE_ContainerList_159P0_specs_1	/* Additional specs */
};

