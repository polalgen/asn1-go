#include <stdio.h>
#include <assert.h>

#include <OCTET_STRING.h>
#include <per_support.h>

static unsigned char buf[0xffff];
static int buf_offset;

static int
_buf_writer(const void *buffer, size_t size, void *app_key) {
	unsigned char *b, *bend;
	(void)app_key;
	assert(buf_offset + size < sizeof(buf));
	memcpy(buf + buf_offset, buffer, size);
	b = buf + buf_offset;
	bend = b + size;
#ifdef EMIT_ASN_DEBUG
	fprintf(stderr, "=> [");
	for(; b < bend; b++) {
		if(*b >= 32 && *b < 127 && *b != '%')
			fprintf(stderr, "%c", *b);
		else
			fprintf(stderr, "%%%02x", *b);
	}
	fprintf(stderr, "]:%zd\n", size);
#endif
	buf_offset += size;
	return 0;
}

static void
check_per_encode_constrained(
		const char* filename, int lineno,
		long long lbound, long long ubound, int rbits, int ebits,
		const uint8_t* dec_val, size_t dec_len,
		const uint8_t* enc_val, size_t enc_len) {
	OCTET_STRING_t st;
	OCTET_STRING_t *reconstructed_st = 0;
	struct asn_per_constraints_s cts;
	asn_enc_rval_t enc_rval = {0};
	asn_dec_rval_t dec_rval = {0};

	printf("%s:%d: Testing (%lld..%lld) rbits:%d ebits:%d, len:%zu len:%zu\n",
			filename, lineno, lbound, ubound, rbits, ebits, dec_len, enc_len);

	memset(&st, 0, sizeof(st));
	memset(&cts, 0, sizeof(cts));

	cts.size.flags = APC_CONSTRAINED;
	cts.size.range_bits = rbits;
	cts.size.effective_bits = ebits;
	cts.size.lower_bound = lbound;
	cts.size.upper_bound = ubound;

	assert(0 == OCTET_STRING_fromBuf(&st, (const char*) dec_val, dec_len));

	asn_DEF_OCTET_STRING.per_constraints = &cts;

	buf_offset = 0;
	enc_rval = aper_encode(&asn_DEF_OCTET_STRING, &st, _buf_writer, NULL);

	assert(-1 != enc_rval.encoded);
	//assert(8 * enc_len == enc_rval.encoded);
	assert(0 == memcmp(buf, enc_val, buf_offset));

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING, &st);

	dec_rval = aper_decode(0, &asn_DEF_OCTET_STRING, (void**) &reconstructed_st, enc_val, enc_len, 0, 0);
	assert(0 == dec_rval.code);
	//assert(enc_len * 8 == dec_rval.consumed);
	assert(0 == memcmp(dec_val, reconstructed_st->buf, reconstructed_st->size));

	ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, reconstructed_st);

}

#define	CHECK(lbound, ubound, rbits, ebits, dec_val, dec_len, enc_val, enc_len)	\
	check_per_encode_constrained(__FILE__, __LINE__, lbound, ubound, rbits, ebits, dec_val, dec_len, enc_val, enc_len)

#define CHECK_4_20000(dec_val, enc_val) \
	CHECK(4, 20000, 15, 15, dec_val, sizeof(dec_val), enc_val, sizeof(enc_val))

static void
check_4_20000() {
	{
		const uint8_t dec[] = {0x01, 0x02, 0x03, 0x04};
		const uint8_t aper[] = {0x00, 0x00, 0x01, 0x02, 0x03, 0x04};
		CHECK_4_20000(dec, aper);
	}

	{
		const uint8_t dec[] = {0x01, 0x02, 0x03, 0x04, 0x05};
		const uint8_t aper[] = {0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05};
		CHECK_4_20000(dec, aper);
	}

	{
		const uint8_t dec[255] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		const uint8_t aper[257] = {0x00, 0xfb, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		CHECK_4_20000(dec, aper);
	}

	{
		const uint8_t dec[259] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		const uint8_t aper[261] = {0x00, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		CHECK_4_20000(dec, aper);
	}

	{
		const uint8_t dec[260] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		const uint8_t aper[262] = {0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		CHECK_4_20000(dec, aper);
	}

	{
		const uint8_t dec[1789] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		const uint8_t aper[1791] = {0x06, 0xf9, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		CHECK_4_20000(dec, aper);
	}

	{
		const uint8_t dec[20000] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		const uint8_t aper[20002] = {0x4e, 0x1c, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff};
		CHECK_4_20000(dec, aper);
	}
}

#define CHECK_2_127(dec_val, enc_val) \
	CHECK(2, 127, 7, 7, dec_val, sizeof(dec_val), enc_val, sizeof(enc_val))
static void
check_2_127() {

	{
		const uint8_t dec[] = {0xff, 0x02};
		const uint8_t aper[] = {0x01, 0xfe, 0x04};
		CHECK_2_127(dec, aper);
	}

	{
		const uint8_t dec[127] = {0x01, 0x02};
		const uint8_t aper[128] = {0xfa, 0x01, 0x02};
		CHECK_2_127(dec, aper);
	}
}

#define CHECK_2_256(dec_val, enc_val) \
	CHECK(2, 256, 8, 8, dec_val, sizeof(dec_val), enc_val, sizeof(enc_val))
static void
check_2_256() {

	{
		const uint8_t dec[] = {0xff, 0x02};
		const uint8_t aper[] = {0x00, 0xff, 0x02};
		CHECK_2_256(dec, aper);
	}

	{
		const uint8_t dec[256] = {0x01, 0x02};
		const uint8_t aper[257] = {0xfe, 0x01, 0x02};
		CHECK_2_256(dec, aper);
	}
}

#define CHECK_2_257(dec_val, enc_val) \
	CHECK(2, 257, 8, 8, dec_val, sizeof(dec_val), enc_val, sizeof(enc_val))
static void
check_2_257() {

	{
		const uint8_t dec[] = {0xff, 0x02};
		const uint8_t aper[] = {0x00, 0xff, 0x02};
		CHECK_2_257(dec, aper);
	}

	{
		const uint8_t dec[] = {0xff, 0x02, 0x3};
		const uint8_t aper[] = {0x01, 0xff, 0x02, 0x03};
		CHECK_2_257(dec, aper);
	}

	{
		const uint8_t dec[257] = {0x01, 0x02, 0x03};
		const uint8_t aper[258] = {0xff, 0x01, 0x02, 0x03};
		CHECK_2_257(dec, aper);
	}
}


#define CHECK_2_258(dec_val, enc_val) \
	CHECK(2, 259, 9, 9, dec_val, sizeof(dec_val), enc_val, sizeof(enc_val))
static void
check_2_258() {

	{
		const uint8_t dec[] = {0xff, 0x02};
		const uint8_t aper[] = {0x00, 0x00, 0xff, 0x02};
		CHECK_2_258(dec, aper);
	}

	{
		const uint8_t dec[] = {0xff, 0x02, 0x3};
		const uint8_t aper[] = {0x00, 0x01, 0xff, 0x02, 0x03};
		CHECK_2_258(dec, aper);
	}

	{
		const uint8_t dec[257] = {0x01, 0x02, 0x03};
		const uint8_t aper[259] = {0x00, 0xff, 0x01, 0x02, 0x03};
		CHECK_2_258(dec, aper);
	}

	{
		const uint8_t dec[258] = {0x01, 0x02, 0x03};
		const uint8_t aper[260] = {0x01, 0x00, 0x01, 0x02, 0x03};
		CHECK_2_258(dec, aper);
	}

	{
		const uint8_t dec[259] = {0x01, 0x02, 0x03};
		const uint8_t aper[261] = {0x01, 0x01, 0x01, 0x02, 0x03};
		CHECK_2_258(dec, aper);
	}
}

int
main() {

	check_2_127();
	check_2_256();
	check_2_257();
	check_2_258();
	check_4_20000();
	return 0;
}
