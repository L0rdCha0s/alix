#ifndef NET_TLS_ASN1_H
#define NET_TLS_ASN1_H

#include "types.h"

typedef struct
{
    const uint8_t *data;
    size_t length;
    size_t offset;
} asn1_reader_t;

void asn1_reader_init(asn1_reader_t *reader, const uint8_t *data, size_t length);
bool asn1_read_element(asn1_reader_t *reader, uint8_t *tag, const uint8_t **value, size_t *length);
bool asn1_enter(asn1_reader_t *reader, uint8_t expected_tag, asn1_reader_t *child);

#endif
