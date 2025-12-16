#include "net/tls_asn1.h"
#include <stddef.h>

void asn1_reader_init(asn1_reader_t *reader, const uint8_t *data, size_t length)
{
    reader->data = data;
    reader->length = length;
    reader->offset = 0;
}

bool asn1_read_element(asn1_reader_t *reader, uint8_t *tag, const uint8_t **value, size_t *length)
{
    if (!reader || reader->offset >= reader->length)
    {
        return false;
    }

    uint8_t t = reader->data[reader->offset++];
    if (reader->offset >= reader->length)
    {
        return false;
    }

    uint8_t len_byte = reader->data[reader->offset++];
    size_t len = 0;
    if ((len_byte & 0x80U) == 0)
    {
        len = len_byte;
    }
    else
    {
        uint8_t count = len_byte & 0x7FU;
        if (count == 0 || count > 4)
        {
            return false;
        }
        if (reader->offset + count > reader->length)
        {
            return false;
        }
        for (uint8_t i = 0; i < count; ++i)
        {
            len = (len << 8) | reader->data[reader->offset++];
        }
    }

    if (reader->offset + len > reader->length)
    {
        return false;
    }

    if (tag)
    {
        *tag = t;
    }
    if (value)
    {
        *value = reader->data + reader->offset;
    }
    if (length)
    {
        *length = len;
    }

    reader->offset += len;
    return true;
}

bool asn1_enter(asn1_reader_t *reader, uint8_t expected_tag, asn1_reader_t *child)
{
    const uint8_t *value = NULL;
    size_t length = 0;
    uint8_t tag = 0;
    if (!asn1_read_element(reader, &tag, &value, &length))
    {
        return false;
    }
    if (tag != expected_tag)
    {
        return false;
    }
    asn1_reader_init(child, value, length);
    return true;
}
