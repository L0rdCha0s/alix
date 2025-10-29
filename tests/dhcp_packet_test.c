#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DHCP_OPTION_MESSAGE     53
#define DHCP_OPTION_PARAM_LIST  55
#define DHCP_OPTION_END         255

#define DHCP_MSG_DISCOVER 1

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xFF);
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)((value >> 16) & 0xFF);
    p[2] = (uint8_t)((value >> 8) & 0xFF);
    p[3] = (uint8_t)(value & 0xFF);
}

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t ip_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
    {
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    }
    if (len & 1)
    {
        sum += (uint32_t)(data[len - 1] << 8);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t udp_checksum(const uint8_t *src_ip, const uint8_t *dst_ip,
                             const uint8_t *udp, size_t udp_len)
{
    uint32_t sum = 0;

    for (int i = 0; i < 4; i += 2)
    {
        sum += (uint32_t)((src_ip[i] << 8) | src_ip[i + 1]);
    }
    for (int i = 0; i < 4; i += 2)
    {
        sum += (uint32_t)((dst_ip[i] << 8) | dst_ip[i + 1]);
    }

    sum += 17; /* protocol */
    sum += (uint32_t)udp_len;

    for (size_t i = 0; i + 1 < udp_len; i += 2)
    {
        sum += (uint32_t)((udp[i] << 8) | udp[i + 1]);
    }
    if (udp_len & 1)
    {
        sum += (uint32_t)(udp[udp_len - 1] << 8);
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static size_t build_dhcp_discover(uint8_t *buffer, size_t capacity,
                                  const uint8_t mac[6], uint32_t xid)
{
    if (capacity < 548)
    {
        return 0;
    }

    memset(buffer, 0, capacity);

    uint8_t *eth = buffer;
    uint8_t *ip = buffer + 14;
    uint8_t *udp = ip + 20;
    uint8_t *dhcp = udp + 8;

    memset(eth, 0xFF, 6);
    memcpy(eth + 6, mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x00;

    memset(ip, 0, 20);
    ip[0] = 0x45;
    ip[1] = 0x00;
    ip[8] = 64;
    ip[9] = 17;
    write_be32(ip + 12, 0);
    write_be32(ip + 16, 0xFFFFFFFFU);

    memset(dhcp, 0, 236);
    dhcp[0] = 1;
    dhcp[1] = 1;
    dhcp[2] = 6;
    write_be32(dhcp + 4, xid);
    write_be16(dhcp + 10, 0x8000);
    memcpy(dhcp + 28, mac, 6);
    write_be32(dhcp + 236, 0x63825363U);

    uint8_t *opt = dhcp + 240;
    *opt++ = DHCP_OPTION_MESSAGE;
    *opt++ = 1;
    *opt++ = DHCP_MSG_DISCOVER;
    *opt++ = DHCP_OPTION_PARAM_LIST;
    *opt++ = 3;
    *opt++ = 1;
    *opt++ = 3;
    *opt++ = 6;
    *opt++ = DHCP_OPTION_END;

    size_t dhcp_len = (size_t)(opt - dhcp);
    if (dhcp_len < 240)
    {
        dhcp_len = 240;
    }

    uint16_t udp_len = (uint16_t)(8 + dhcp_len);
    uint16_t ip_len = (uint16_t)(20 + udp_len);

    write_be16(ip + 2, ip_len);
    write_be16(udp + 4, udp_len);
    write_be16(udp, 68);
    write_be16(udp + 2, 67);

    write_be16(ip + 10, 0);
    uint16_t ip_sum = ip_checksum(ip, 20);
    write_be16(ip + 10, ip_sum);

    write_be16(udp + 6, 0);
    uint16_t udp_sum = udp_checksum(ip + 12, ip + 16, udp, udp_len);
    if (udp_sum == 0)
    {
        udp_sum = 0xFFFF;
    }
    write_be16(udp + 6, udp_sum);

    size_t frame_len = 14 + ip_len;
    if (frame_len < 60)
    {
        memset(buffer + frame_len, 0, 60 - frame_len);
        frame_len = 60;
    }

    return frame_len;
}

static void assert_option_sequence(const uint8_t *options, size_t len)
{
    const uint8_t expected[] = { DHCP_OPTION_MESSAGE, 1, DHCP_MSG_DISCOVER,
                                  DHCP_OPTION_PARAM_LIST, 3, 1, 3, 6,
                                  DHCP_OPTION_END };
    for (size_t i = 0; i < sizeof(expected); ++i)
    {
        assert(options[i] == expected[i]);
    }
    (void)len;
}

int main(void)
{
    uint8_t frame[548];
    const uint8_t mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
    uint32_t xid = 0x12345678U + 0x01020304U; /* matches first discover */

    size_t frame_len = build_dhcp_discover(frame, sizeof(frame), mac, xid);
    assert(frame_len >= 60);

    /* Ethernet */
    for (int i = 0; i < 6; ++i)
    {
        assert(frame[i] == 0xFF);
    }
    assert(memcmp(frame + 6, mac, 6) == 0);
    assert(read_be16(frame + 12) == 0x0800);

    const uint8_t *ip = frame + 14;
    assert((ip[0] >> 4) == 4);
    assert((ip[0] & 0x0F) == 5);
    uint16_t ip_len = read_be16(ip + 2);
    assert(ip_len == frame_len - 14);
    assert(ip[8] == 64);
    assert(ip[9] == 17);
    assert(read_be32(ip + 12) == 0);
    assert(read_be32(ip + 16) == 0xFFFFFFFFU);

    uint16_t stored_ip_sum = read_be16(ip + 10);
    uint8_t ip_tmp[20];
    memcpy(ip_tmp, ip, sizeof(ip_tmp));
    ip_tmp[10] = ip_tmp[11] = 0;
    assert(stored_ip_sum == ip_checksum(ip_tmp, 20));

    const uint8_t *udp = ip + 20;
    assert(read_be16(udp) == 68);
    assert(read_be16(udp + 2) == 67);
    uint16_t udp_len = read_be16(udp + 4);
    assert(udp_len == ip_len - 20);
    uint16_t stored_udp_sum = read_be16(udp + 6);
    uint8_t udp_tmp[1024];
    assert(udp_len <= sizeof(udp_tmp));
    memcpy(udp_tmp, udp, udp_len);
    udp_tmp[6] = udp_tmp[7] = 0;
    uint16_t computed_udp_sum = udp_checksum(ip + 12, ip + 16, udp_tmp, udp_len);
    if (computed_udp_sum == 0)
    {
        computed_udp_sum = 0xFFFF;
    }
    assert(stored_udp_sum == computed_udp_sum);

    const uint8_t *dhcp = udp + 8;
    assert(dhcp[0] == 1);
    assert(dhcp[1] == 1);
    assert(dhcp[2] == 6);
    assert(read_be32(dhcp + 4) == xid);
    assert(read_be16(dhcp + 10) == 0x8000);
    assert(memcmp(dhcp + 28, mac, 6) == 0);
    assert(read_be32(dhcp + 236) == 0x63825363U);

    assert_option_sequence(dhcp + 240, 9);

    printf("DHCP discover frame layout OK\n");
    printf("  frame_len=%zu bytes\n", frame_len);
    printf("  ip_len=%u bytes\n", (unsigned)ip_len);
    printf("  udp_len=%u bytes\n", (unsigned)udp_len);
    printf("  dhcp_payload_len=%u bytes\n", (unsigned)(udp_len - 8));
    printf("  ip_checksum=0x%04X\n", stored_ip_sum);
    printf("  udp_checksum=0x%04X\n", stored_udp_sum);
    return 0;
}
