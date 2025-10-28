#include "pci.h"
#include "io.h"

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static uint32_t pci_build_address(pci_device_t dev, uint8_t offset)
{
    return 0x80000000U
        | ((uint32_t)dev.bus << 16)
        | ((uint32_t)dev.device << 11)
        | ((uint32_t)dev.function << 8)
        | (offset & 0xFC);
}

uint32_t pci_config_read32(pci_device_t dev, uint8_t offset)
{
    uint32_t address = pci_build_address(dev, offset);
    outl(PCI_CONFIG_ADDRESS, address);
    return inl(PCI_CONFIG_DATA);
}

uint16_t pci_config_read16(pci_device_t dev, uint8_t offset)
{
    uint32_t value = pci_config_read32(dev, offset);
    uint8_t shift = (uint8_t)((offset & 0x02) * 8);
    return (uint16_t)((value >> shift) & 0xFFFF);
}

uint8_t pci_config_read8(pci_device_t dev, uint8_t offset)
{
    uint32_t value = pci_config_read32(dev, offset);
    uint8_t shift = (uint8_t)((offset & 0x03) * 8);
    return (uint8_t)((value >> shift) & 0xFF);
}

void pci_config_write32(pci_device_t dev, uint8_t offset, uint32_t value)
{
    uint32_t address = pci_build_address(dev, offset);
    outl(PCI_CONFIG_ADDRESS, address);
    outl(PCI_CONFIG_DATA, value);
}

void pci_config_write16(pci_device_t dev, uint8_t offset, uint16_t value)
{
    uint32_t full = pci_config_read32(dev, offset);
    uint8_t shift = (uint8_t)((offset & 0x02) * 8);
    full &= ~(0xFFFFU << shift);
    full |= ((uint32_t)value << shift);
    pci_config_write32(dev, offset, full);
}

void pci_config_write8(pci_device_t dev, uint8_t offset, uint8_t value)
{
    uint32_t full = pci_config_read32(dev, offset);
    uint8_t shift = (uint8_t)((offset & 0x03) * 8);
    full &= ~(0xFFU << shift);
    full |= ((uint32_t)value << shift);
    pci_config_write32(dev, offset, full);
}

bool pci_find_device(uint16_t vendor, uint16_t device_id, pci_device_t *out_dev)
{
    for (uint16_t bus = 0; bus < 256; ++bus)
    {
        for (uint8_t device = 0; device < 32; ++device)
        {
            for (uint8_t function = 0; function < 8; ++function)
            {
                pci_device_t candidate = { .bus = (uint8_t)bus, .device = device, .function = function };
                uint16_t current_vendor = pci_config_read16(candidate, 0x00);
                if (current_vendor == 0xFFFF)
                {
                    if (function == 0)
                    {
                        break;
                    }
                    continue;
                }
                uint16_t current_device = pci_config_read16(candidate, 0x02);
                if (current_vendor == vendor && current_device == device_id)
                {
                    if (out_dev)
                    {
                        *out_dev = candidate;
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

void pci_set_command_bits(pci_device_t dev, uint16_t set_bits, uint16_t clear_bits)
{
    uint16_t value = pci_config_read16(dev, 0x04);
    value |= set_bits;
    value &= (uint16_t)~clear_bits;
    pci_config_write16(dev, 0x04, value);
}
