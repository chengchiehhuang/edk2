/** @file
  This library will parse the linuxboot table in memory and extract those
required information.

  Copyright (c) 2014 - 2016, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Coreboot.h>
#include <Linuxboot.h>
#include <IndustryStandard/Acpi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BlParseLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>
#include <Uefi/UefiBaseType.h>
#include <IndustryStandard/SmBios.h>

void AddMemoryRange(IN BL_MEM_INFO_CALLBACK MemInfoCallback, IN UINTN start,
                    IN UINTN end, IN int type) {
  MEMROY_MAP_ENTRY MemoryMap;
  MemoryMap.Base = start;
  MemoryMap.Size = end - start + 1;
  MemoryMap.Type = type;
  MemoryMap.Flag = 0;
  MemInfoCallback(&MemoryMap, NULL);
}

/**
  Acquire the memory information from the coreboot table in memory.

  @param  MemInfoCallback     The callback routine
  @param  Params              Pointer to the callback routine parameter

  @retval RETURN_SUCCESS     Successfully find out the memory information.
  @retval RETURN_NOT_FOUND   Failed to find the memory information.

**/
RETURN_STATUS
EFIAPI
ParseMemoryInfo(IN BL_MEM_INFO_CALLBACK MemInfoCallback, IN VOID *Params) {

  AddMemoryRange(MemInfoCallback, 0x0000000000000000, 0x000000000009ffff,
                 CB_MEM_RAM);
  AddMemoryRange(MemInfoCallback, 0x0000000000100000, 0x00000000007fffff,
                 CB_MEM_RAM);
  AddMemoryRange(MemInfoCallback, 0x0000000000100000, 0x00000000007fffff,
                 CB_MEM_RAM);
  AddMemoryRange(MemInfoCallback, 0x0000000000900000, 0x000000007f8eefff,
                 CB_MEM_RAM);
  AddMemoryRange(MemInfoCallback, 0x000000007ffda000, 0x000000007fffffff,
                 CB_MEM_RESERVED);

  AddMemoryRange(MemInfoCallback, 0x00000000fffc0000, 0x00000000ffffffff,
                 CB_MEM_RESERVED);
  return RETURN_SUCCESS;
}

 // Find _SM_ in memory in F0000
UINTN FindSMBIOSPtrInLowMem(UINT32* Size){
  UINTN base;
  for (base = 0xF0000; base < 0x100000; base++) {
    SMBIOS_TABLE_ENTRY_POINT* smbios = (SMBIOS_TABLE_ENTRY_POINT*)base;
    if (smbios->AnchorString[0] == 0x5f &&
        smbios->AnchorString[1] == 0x53 &&
        smbios->AnchorString[2] == 0x4d &&
        smbios->AnchorString[3] == 0x5f &&
        smbios->IntermediateAnchorString[0] == 0x5f &&
        smbios->IntermediateAnchorString[1] == 0x44 &&
        smbios->IntermediateAnchorString[2] == 0x4d &&
        smbios->IntermediateAnchorString[3] == 0x49 &&
        smbios->IntermediateAnchorString[4] == 0x5f) {
      *Size = 0x1f;
      DEBUG((DEBUG_INFO, "Found SMBIOS anchor ptr in: 0x%08x\n", base));
      return base;
    }
  }
  for (base = 0xF0000; base < 0x100000; base++) {
    SMBIOS_TABLE_3_0_ENTRY_POINT* smbios = (SMBIOS_TABLE_3_0_ENTRY_POINT*)base;
    if (smbios->AnchorString[0] == 0x5f &&
        smbios->AnchorString[1] == 0x53 &&
        smbios->AnchorString[2] == 0x4d &&
        smbios->AnchorString[3] == 0x33 &&
        smbios->AnchorString[4] == 0x5f) {
      *Size = 0x18;
      DEBUG((DEBUG_INFO, "Found SMBIOS3 anchor ptr in: 0x%08x\n", base));
      return base;
    }
  }
  DEBUG((DEBUG_INFO, "SMBIOS header is not found in F0000\n"));
  return 0xf5b40;
}

 // " RSD PTR" in hex, 8 bytes.
UINTN FindRsdpPtrInLowMem(){
  UINTN base;
  const UINT64 RsdpTag = 0x2052545020445352;
  for (base = 0xE0000; base < 0x100000; base++) {
    if (*(UINT64*)base == RsdpTag) {
      DEBUG((DEBUG_INFO, "Found RSDP ptr in: 0x%08x\n", base));
      return base;
    }
  }
  for (base = 0x80000; base < 0xA0000; base++) {
    if (*(UINT64*)base == RsdpTag) {
      DEBUG((DEBUG_INFO, "Found RSDP ptr in: 0x%08x\n", base));
      return base;
    }
  }
  DEBUG((DEBUG_INFO, "RSDP ptr not found in F0000\n"));
  return 0xf5b20;
}

/**
  Acquire acpi table and smbios table from coreboot

  @param  SystemTableInfo          Pointer to the system table info

  @retval RETURN_SUCCESS            Successfully find out the tables.
  @retval RETURN_NOT_FOUND          Failed to find the tables.

**/
RETURN_STATUS
EFIAPI
ParseSystemTable(OUT SYSTEM_TABLE_INFO *SystemTableInfo) {
  UINT32 SMBIOSHdrSize;
  UINTN RsdpPtr;

  RsdpPtr = FindRsdpPtrInLowMem();

  SystemTableInfo->AcpiTableBase = RsdpPtr;
  SystemTableInfo->AcpiTableSize = 14;

  SystemTableInfo->SmbiosTableBase = FindSMBIOSPtrInLowMem(&SMBIOSHdrSize);
  SystemTableInfo->SmbiosTableSize = SMBIOSHdrSize;

  return RETURN_SUCCESS;
}

/**
  Find the serial port information

  @param  SERIAL_PORT_INFO   Pointer to serial port info structure

  @retval RETURN_SUCCESS     Successfully find the serial port information.
  @retval RETURN_NOT_FOUND   Failed to find the serial port information .

**/
RETURN_STATUS
EFIAPI
ParseSerialInfo(OUT SERIAL_PORT_INFO *SerialPortInfo) {
  SerialPortInfo->BaseAddr = 0x3f8;
  SerialPortInfo->RegWidth = 8;
  SerialPortInfo->Type = PLD_SERIAL_TYPE_IO_MAPPED;
  SerialPortInfo->Baud = 115200;
  SerialPortInfo->InputHertz = 0;
  SerialPortInfo->UartPciAddr = 0;

  return RETURN_SUCCESS;
}

/**
  Find the video frame buffer information

  @param  GfxInfo             Pointer to the EFI_PEI_GRAPHICS_INFO_HOB structure

  @retval RETURN_SUCCESS     Successfully find the video frame buffer
information.
  @retval RETURN_NOT_FOUND   Failed to find the video frame buffer information .

**/
RETURN_STATUS
EFIAPI
ParseGfxInfo(OUT EFI_PEI_GRAPHICS_INFO_HOB *GfxInfo) {
  // Not supported
  return RETURN_NOT_FOUND;
}

/**
  Find the video frame buffer device information

  @param  GfxDeviceInfo      Pointer to the EFI_PEI_GRAPHICS_DEVICE_INFO_HOB
structure

  @retval RETURN_SUCCESS     Successfully find the video frame buffer
information.
  @retval RETURN_NOT_FOUND   Failed to find the video frame buffer information.

**/
RETURN_STATUS
EFIAPI
ParseGfxDeviceInfo(OUT EFI_PEI_GRAPHICS_DEVICE_INFO_HOB *GfxDeviceInfo) {
  return RETURN_NOT_FOUND;
}
