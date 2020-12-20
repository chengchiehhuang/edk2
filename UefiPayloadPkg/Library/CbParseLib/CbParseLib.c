/** @file
  This library will parse the coreboot table in memory and extract those
required information.

  Copyright (c) 2014 - 2016, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Coreboot.h>
#include <IndustryStandard/Acpi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BlParseLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>
#include <Uefi/UefiBaseType.h>
#include <IndustryStandard/SmBios.h>

/**
  Convert a packed value from cbuint64 to a UINT64 value.

  @param  val      The pointer to packed data.

  @return          the UNIT64 value after conversion.

**/
UINT64
cb_unpack64(IN struct cbuint64 val) { return LShiftU64(val.hi, 32) | val.lo; }

/**
  Returns the sum of all elements in a buffer of 16-bit values.  During
  calculation, the carry bits are also been added.

  @param  Buffer      The pointer to the buffer to carry out the sum operation.
  @param  Length      The size, in bytes, of Buffer.

  @return Sum         The sum of Buffer with carry bits included during
additions.

**/
UINT16
CbCheckSum16(IN UINT16 *Buffer, IN UINTN Length) {
  UINT32 Sum;
  UINT32 TmpValue;
  UINTN Idx;
  UINT8 *TmpPtr;

  Sum = 0;
  TmpPtr = (UINT8 *)Buffer;
  for (Idx = 0; Idx < Length; Idx++) {
    TmpValue = TmpPtr[Idx];
    if (Idx % 2 == 1) {
      TmpValue <<= 8;
    }

    Sum += TmpValue;

    // Wrap
    if (Sum >= 0x10000) {
      Sum = (Sum + (Sum >> 16)) & 0xFFFF;
    }
  }

  return (UINT16)((~Sum) & 0xFFFF);
}

/**
  Check the coreboot table if it is valid.

  @param  Header            Pointer to coreboot table

  @retval TRUE              The coreboot table is valid.
  @retval Others            The coreboot table is not valid.

**/
BOOLEAN
IsValidCbTable(IN struct cb_header *Header) {
  UINT16 CheckSum;

  if ((Header == NULL) || (Header->table_bytes == 0)) {
    return FALSE;
  }

  if (Header->signature != CB_HEADER_SIGNATURE) {
    return FALSE;
  }

  //
  // Check the checksum of the coreboot table header
  //
  CheckSum = CbCheckSum16((UINT16 *)Header, sizeof(*Header));
  if (CheckSum != 0) {
    DEBUG((DEBUG_ERROR, "Invalid coreboot table header checksum\n"));
    return FALSE;
  }

  CheckSum = CbCheckSum16((UINT16 *)((UINT8 *)Header + sizeof(*Header)),
                          Header->table_bytes);
  if (CheckSum != Header->table_checksum) {
    DEBUG((DEBUG_ERROR,
           "Incorrect checksum of all the coreboot table entries\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  This function retrieves the parameter base address from boot loader.

  This function will get bootloader specific parameter address for UEFI payload.
  e.g. HobList pointer for Slim Bootloader, and coreboot table header for
Coreboot.

  @retval NULL            Failed to find the GUID HOB.
  @retval others          GUIDed HOB data pointer.

**/
VOID *EFIAPI GetParameterBase(VOID) {
  struct cb_header *Header;
  struct cb_record *Record;
  UINT8 *TmpPtr;
  UINT8 *CbTablePtr;
  UINTN Idx;

  //
  // coreboot could pass coreboot table to UEFI payload
  //
  Header = (struct cb_header *)(UINTN)GET_BOOTLOADER_PARAMETER();
  if (IsValidCbTable(Header)) {
    return Header;
  }

  //
  // Find simplified coreboot table in memory range 0 ~ 4KB.
  // Some GCC version does not allow directly access to NULL pointer,
  // so start the search from 0x10 instead.
  //
  for (Idx = 16; Idx < 4096; Idx += 16) {
    Header = (struct cb_header *)Idx;
    if (Header->signature == CB_HEADER_SIGNATURE) {
      break;
    }
  }

  if (Idx >= 4096) {
    return NULL;
  }

  //
  // Check the coreboot header
  //
  if (!IsValidCbTable(Header)) {
    return NULL;
  }

  //
  // Find full coreboot table in high memory
  //
  CbTablePtr = NULL;
  TmpPtr = (UINT8 *)Header + Header->header_bytes;
  for (Idx = 0; Idx < Header->table_entries; Idx++) {
    Record = (struct cb_record *)TmpPtr;
    if (Record->tag == CB_TAG_FORWARD) {
      CbTablePtr = (VOID *)(UINTN)((struct cb_forward *)(UINTN)Record)->forward;
      break;
    }
    TmpPtr += Record->size;
  }

  //
  // Check the coreboot header in high memory
  //
  if (!IsValidCbTable((struct cb_header *)CbTablePtr)) {
    return NULL;
  }

  SET_BOOTLOADER_PARAMETER((UINT32)(UINTN)CbTablePtr);

  return CbTablePtr;
}

/**
  Find coreboot record with given Tag.

  @param  Tag                The tag id to be found

  @retval NULL              The Tag is not found.
  @retval Others            The pointer to the record found.

**/
VOID *FindCbTag(IN UINT32 Tag) {
  struct cb_header *Header;
  struct cb_record *Record;
  UINT8 *TmpPtr;
  UINT8 *TagPtr;
  UINTN Idx;

  return NULL;

  Header = (struct cb_header *)GetParameterBase();

  TagPtr = NULL;
  TmpPtr = (UINT8 *)Header + Header->header_bytes;
  for (Idx = 0; Idx < Header->table_entries; Idx++) {
    Record = (struct cb_record *)TmpPtr;
    if (Record->tag == Tag) {
      TagPtr = TmpPtr;
      break;
    }
    TmpPtr += Record->size;
  }

  return TagPtr;
}

/**
  Find the given table with TableId from the given coreboot memory Root.

  @param  Root               The coreboot memory table to be searched in
  @param  TableId            Table id to be found
  @param  MemTable           To save the base address of the memory table found
  @param  MemTableSize       To save the size of memory table found

  @retval RETURN_SUCCESS            Successfully find out the memory table.
  @retval RETURN_INVALID_PARAMETER  Invalid input parameters.
  @retval RETURN_NOT_FOUND          Failed to find the memory table.

**/
RETURN_STATUS
FindCbMemTable(IN struct cbmem_root *Root, IN UINT32 TableId,
               OUT VOID **MemTable, OUT UINT32 *MemTableSize) {
  UINTN Idx;
  BOOLEAN IsImdEntry;
  struct cbmem_entry *Entries;

  if ((Root == NULL) || (MemTable == NULL)) {
    return RETURN_INVALID_PARAMETER;
  }
  //
  // Check if the entry is CBMEM or IMD
  // and handle them separately
  //
  Entries = Root->entries;
  if (Entries[0].magic == CBMEM_ENTRY_MAGIC) {
    IsImdEntry = FALSE;
  } else {
    Entries = (struct cbmem_entry *)((struct imd_root *)Root)->entries;
    if (Entries[0].magic == IMD_ENTRY_MAGIC) {
      IsImdEntry = TRUE;
    } else {
      return RETURN_NOT_FOUND;
    }
  }

  for (Idx = 0; Idx < Root->num_entries; Idx++) {
    if (Entries[Idx].id == TableId) {
      if (IsImdEntry) {
        *MemTable = (VOID *)((UINTN)Entries[Idx].start + (UINTN)Root);
      } else {
        *MemTable = (VOID *)(UINTN)Entries[Idx].start;
      }
      if (MemTableSize != NULL) {
        *MemTableSize = Entries[Idx].size;
      }

      DEBUG((DEBUG_INFO, "Find CbMemTable Id 0x%x, base %p, size 0x%x\n",
             TableId, *MemTable, Entries[Idx].size));
      return RETURN_SUCCESS;
    }
  }

  return RETURN_NOT_FOUND;
}

/**
  Acquire the coreboot memory table with the given table id

  @param  TableId            Table id to be searched
  @param  MemTable           Pointer to the base address of the memory table
  @param  MemTableSize       Pointer to the size of the memory table

  @retval RETURN_SUCCESS     Successfully find out the memory table.
  @retval RETURN_INVALID_PARAMETER  Invalid input parameters.
  @retval RETURN_NOT_FOUND   Failed to find the memory table.

**/
RETURN_STATUS
ParseCbMemTable(IN UINT32 TableId, OUT VOID **MemTable,
                OUT UINT32 *MemTableSize) {
  EFI_STATUS Status;
  struct cb_memory *rec;
  struct cb_memory_range *Range;
  UINT64 Start;
  UINT64 Size;
  UINTN Index;
  struct cbmem_root *CbMemRoot;

  if (MemTable == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  *MemTable = NULL;
  Status = RETURN_NOT_FOUND;

  //
  // Get the coreboot memory table
  //
  rec = (struct cb_memory *)FindCbTag(CB_TAG_MEMORY);
  if (rec == NULL) {
    return Status;
  }

  for (Index = 0; Index < MEM_RANGE_COUNT(rec); Index++) {
    Range = MEM_RANGE_PTR(rec, Index);
    Start = cb_unpack64(Range->start);
    Size = cb_unpack64(Range->size);

    if ((Range->type == CB_MEM_TABLE) && (Start > 0x1000)) {
      CbMemRoot =
          (struct cbmem_root *)(UINTN)(Start + Size - DYN_CBMEM_ALIGN_SIZE);
      Status = FindCbMemTable(CbMemRoot, TableId, MemTable, MemTableSize);
      if (!EFI_ERROR(Status)) {
        break;
      }
    }
  }

  return Status;
}

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
  /*
  struct cb_memory         *rec;
  struct cb_memory_range   *Range;
  UINTN                    Index;
  MEMROY_MAP_ENTRY         MemoryMap;

  //
  // Get the coreboot memory table
  //
  rec = (struct cb_memory *)FindCbTag (CB_TAG_MEMORY);
  if (rec == NULL) {
    return RETURN_NOT_FOUND;
  }

  for (Index = 0; Index < MEM_RANGE_COUNT(rec); Index++) {
    Range = MEM_RANGE_PTR(rec, Index);
    MemoryMap.Base = cb_unpack64(Range->start);
    MemoryMap.Size = cb_unpack64(Range->size);
    MemoryMap.Type = (UINT8)Range->type;
    MemoryMap.Flag = 0;
    DEBUG ((DEBUG_INFO, "%d. %016lx - %016lx [%02x]\n",
            Index, MemoryMap.Base, MemoryMap.Base + MemoryMap.Size - 1,
  MemoryMap.Type));

    MemInfoCallback (&MemoryMap, Params);
  }
*/

  /*
  w/ Ovmf
  [mem 0x0000000000000000-0x000000000009ffff] usable
  [mem 0x0000000000100000-0x00000000007fffff] usable
  [mem 0x0000000000800000-0x0000000000807fff] ACPI NVS
  [mem 0x0000000000808000-0x000000000080ffff] usable
  [mem 0x0000000000810000-0x00000000008fffff] ACPI NVS
  [mem 0x0000000000900000-0x000000007f8eefff] usable
  [mem 0x000000007f8ef000-0x000000007fb6efff] reserved
  [mem 0x000000007fb6f000-0x000000007fb7efff] ACPI data
  [mem 0x000000007fb7f000-0x000000007fbfefff] ACPI NVS
  [mem 0x000000007fbff000-0x000000007fef3fff] usable
  [mem 0x000000007fef4000-0x000000007ff77fff] reserved
  [mem 0x000000007ff78000-0x000000007fffffff] ACPI NVS
  [mem 0x00000000b0000000-0x00000000bfffffff] reserved 
  */
  AddMemoryRange(MemInfoCallback, 0x0000000000000000, 0x000000000009ffff,
                 CB_MEM_RAM);
  AddMemoryRange(MemInfoCallback, 0x0000000000100000, 0x00000000007fffff,
                 CB_MEM_RAM);
  AddMemoryRange(MemInfoCallback, 0x0000000000100000, 0x00000000007fffff,
                 CB_MEM_RAM);
  AddMemoryRange(MemInfoCallback, 0x0000000000900000, 0x000000007f8eefff,
                 CB_MEM_RAM);
  /*
  w/ ubuntu
  [mem 0x0000000000000000-0x000000000009fbff] usable
  [mem 0x000000000009fc00-0x000000000009ffff] reserved
  [mem 0x00000000000f0000-0x00000000000fffff] reserved
  [mem 0x0000000000100000-0x000000007ffd9fff] usable
  [mem 0x000000007ffda000-0x000000007fffffff] reserved
  [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
  w/o ubuntu
  [mem 0x0000000000000000-0x000000000009fbff] usable
  [mem 0x000000000009fc00-0x000000000009ffff] reserved
  [mem 0x00000000000f0000-0x00000000000fffff] reserved
  [mem 0x0000000000100000-0x000000007ffdcfff] usable
  [mem 0x000000007ffdd000-0x000000007fffffff] reserved
  [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
   * */
  // AddMemoryRange(MemInfoCallback, 0x0000000000000000, 0x000000000009efff,
  //                CB_MEM_RAM);
  // AddMemoryRange(MemInfoCallback, 0x000000000009f000, 0x000000000009ffff,
  //                CB_MEM_RESERVED);
  // AddMemoryRange(MemInfoCallback, 0x00000000000f0000, 0x00000000000fffff,
  //                CB_MEM_RESERVED);
  // AddMemoryRange(MemInfoCallback, 0x0000000000100000, 0x000000007ffdcfff,
  //                CB_MEM_RAM);
  // AddMemoryRange(MemInfoCallback, 0x000000007ffdd000, 0x000000007fffffff,
  //                CB_MEM_RESERVED);
  // AddMemoryRange(MemInfoCallback, 0x0000000000100000, 0x000000007ffd9fff,
  //               CB_MEM_RAM);
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
  EFI_STATUS Status;
  VOID *MemTable;
  UINT32 MemTableSize;
  UINT32 SMBIOSHdrSize;
  UINTN RsdpPtr;

  RsdpPtr = FindRsdpPtrInLowMem();

  SystemTableInfo->AcpiTableBase = RsdpPtr;
  SystemTableInfo->AcpiTableSize = 14;
  
  SystemTableInfo->SmbiosTableBase = FindSMBIOSPtrInLowMem(&SMBIOSHdrSize);
  SystemTableInfo->SmbiosTableSize = SMBIOSHdrSize;

  return RETURN_SUCCESS;

  Status = ParseCbMemTable(SIGNATURE_32('T', 'B', 'M', 'S'), &MemTable,
                           &MemTableSize);
  if (EFI_ERROR(Status)) {
    return EFI_NOT_FOUND;
  }
  SystemTableInfo->SmbiosTableBase = (UINT64)(UINTN)MemTable;
  SystemTableInfo->SmbiosTableSize = MemTableSize;

  Status = ParseCbMemTable(SIGNATURE_32('I', 'P', 'C', 'A'), &MemTable,
                           &MemTableSize);
  if (EFI_ERROR(Status)) {
    return EFI_NOT_FOUND;
  }
  SystemTableInfo->AcpiTableBase = (UINT64)(UINTN)MemTable;
  SystemTableInfo->AcpiTableSize = MemTableSize;

  return Status;
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
  // struct cb_serial          *CbSerial;

  // CbSerial = FindCbTag (CB_TAG_SERIAL);
  // if (CbSerial == NULL) {
  //   return RETURN_NOT_FOUND;
  // }

  // SerialPortInfo->BaseAddr    = CbSerial->baseaddr;
  // SerialPortInfo->RegWidth    = CbSerial->regwidth;
  // SerialPortInfo->Type        = CbSerial->type;
  // SerialPortInfo->Baud        = CbSerial->baud;
  // SerialPortInfo->InputHertz  = CbSerial->input_hertz;
  // SerialPortInfo->UartPciAddr = CbSerial->uart_pci_addr;
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
  struct cb_framebuffer *CbFbRec;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *GfxMode;

  if (GfxInfo == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  CbFbRec = FindCbTag(CB_TAG_FRAMEBUFFER);
  if (CbFbRec == NULL) {
    return RETURN_NOT_FOUND;
  }

  DEBUG((DEBUG_INFO, "Found coreboot video frame buffer information\n"));
  DEBUG((DEBUG_INFO, "physical_address: 0x%lx\n", CbFbRec->physical_address));
  DEBUG((DEBUG_INFO, "x_resolution: 0x%x\n", CbFbRec->x_resolution));
  DEBUG((DEBUG_INFO, "y_resolution: 0x%x\n", CbFbRec->y_resolution));
  DEBUG((DEBUG_INFO, "bits_per_pixel: 0x%x\n", CbFbRec->bits_per_pixel));
  DEBUG((DEBUG_INFO, "bytes_per_line: 0x%x\n", CbFbRec->bytes_per_line));

  DEBUG((DEBUG_INFO, "red_mask_size: 0x%x\n", CbFbRec->red_mask_size));
  DEBUG((DEBUG_INFO, "red_mask_pos: 0x%x\n", CbFbRec->red_mask_pos));
  DEBUG((DEBUG_INFO, "green_mask_size: 0x%x\n", CbFbRec->green_mask_size));
  DEBUG((DEBUG_INFO, "green_mask_pos: 0x%x\n", CbFbRec->green_mask_pos));
  DEBUG((DEBUG_INFO, "blue_mask_size: 0x%x\n", CbFbRec->blue_mask_size));
  DEBUG((DEBUG_INFO, "blue_mask_pos: 0x%x\n", CbFbRec->blue_mask_pos));
  DEBUG(
      (DEBUG_INFO, "reserved_mask_size: 0x%x\n", CbFbRec->reserved_mask_size));
  DEBUG((DEBUG_INFO, "reserved_mask_pos: 0x%x\n", CbFbRec->reserved_mask_pos));

  GfxMode = &GfxInfo->GraphicsMode;
  GfxMode->Version = 0;
  GfxMode->HorizontalResolution = CbFbRec->x_resolution;
  GfxMode->VerticalResolution = CbFbRec->y_resolution;
  GfxMode->PixelsPerScanLine =
      (CbFbRec->bytes_per_line << 3) / CbFbRec->bits_per_pixel;
  if ((CbFbRec->red_mask_pos == 0) && (CbFbRec->green_mask_pos == 8) &&
      (CbFbRec->blue_mask_pos == 16)) {
    GfxMode->PixelFormat = PixelRedGreenBlueReserved8BitPerColor;
  } else if ((CbFbRec->blue_mask_pos == 0) && (CbFbRec->green_mask_pos == 8) &&
             (CbFbRec->red_mask_pos == 16)) {
    GfxMode->PixelFormat = PixelBlueGreenRedReserved8BitPerColor;
  }
  GfxMode->PixelInformation.RedMask = ((1 << CbFbRec->red_mask_size) - 1)
                                      << CbFbRec->red_mask_pos;
  GfxMode->PixelInformation.GreenMask = ((1 << CbFbRec->green_mask_size) - 1)
                                        << CbFbRec->green_mask_pos;
  GfxMode->PixelInformation.BlueMask = ((1 << CbFbRec->blue_mask_size) - 1)
                                       << CbFbRec->blue_mask_pos;
  GfxMode->PixelInformation.ReservedMask =
      ((1 << CbFbRec->reserved_mask_size) - 1) << CbFbRec->reserved_mask_pos;

  GfxInfo->FrameBufferBase = CbFbRec->physical_address;
  GfxInfo->FrameBufferSize = CbFbRec->bytes_per_line * CbFbRec->y_resolution;

  return RETURN_SUCCESS;
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
