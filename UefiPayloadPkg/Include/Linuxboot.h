/** @file
  LinuxBoot PEI module include file.

  Copyright (c) 2014 - 2015, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#ifndef _LINUXBOOT_PEI_H_INCLUDED_
#define _LINUXBOOT_PEI_H_INCLUDED_

#if defined(_MSC_VER)
#pragma warning(disable : 4200)
#endif

/* Payload struct in U-root
type UefiPayloadConfig struct {
        PciExBase           uint64
        AcpiBase            uint64
        AcpiSize            uint64
        MemoryMapAddress    uint64
        NumMemoryMapEntries uint32
}
*/
typedef struct UefiPayloadConfigStruct {
  UINT64 PciExBase;
  UINT64 AcpiBase;
  UINT64 AcpiSize;
  UINT64 MemoryMapAddress;
  UINT32 NumMemoryMapEntries;
} UefiPayloadConfig;

typedef struct MemoryMapEntryStruct {
  UINT64 Start;
  UINT64 End;
  UINT32 Type;
} MemoryMapEntry;

#define LINUXBOOT_MEM_RAM 0
#define LINUXBOOT_MEM_DEFAULT 1
#define LINUXBOOT_MEM_ACPI 2
#define LINUXBOOT_MEM_NVS 3
#define LINUXBOOT_MEM_RESERVED 4

#endif  // _LINUXBOOT_PEI_H_INCLUDED_
