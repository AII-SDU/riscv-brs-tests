/** @file
  RISC-V UEFI Protocol specification chapter 3 implementation Shell test.

  This test intentionally carries the GUID and protocol structure from the
  specification locally so that it can be built without changing a platform
  package or adding a protocol header to the firmware tree.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef RISCV_BOOT_PROTOCOL_SCT_TEST_H_
#define RISCV_BOOT_PROTOCOL_SCT_TEST_H_

#include <Uefi.h>

//
// RISCV_UEFI_PROTOCOL-spec.pdf, section 3.1.
//
#define RISCV_EFI_BOOT_PROTOCOL_GUID \
  { 0xccd15fec, 0x6f73, 0x4eec, \
    { 0x83, 0x95, 0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf } }

//
// RISCV_UEFI_PROTOCOL-spec.pdf, sections 3.3 and 3.3.1.
//
typedef struct _RISCV_EFI_BOOT_PROTOCOL RISCV_EFI_BOOT_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_GET_BOOT_HARTID)(
  IN RISCV_EFI_BOOT_PROTOCOL  *This,
  OUT UINTN                  *BootHartId
  );

struct _RISCV_EFI_BOOT_PROTOCOL {
  UINT64                 Revision;
  EFI_GET_BOOT_HARTID     GetBootHartId;
};

EFI_STATUS
EFIAPI
RiscvBootProtocolSctTestEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

#endif // RISCV_BOOT_PROTOCOL_SCT_TEST_H_
