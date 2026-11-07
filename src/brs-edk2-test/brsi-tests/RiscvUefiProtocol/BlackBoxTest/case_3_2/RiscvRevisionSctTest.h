/** @file
  RISC-V UEFI Protocol specification 3.2 (Revision Number) Shell test.

  This test intentionally carries the GUID, revision, and protocol structure
  from the specification locally so that it can be built without changing a
  platform package or adding a protocol header to the firmware tree.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef RISCV_REVISION_SCT_TEST_H_
#define RISCV_REVISION_SCT_TEST_H_

#include <Uefi.h>

//
// RISCV_UEFI_PROTOCOL-spec.pdf, section 3.1.
//
#define RISCV_EFI_BOOT_PROTOCOL_GUID \
  { 0xccd15fec, 0x6f73, 0x4eec, \
    { 0x83, 0x95, 0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf } }

//
// RISCV_UEFI_PROTOCOL-spec.pdf, section 3.2.
//
#define RISCV_EFI_BOOT_PROTOCOL_REVISION  0x00010000 //SPEC规定的REVISION
#define RISCV_EFI_BOOT_PROTOCOL_LATEST_VERSION \
  RISCV_EFI_BOOT_PROTOCOL_REVISION //指向RISCV_EFI_BOOT_PROTOCOL_REVISION，像文件里规定的那样

//
// RISCV_UEFI_PROTOCOL-spec.pdf, section 3.3.
//
typedef struct _RISCV_EFI_BOOT_PROTOCOL RISCV_EFI_BOOT_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_GET_BOOT_HARTID)(
  IN RISCV_EFI_BOOT_PROTOCOL  *This,
  OUT UINTN                   *BootHartId
  );

struct _RISCV_EFI_BOOT_PROTOCOL {
  UINT64                 Revision;
  EFI_GET_BOOT_HARTID    GetBootHartId;
};

EFI_STATUS
EFIAPI
RiscvRevisionSctTestEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

#endif // RISCV_REVISION_SCT_TEST_H_
