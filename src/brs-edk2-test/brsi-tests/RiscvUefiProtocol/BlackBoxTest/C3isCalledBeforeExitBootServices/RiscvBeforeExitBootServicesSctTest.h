/** @file
  RISC-V UEFI Protocol chapter 3 pre-ExitBootServices Shell test.

  The protocol definition is kept local so this test does not require changes
  to a platform package or the firmware's public protocol headers.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef RISCV_BEFORE_EXIT_BOOT_SERVICES_SCT_TEST_H_
#define RISCV_BEFORE_EXIT_BOOT_SERVICES_SCT_TEST_H_

#include <Uefi.h>

//
// RISCV_UEFI_PROTOCOL-spec.pdf, sections 3.1, 3.3 and 3.3.1.
//
#define RISCV_EFI_BOOT_PROTOCOL_GUID \
  { 0xccd15fec, 0x6f73, 0x4eec, \
    { 0x83, 0x95, 0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf } }

typedef struct _RISCV_EFI_BOOT_PROTOCOL RISCV_EFI_BOOT_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_GET_BOOT_HARTID)(
  IN  RISCV_EFI_BOOT_PROTOCOL  *This,
  OUT UINTN                    *BootHartId
  );

struct _RISCV_EFI_BOOT_PROTOCOL {
  UINT64                 Revision;
  EFI_GET_BOOT_HARTID     GetBootHartId;
};

EFI_STATUS
EFIAPI
RiscvBeforeExitBootServicesSctTestEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

#endif // RISCV_BEFORE_EXIT_BOOT_SERVICES_SCT_TEST_H_
