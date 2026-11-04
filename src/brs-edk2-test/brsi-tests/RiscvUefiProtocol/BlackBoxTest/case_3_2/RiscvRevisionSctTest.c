/** @file
  RISC-V UEFI Protocol specification 3.2 (Revision Number) Shell test.

  The test follows the SCT black-box pattern of locating the protocol by its
  specification GUID and validating the Revision member of every instance.
  It is packaged as a UEFI application so it can be run directly from UEFI
  Shell.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "RiscvRevisionSctTest.h"

#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

STATIC EFI_GUID  mRiscvEfiBootProtocolGuid = RISCV_EFI_BOOT_PROTOCOL_GUID;

/**
  Locate all instances registered with the section 3.1 GUID and verify that
  each matching handle returns the section 3.2 Revision value.

  @retval EFI_SUCCESS           Every discovered instance has the expected revision.
  @retval EFI_NOT_FOUND         The protocol is not installed by the firmware.
  @retval EFI_DEVICE_ERROR      An interface or revision check failed.
  @retval Others                Error from a UEFI Boot Service.
**/
STATIC
EFI_STATUS
CheckRiscvBootProtocolRevision (
  VOID
  )
{
  EFI_STATUS               Status;
  EFI_HANDLE               *HandleBuffer;
  UINTN                    HandleCount;
  UINTN                    Index;
  VOID                     *Interface;
  RISCV_EFI_BOOT_PROTOCOL  *Protocol;
  UINT64                   ExpectedRevision;

  HandleBuffer     = NULL;
  HandleCount      = 0;
  ExpectedRevision = (UINT64)RISCV_EFI_BOOT_PROTOCOL_LATEST_VERSION;

  // LocateProtocol validates that the exact GUID can resolve to an interface.
  Interface = NULL;
  Status = gBS->LocateProtocol (//找到第一个RISCV_EFI_BOOT_PROTOCOL实例
                  &mRiscvEfiBootProtocolGuid,
                  NULL,//只查找协议是否存在，这里写NULL即可
                  &Interface
                  );
  if (EFI_ERROR (Status)) {
    return Status;//不能存在这个协议的话，测试用例直接未通过
  }

  if (Interface == NULL) {
    return EFI_DEVICE_ERROR;
  }

  // Enumerate every matching handle, as SCT protocol tests do.
  Status = gBS->LocateHandleBuffer (//找到所有装了RISCV_EFI_BOOT_PROTOCOL的Handle
                  ByProtocol,
                  &mRiscvEfiBootProtocolGuid,
                  NULL,
                  &HandleCount,//输出匹配Handle数量
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((HandleCount == 0) || (HandleBuffer == NULL)) {
    if (HandleBuffer != NULL) {
      FreePool (HandleBuffer);
    }

    return EFI_NOT_FOUND;
  }

  for (Index = 0; Index < HandleCount; ++Index) {
    Interface = NULL;
    Status = gBS->HandleProtocol (//HandleProtocol用于打开HandleBuffer，每次检查前重新清空接口指针
                    HandleBuffer[Index],
                    &mRiscvEfiBootProtocolGuid,
                    &Interface
                    );
    if (EFI_ERROR (Status) || (Interface == NULL)) {
      FreePool (HandleBuffer);
      return EFI_DEVICE_ERROR;
    }

    Protocol = (RISCV_EFI_BOOT_PROTOCOL *)Interface;
    if (Protocol->Revision != ExpectedRevision) {//检查Revision是否为0x00010000
      Print (
        L"[FAIL] Handle[%u] Revision mismatch: actual=0x%016lx expected=0x%016lx\n",//如果不是，则返回FAIL
        Index,
        Protocol->Revision,
        ExpectedRevision
        );
      FreePool (HandleBuffer);
      return EFI_DEVICE_ERROR;
    }
  }

  FreePool (HandleBuffer);
  return EFI_SUCCESS;
}

/**
  UEFI Shell entry point.

  @param[in] ImageHandle   The image handle of this application.
  @param[in] SystemTable   The UEFI system table.

  @retval EFI_SUCCESS      The section 3.2 Revision test passed.
  @retval Others           The test failed; the status is returned to Shell.
**/
EFI_STATUS
EFIAPI
RiscvRevisionSctTestEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  (VOID)ImageHandle;
  (VOID)SystemTable;

  Print (L"RISC-V UEFI Protocol SCT-style test\n");
  Print (L"Test case: 3.2 Revision Number\n");
  Print (L"Expected Revision: 0x0000000000010000\n");

  Status = CheckRiscvBootProtocolRevision ();
  if (EFI_ERROR (Status)) {
    Print (L"[FAIL] Protocol lookup, interface, or Revision validation failed: %r\n", Status);
    Print (L"       The firmware must install RISCV_EFI_BOOT_PROTOCOL with the\n");
    Print (L"       revision specified in RISCV_UEFI_PROTOCOL-spec.pdf section 3.2.\n");
    return Status;
  }

  Print (L"[PASS] Protocol found and every instance has the expected Revision.\n");
  return EFI_SUCCESS;
}
