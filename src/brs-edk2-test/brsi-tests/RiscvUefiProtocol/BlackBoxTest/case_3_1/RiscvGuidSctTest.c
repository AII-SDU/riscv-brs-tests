/** @file
  RISC-V UEFI Protocol specification 3.1 (GUID) Shell test.

  The test follows the SCT black-box pattern of locating the protocol by its
  specification GUID and validating that the returned protocol interface is
  usable.  It is packaged as a UEFI application so it can be run directly
  from UEFI Shell.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "RiscvGuidSctTest.h"

#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

STATIC EFI_GUID  mRiscvEfiBootProtocolGuid = RISCV_EFI_BOOT_PROTOCOL_GUID;

/**
  Locate all instances registered with the section 3.1 GUID and verify that
  each matching handle returns a non-NULL protocol interface.

  @retval EFI_SUCCESS           At least one valid instance was found.
  @retval EFI_NOT_FOUND         The GUID is not installed by the firmware.
  @retval EFI_DEVICE_ERROR      A matching handle did not return an interface.
  @retval Others                Error from a UEFI Boot Service.
**/
STATIC
EFI_STATUS
CheckRiscvBootProtocolGuid (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_STATUS  HandleStatus;
  EFI_HANDLE  *HandleBuffer;
  UINTN       HandleCount;
  UINTN       Index;
  VOID        *Interface;
  BOOLEAN     Found;

  HandleBuffer = NULL;
  HandleCount  = 0;
  Found        = FALSE;

  // LocateProtocol validates that the exact GUID can resolve to an interface.
  Interface = NULL;
  Status = gBS->LocateProtocol (
                  &mRiscvEfiBootProtocolGuid, //确认规范中指定的GUID能找到协议实例
                  NULL,
                  &Interface //返回系统中第一个匹配到的Protocol实例
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Interface == NULL) { //确认返回的协议接口非空
    return EFI_DEVICE_ERROR;
  }

  // Enumerate every matching handle, as SCT protocol tests do.
  Status = gBS->LocateHandleBuffer ( //枚举支持某个Protocol的所有设备，即所有安装了该GUID的实例
                  ByProtocol,
                  &mRiscvEfiBootProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((HandleCount == 0) || (HandleBuffer == NULL)) { //数组与数量是否有效
    if (HandleBuffer != NULL) {
      FreePool (HandleBuffer);
    }

    return EFI_NOT_FOUND;
  }

  for (Index = 0; Index < HandleCount; ++Index) {
    Interface = NULL;
    HandleStatus = gBS->HandleProtocol ( //调用HandleProtocol，检查每个句柄上的协议接口
                            HandleBuffer[Index],
                            &mRiscvEfiBootProtocolGuid,
                            &Interface
                            );
    if (EFI_ERROR (HandleStatus) || (Interface == NULL)) {
      FreePool (HandleBuffer);
      return EFI_DEVICE_ERROR;
    }

    Found = TRUE;
  }

  FreePool (HandleBuffer); //释放句柄数组，并返回最终结果
  return Found ? EFI_SUCCESS : EFI_NOT_FOUND;
}

/**
  UEFI Shell entry point.

  @param[in] ImageHandle   The image handle of this application.
  @param[in] SystemTable   The UEFI system table.

  @retval EFI_SUCCESS      The section 3.1 GUID test passed.
  @retval Others           The test failed; the status is returned to Shell.
**/
EFI_STATUS
EFIAPI
RiscvGuidSctTestEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  (VOID)ImageHandle;
  (VOID)SystemTable;

  Print (L"RISC-V UEFI Protocol SCT-style test\n");
  Print (L"Test case: 3.1 GUID\n");
  Print (L"Expected:  ccd15fec-6f73-4eec-8395-3e69e4b940bf\n");

  Status = CheckRiscvBootProtocolGuid ();
  if (EFI_ERROR (Status)) {
    Print (L"[FAIL] GUID lookup or protocol interface validation failed: %r\n", Status);
    Print (L"       The firmware must install RISCV_EFI_BOOT_PROTOCOL with the\n");
    Print (L"       GUID specified in RISCV_UEFI_PROTOCOL-spec.pdf section 3.1.\n");
    return Status;
  }

  Print (L"[PASS] Protocol found and returned a non-NULL interface for the\n");
  Print (L"       section 3.1 GUID.\n");
  return EFI_SUCCESS;
}
