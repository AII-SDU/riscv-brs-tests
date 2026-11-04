/** @file
  RISC-V UEFI Protocol specification chapter 3 implementation Shell test.

  The test follows the SCT black-box pattern of locating the protocol by its
  specification GUID and exercising its interface with valid parameters.
  It is packaged as a UEFI application so it can be run directly from
  UEFI Shell on either EDK II or U-Boot firmware.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "RiscvBootProtocolSctTest.h"

#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

STATIC EFI_GUID  mRiscvEfiBootProtocolGuid = RISCV_EFI_BOOT_PROTOCOL_GUID;

/**
  Verify that one installed instance implements a callable GetBootHartId.

  Two different initial output values detect an implementation that returns
  success without writing the output.  No particular hart ID is assumed.

  @param[in] Protocol    The non-NULL interface returned by HandleProtocol.
  @param[in] Index       The instance index, used for diagnostic output.

  @retval EFI_SUCCESS       Both calls succeeded and returned the same hart ID.
  @retval EFI_DEVICE_ERROR  The interface or its output failed validation.
  @retval Others            Error returned by GetBootHartId.
**/
STATIC
EFI_STATUS
CheckRiscvBootProtocolInterface (
  IN RISCV_EFI_BOOT_PROTOCOL  *Protocol,
  IN UINTN                   Index
  )
{
  EFI_STATUS  Status;
  UINTN       BootHartId1; //第一次调用返回的hart ID
  UINTN       BootHartId2; //第二次调用返回的hart ID

  if (Protocol->GetBootHartId == NULL) { //确认协议提供了GetBootHartId入口
    Print (L"       Instance %u: GetBootHartId is NULL.\n", Index);
    return EFI_DEVICE_ERROR;
  }

  // 使用不同初值，避免把未写入输出参数的空实现判为通过。
  BootHartId1 = 0;
  BootHartId2 = ~(UINTN)0;

  Status = Protocol->GetBootHartId (Protocol, &BootHartId1);//第一次调用：传入协议自身和输出变量的地址
  if (Status != EFI_SUCCESS) {
    Print (L"       Instance %u: first GetBootHartId call failed: %r\n", Index, Status);
    return EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR;
  }

  Status = Protocol->GetBootHartId (Protocol, &BootHartId2);//第二次调用：对同一个协议实例再次获取结果
  if (Status != EFI_SUCCESS) {
    Print (L"       Instance %u: second GetBootHartId call failed: %r\n", Index, Status);
    return EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR;
  }

  if (BootHartId1 != BootHartId2) { //比较两个结果，检查返回值是否一致，一致则通过，不一致则失败
    Print (
      L"       Instance %u: inconsistent or unwritten boot hart ID: %Lu, %Lu\n",
      Index,
      (UINT64)BootHartId1,
      (UINT64)BootHartId2
      );
    return EFI_DEVICE_ERROR;
  }

  Print (L"[INFO] Instance %u: boot hart ID = %Lu\n", Index, (UINT64)BootHartId1);
  return EFI_SUCCESS;
}

/**
  Locate the mandatory protocol and verify every installed instance.

  @retval EFI_SUCCESS       At least one instance was found; all checks passed.
  @retval EFI_NOT_FOUND     The mandatory protocol is not installed.
  @retval EFI_DEVICE_ERROR  An installed interface failed validation.
  @retval Others            Error from Boot Services or GetBootHartId.
**/
STATIC
EFI_STATUS
CheckRiscvBootProtocolImplementation (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  *HandleBuffer;
  UINTN       HandleCount;
  UINTN       Index;
  VOID        *Interface;

  HandleBuffer = NULL;
  HandleCount  = 0;
  Interface    = NULL;

  // 按规范 GUID 查找固件必须提供的协议。
  Status = gBS->LocateProtocol (
                  &mRiscvEfiBootProtocolGuid,
                  NULL,
                  &Interface
                  );
  if (EFI_ERROR (Status)) {
    Print (L"       LocateProtocol failed: %r\n", Status);
    return Status;
  }

  if (Interface == NULL) {
    Print (L"       LocateProtocol returned a NULL interface.\n");
    return EFI_DEVICE_ERROR;
  }

  // 与其他 SCT 风格用例一致，枚举并检查所有匹配句柄（安装了该协议的句柄）。
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &mRiscvEfiBootProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    Print (L"       LocateHandleBuffer failed: %r\n", Status);
    goto Done;
  }

  if ((HandleCount == 0) || (HandleBuffer == NULL)) {
    Print (L"       No protocol handles were returned.\n");
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  for (Index = 0; Index < HandleCount; ++Index) { //遍历句柄，逐个取出协议接口并进行测试
    Interface = NULL;
    Status = gBS->HandleProtocol (//逐个打开HandleBuffer
                    HandleBuffer[Index],
                    &mRiscvEfiBootProtocolGuid,
                    &Interface
                    );
    if (EFI_ERROR (Status)) {
      Print (L"       Instance %u: HandleProtocol failed: %r\n", Index, Status);
      goto Done;
    }//打开HandleBuffer失败，则测试失败

    if (Interface == NULL) {
      Print (L"       Instance %u: HandleProtocol returned a NULL interface.\n", Index);
      Status = EFI_DEVICE_ERROR;
      goto Done;
    }//检查空指针，返回的接口是NULL，则测试失败

    Status = CheckRiscvBootProtocolInterface ((RISCV_EFI_BOOT_PROTOCOL *)Interface, Index);//检测两次调用GetBootHartId是否一样，一样则测试通过，不一样则测试不通过
    if (EFI_ERROR (Status)) {
      goto Done;
    }
  }

  Status = EFI_SUCCESS;

Done:
  // 成功与失败路径均释放 Boot Services 分配的句柄数组。
  if (HandleBuffer != NULL) {
    FreePool (HandleBuffer);
  }

  return Status;
}

/**
  UEFI Shell entry point.

  @param[in] ImageHandle   The image handle of this application.
  @param[in] SystemTable   The UEFI system table.

  @retval EFI_SUCCESS     The chapter 3 implementation test passed.
  @retval Others          The test failed; the status is returned to Shell.
**/
EFI_STATUS
EFIAPI
RiscvBootProtocolSctTestEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  (VOID)ImageHandle;
  (VOID)SystemTable;

  Print (L"RISC-V UEFI Protocol SCT-style test\n");
  Print (L"Test case: Chapter 3 mandatory protocol implementation\n");
  Print (L"Expected:  RISCV_EFI_BOOT_PROTOCOL is installed and callable\n");
  Print (L"GUID:      ccd15fec-6f73-4eec-8395-3e69e4b940bf\n");

  Status = CheckRiscvBootProtocolImplementation ();
  if (EFI_ERROR (Status)) {
    Print (L"[FAIL] Mandatory protocol implementation check failed: %r\n", Status);
    Print (L"       RISC-V UEFI firmware must implement RISCV_EFI_BOOT_PROTOCOL\n");
    Print (L"       as required by RISCV_UEFI_PROTOCOL-spec.pdf chapter 3.\n");
    return Status;
  }

  Print (L"[PASS] Mandatory protocol found; every installed instance returned\n");
  Print (L"       a consistent boot hart ID with EFI_SUCCESS.\n");
  return EFI_SUCCESS;
}
