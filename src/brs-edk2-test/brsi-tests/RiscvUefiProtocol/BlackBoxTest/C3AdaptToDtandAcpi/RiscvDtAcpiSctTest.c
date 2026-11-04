/** @file
  RISC-V UEFI Protocol DT and ACPI applicability Shell test.

  The test identifies the active firmware configuration table type and checks
  that RISCV_EFI_BOOT_PROTOCOL provides the boot hart ID in that environment.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "RiscvDtAcpiSctTest.h"

#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

STATIC EFI_GUID  mRiscvEfiBootProtocolGuid = RISCV_EFI_BOOT_PROTOCOL_GUID;

// UEFI ACPI 2.0, ACPI 1.0, and Device Tree configuration table GUIDs.
STATIC EFI_GUID  mAcpi20TableGuid = { //包含了ACPI 2.0以及之后的版本
  0x8868e871, 0xe4f1, 0x11d3,
  { 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 }
};

STATIC EFI_GUID  mAcpi10TableGuid = {
  0xeb9d2d30, 0x2d88, 0x11d3,
  { 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};

STATIC EFI_GUID  mDeviceTreeTableGuid = {
  0xb1b621d5, 0xf19c, 0x41a5,
  { 0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0 }
};

/** Identify DT and ACPI configuration tables published by the firmware. */
STATIC
EFI_STATUS
GetConfigurationTableTypes ( 
  IN  EFI_SYSTEM_TABLE  *SystemTable,
  OUT BOOLEAN           *HasDeviceTree, //是否有设备树
  OUT BOOLEAN           *HasAcpi //是否有ACPI
  )
{
  UINTN  Index;

  if ((SystemTable == NULL) || (HasDeviceTree == NULL) || (HasAcpi == NULL)) {
    return EFI_INVALID_PARAMETER; //参数为空，则调用无效
  }

  *HasDeviceTree = FALSE;//初始化输出结果
  *HasAcpi       = FALSE;
  if ((SystemTable->NumberOfTableEntries != 0) &&
      (SystemTable->ConfigurationTable == NULL)) //检查系统表是否声称存在该配置表项
  {
    return EFI_COMPROMISED_DATA;   //表示检测到了数据不一致的情况
  }

  for (Index = 0; Index < SystemTable->NumberOfTableEntries; ++Index) { //遍历配置表数组
    EFI_CONFIGURATION_TABLE  *Table;

    Table = &SystemTable->ConfigurationTable[Index]; //取得当前表项的地址
    if (Table->VendorTable == NULL) {
      continue;
    }

    if (CompareGuid (&Table->VendorGuid, &mDeviceTreeTableGuid)) {
      *HasDeviceTree = TRUE; //如果识别到了设备树表项，那么HasDeviceTree = TRUE
    } else if (CompareGuid (&Table->VendorGuid, &mAcpi20TableGuid) ||
               CompareGuid (&Table->VendorGuid, &mAcpi10TableGuid))
    {
      *HasAcpi = TRUE; //如果识别到了ACPI表项，则HasAcpi = TRUE
    }
  }

  return ((*HasDeviceTree || *HasAcpi) ? EFI_SUCCESS : EFI_NOT_FOUND);
}

/** Call GetBootHartId successfully on every instance of the protocol. */
STATIC
EFI_STATUS
CheckBootHartIdProtocol (
  VOID
  )
{
  EFI_STATUS               Status;
  EFI_HANDLE               *HandleBuffer;
  UINTN                    HandleCount;
  UINTN                    Index;
  VOID                     *Interface;
  RISCV_EFI_BOOT_PROTOCOL  *Protocol;
  UINTN                    BootHartId;

  HandleBuffer = NULL; //初始化句柄数组状态
  HandleCount  = 0;

  Interface = NULL;
  Status = gBS->LocateProtocol (
                  &mRiscvEfiBootProtocolGuid,
                  NULL,
                  &Interface //返回系统中第一个匹配到的Protocol实例
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Interface == NULL) {
    return EFI_DEVICE_ERROR;
  }

  Status = gBS->LocateHandleBuffer ( //枚举支持这个协议的所有设备
                  ByProtocol,
                  &mRiscvEfiBootProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((HandleCount == 0) || (HandleBuffer == NULL)) { //处理没有找到句柄的情况
    if (HandleBuffer != NULL) {
      FreePool (HandleBuffer);
    }

    return EFI_NOT_FOUND;
  }

  for (Index = 0; Index < HandleCount; ++Index) { //遍历句柄
    Interface = NULL;
    Status = gBS->HandleProtocol ( //从当前句柄取协议接口
                    HandleBuffer[Index],
                    &mRiscvEfiBootProtocolGuid,
                    &Interface
                    );
    if (EFI_ERROR (Status) || (Interface == NULL)) {
      Print (L"[FAIL] Handle[%u] protocol lookup failed: %r\n", Index, Status);
      FreePool (HandleBuffer);
      return EFI_DEVICE_ERROR;
    }

    Protocol = (RISCV_EFI_BOOT_PROTOCOL *)Interface; //转换接口并检查函数指针
    if (Protocol->GetBootHartId == NULL) {
      Print (L"[FAIL] Handle[%u] has a NULL GetBootHartId function.\n", Index);
      FreePool (HandleBuffer);
      return EFI_DEVICE_ERROR;
    }

    BootHartId = 0;
    Status = Protocol->GetBootHartId (Protocol, &BootHartId); //调用GetBootHartId并检查状态
    if (Status != EFI_SUCCESS) { //看看是不是SUCCESS
      Print (L"[FAIL] Handle[%u] GetBootHartId returned %r.\n", Index, Status);
      FreePool (HandleBuffer);
      return EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR;
    }

    Print (
      L"[PASS] Handle[%u] returned boot hart ID 0x%lx.\n",
      Index,
      (UINT64)BootHartId
      );
  }

  FreePool (HandleBuffer); //释放数组
  return EFI_SUCCESS;
}

/** UEFI Shell entry point. */
EFI_STATUS
EFIAPI
RiscvDtAcpiSctTestEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  BOOLEAN     HasDeviceTree;
  BOOLEAN     HasAcpi;

  (VOID)ImageHandle;

  Print (L"RISC-V UEFI Protocol SCT-style test\n");
  Print (L"Test case: DT and ACPI applicability\n");

  Status = GetConfigurationTableTypes (SystemTable, &HasDeviceTree, &HasAcpi); //先确认有无设备树或ACPI
  if (EFI_ERROR (Status)) {
    Print (
      L"[FAIL] No valid Device Tree or ACPI configuration table was found: %r\n",
      Status
      );
    return Status;
  }

  Print (L"Configuration tables: %s%s\n",
         HasDeviceTree ? L"DT" : L"",
         (HasDeviceTree && HasAcpi) ? L" and ACPI" : (HasAcpi ? L"ACPI" : L""));

  Status = CheckBootHartIdProtocol (); //再测函数能否正常运行
  if (EFI_ERROR (Status)) {
    Print (
      L"[FAIL] RISCV_EFI_BOOT_PROTOCOL was not usable with the active configuration: %r\n",
      Status
      );
    Print (L"       Check protocol installation and GetBootHartId implementation.\n");
    return Status;
  }

  Print (
    L"[PASS] RISCV_EFI_BOOT_PROTOCOL returned a boot hart ID with the active configuration.\n"
    );
  return EFI_SUCCESS;
}
