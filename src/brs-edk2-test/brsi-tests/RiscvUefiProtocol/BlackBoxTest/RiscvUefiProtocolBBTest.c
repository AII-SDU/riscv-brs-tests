/** @file
  Register the original Shell tests as SCT black-box test entries.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "RiscvUefiProtocolBBTest.h"

#include <Library/UefiBootServicesTableLib.h>
#include "SctLib.h"

STATIC EFI_HANDLE            mImageHandle;
STATIC EFI_SYSTEM_TABLE      *mSystemTable;
STATIC EFI_BB_TEST_PROTOCOL  *mBBTestProtocolInterface;

typedef
EFI_STATUS
(EFIAPI *RISCV_UEFI_TEST_ENTRY)(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

/**
  Call an unchanged test entry and record its returned status in SCT.
**/
STATIC
EFI_STATUS
RunRegisteredTest (
  IN EFI_HANDLE             SupportHandle,
  IN RISCV_UEFI_TEST_ENTRY   EntryPoint,
  IN EFI_GUID               AssertionGuid,
  IN CHAR16                 *TestName
  )
{
  EFI_STATUS                          Status;
  EFI_STANDARD_TEST_LIBRARY_PROTOCOL  *StandardLib;

  Status = gBS->HandleProtocol (
                  SupportHandle,
                  &gEfiStandardTestLibraryGuid,
                  (VOID **)&StandardLib
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = EntryPoint (mImageHandle, mSystemTable);
  return StandardLib->RecordAssertion (
                        StandardLib,
                        (Status == EFI_SUCCESS) ? EFI_TEST_ASSERTION_PASSED : EFI_TEST_ASSERTION_FAILED,
                        AssertionGuid,
                        TestName,
                        L"%a:%d: Status = %r",
                        __FILE__,
                        __LINE__,
                        Status
                        );
}

STATIC
EFI_STATUS
BBTestRiscvBootProtocolSctTest (
  IN EFI_BB_TEST_PROTOCOL  *This,
  IN VOID                 *ClientInterface,
  IN EFI_TEST_LEVEL       TestLevel,
  IN EFI_HANDLE           SupportHandle
  )
{
  EFI_GUID  AssertionGuid = RISCV_BOOT_IMPL_ASSERT_GUID;

  return RunRegisteredTest (
           SupportHandle,
           RiscvBootProtocolSctTestEntry,
           AssertionGuid,
           L"RiscvBootProtocolSctTest"
           );
}

STATIC
EFI_STATUS
BBTestRiscvBeforeExitBootServicesSctTest (
  IN EFI_BB_TEST_PROTOCOL  *This,
  IN VOID                 *ClientInterface,
  IN EFI_TEST_LEVEL       TestLevel,
  IN EFI_HANDLE           SupportHandle
  )
{
  EFI_GUID  AssertionGuid = RISCV_PRE_EXIT_ASSERT_GUID;

  return RunRegisteredTest (
           SupportHandle,
           RiscvBeforeExitBootServicesSctTestEntry,
           AssertionGuid,
           L"RiscvBeforeExitBootServicesSctTest"
           );
}

STATIC
EFI_STATUS
BBTestRiscvDtAcpiSctTest (
  IN EFI_BB_TEST_PROTOCOL  *This,
  IN VOID                 *ClientInterface,
  IN EFI_TEST_LEVEL       TestLevel,
  IN EFI_HANDLE           SupportHandle
  )
{
  EFI_GUID  AssertionGuid = RISCV_DT_ACPI_ASSERT_GUID;

  return RunRegisteredTest (
           SupportHandle,
           RiscvDtAcpiSctTestEntry,
           AssertionGuid,
           L"RiscvDtAcpiSctTest"
           );
}

STATIC
EFI_STATUS
BBTestRiscvGuidSctTest (
  IN EFI_BB_TEST_PROTOCOL  *This,
  IN VOID                 *ClientInterface,
  IN EFI_TEST_LEVEL       TestLevel,
  IN EFI_HANDLE           SupportHandle
  )
{
  EFI_GUID  AssertionGuid = RISCV_GUID_LOOKUP_ASSERT_GUID;

  return RunRegisteredTest (
           SupportHandle,
           RiscvGuidSctTestEntry,
           AssertionGuid,
           L"RiscvGuidSctTest"
           );
}

STATIC
EFI_STATUS
BBTestRiscvRevisionSctTest (
  IN EFI_BB_TEST_PROTOCOL  *This,
  IN VOID                 *ClientInterface,
  IN EFI_TEST_LEVEL       TestLevel,
  IN EFI_HANDLE           SupportHandle
  )
{
  EFI_GUID  AssertionGuid = RISCV_REVISION_ASSERT_GUID;

  return RunRegisteredTest (
           SupportHandle,
           RiscvRevisionSctTestEntry,
           AssertionGuid,
           L"RiscvRevisionSctTest"
           );
}

STATIC EFI_BB_TEST_PROTOCOL_FIELD  mBBTestProtocolField = {
  0x00010000,
  RISCV_UEFI_PROTOCOL_TEST_GUID,
  L"RISC-V UEFI Protocol Tests",
  L"Standalone RISC-V UEFI protocol tests registered with SCT."
};

STATIC EFI_GUID  mSupportProtocolGuid[] = {
  EFI_STANDARD_TEST_LIBRARY_GUID,
  EFI_NULL_GUID
};

STATIC EFI_BB_TEST_ENTRY_FIELD  mBBTestEntryField[] = {
  {
    RISCV_UEFI_PROTOCOL_ENTRY_GUID1,
    L"RiscvBootProtocolSctTest",
    L"Check that the RISC-V boot protocol is installed and callable.",
    EFI_TEST_LEVEL_DEFAULT,
    mSupportProtocolGuid,
    EFI_TEST_CASE_AUTO,
    BBTestRiscvBootProtocolSctTest
  },
  {
    RISCV_UEFI_PROTOCOL_ENTRY_GUID2,
    L"RiscvBeforeExitBootServicesSctTest",
    L"Run the boot protocol checks before ExitBootServices().",
    EFI_TEST_LEVEL_DEFAULT,
    mSupportProtocolGuid,
    EFI_TEST_CASE_AUTO,
    BBTestRiscvBeforeExitBootServicesSctTest
  },
  {
    RISCV_UEFI_PROTOCOL_ENTRY_GUID3,
    L"RiscvDtAcpiSctTest",
    L"Check the boot protocol with the active DT or ACPI configuration.",
    EFI_TEST_LEVEL_DEFAULT,
    mSupportProtocolGuid,
    EFI_TEST_CASE_AUTO,
    BBTestRiscvDtAcpiSctTest
  },
  {
    RISCV_UEFI_PROTOCOL_ENTRY_GUID4,
    L"RiscvGuidSctTest",
    L"Check protocol lookup using the specified GUID.",
    EFI_TEST_LEVEL_DEFAULT,
    mSupportProtocolGuid,
    EFI_TEST_CASE_AUTO,
    BBTestRiscvGuidSctTest
  },
  {
    RISCV_UEFI_PROTOCOL_ENTRY_GUID5,
    L"RiscvRevisionSctTest",
    L"Check the revision of every installed boot protocol instance.",
    EFI_TEST_LEVEL_DEFAULT,
    mSupportProtocolGuid,
    EFI_TEST_CASE_AUTO,
    BBTestRiscvRevisionSctTest
  },
  { EFI_NULL_GUID, NULL, NULL, 0, NULL, 0, NULL }
};

EFI_STATUS
EFIAPI
UnloadBBTestRiscvUefiProtocol (
  IN EFI_HANDLE  ImageHandle
  )
{
  return EfiUninstallAndFreeBBTestInterface (
           ImageHandle,
           mBBTestProtocolInterface
           );
}

EFI_STATUS
EFIAPI
InitializeBBTestRiscvUefiProtocol (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EfiInitializeTestLib (ImageHandle, SystemTable); //初始化SCT的通用测试库
  SctInitializeLib (ImageHandle, SystemTable); //初始化SCT自己的库上下文

  mImageHandle = ImageHandle;
  mSystemTable = SystemTable;

  return EfiInitAndInstallBBTestInterface (
           &ImageHandle,
           &mBBTestProtocolField,
           mBBTestEntryField,
           UnloadBBTestRiscvUefiProtocol,
           &mBBTestProtocolInterface
           );
}
