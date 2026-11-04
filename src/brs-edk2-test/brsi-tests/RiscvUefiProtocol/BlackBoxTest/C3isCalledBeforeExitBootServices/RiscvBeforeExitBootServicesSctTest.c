/** @file
  RISC-V UEFI Protocol chapter 3 pre-ExitBootServices Shell test.

  Exercise GetBootHartId while Boot Services are available and copy its result
  into loader-owned memory.  A simulated OS consumer reads only the copied
  data.  This Shell application does not call ExitBootServices and does not
  claim to verify an actual loader-to-OS transition.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "RiscvBeforeExitBootServicesSctTest.h"

#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h> // The Boot Services table used.
#include <Library/UefiLib.h>

STATIC EFI_GUID  mRiscvEfiBootProtocolGuid = RISCV_EFI_BOOT_PROTOCOL_GUID;

//
// Private test data, not a structure or OS handoff ABI defined by the spec.
// Keep a value rather than a pointer to the protocol or its output variable.
//
#define RISCV_TEST_HANDOFF_SIGNATURE  SIGNATURE_32 ('R', 'V', 'B', 'H')
#define RISCV_TEST_HANDOFF_VERSION    1

typedef struct {
  UINT32    Signature;
  UINT32    Version;
  UINTN     Size;
  UINTN     BootHartId;
} RISCV_TEST_BOOT_HANDOFF; // Test the custom data format used to simulate the data prepared by the bootloader and passed to the operating system for reading.

/**
  Simulate an OS-side reader that consumes only previously saved data.

  No Boot Service, protocol interface or UEFI console is used here.  This is
  a local handoff check; it does not execute after ExitBootServices.

  @param[in]  Handoff       Private handoff data created by the test loader.
  @param[out] BootHartId    Boot hart ID copied out of the handoff data.

  @retval EFI_SUCCESS           The private data format was valid.
  @retval EFI_INVALID_PARAMETER A required pointer was NULL.
  @retval EFI_COMPROMISED_DATA  The private data header was invalid.
**/
STATIC
EFI_STATUS
ReadBootHartIdFromHandoff (
  IN  CONST RISCV_TEST_BOOT_HANDOFF  *Handoff,
  OUT UINTN                          *BootHartId
  )
{
  if ((Handoff == NULL) || (BootHartId == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Handoff->Signature != RISCV_TEST_HANDOFF_SIGNATURE) ||
      (Handoff->Version != RISCV_TEST_HANDOFF_VERSION) ||
      (Handoff->Size != sizeof (*Handoff)))
  {
    return EFI_COMPROMISED_DATA;
  }

  *BootHartId = Handoff->BootHartId;
  return EFI_SUCCESS;
}

/**
  Model a loader retrieving the boot hart ID before ExitBootServices.

  Both protocol calls occur during ordinary Shell execution, before any
  ExitBootServices attempt.  Different initial output values detect a method
  that returns EFI_SUCCESS without writing its output.  No hart ID value,
  including zero, is assumed to be invalid.

  @retval EFI_SUCCESS       Pre-exit calls and simulated data handoff passed.
  @retval EFI_DEVICE_ERROR  An interface, status or returned value was invalid.
  @retval Others            Error from Boot Services or GetBootHartId.
**/
STATIC
EFI_STATUS
CheckRiscvBootProtocolBeforeExitBootServices (
  VOID
  )
{
  EFI_STATUS                Status;
  VOID                      *Interface;
  VOID                      *Buffer;
  RISCV_EFI_BOOT_PROTOCOL    *Protocol;
  RISCV_TEST_BOOT_HANDOFF    *Handoff;
  UINTN                     BootHartId1;
  UINTN                     BootHartId2;
  UINTN                     ReceivedBootHartId;

  Interface = NULL;
  Buffer    = NULL;

  // Shell is still in the Boot Services phase; locate the specification GUID.
  Status = gBS->LocateProtocol ( // Find the first BOOT_PROTOCOL instance. gBS is the BootServices table pointer; it is assumed that execution is already in the BS phase.
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

  Protocol = (RISCV_EFI_BOOT_PROTOCOL *)Interface;
  if (Protocol->GetBootHartId == NULL) {
    Print (L"       GetBootHartId is NULL.\n");
    return EFI_DEVICE_ERROR;
  }

  BootHartId1 = 0; // Defines two BootHartId values for consistency checking.
  BootHartId2 = ~(UINTN)0;

  Status = Protocol->GetBootHartId (Protocol, &BootHartId1);
  if (Status != EFI_SUCCESS) {
    Print (L"       First pre-exit GetBootHartId call failed: %r\n", Status);
    return EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR;
  }

  Status = Protocol->GetBootHartId (Protocol, &BootHartId2);
  if (Status != EFI_SUCCESS) {
    Print (L"       Second pre-exit GetBootHartId call failed: %r\n", Status);
    return EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR;
  }

  if (BootHartId1 != BootHartId2) { // If the two checks are inconsistent, it is treated as a failure.
    Print (
      L"       Inconsistent or unwritten boot hart ID: %Lu, %Lu\n",
      (UINT64)BootHartId1,
      (UINT64)BootHartId2
      );
    return EFI_DEVICE_ERROR;
  }

  Print (L"[INFO] Pre-exit GetBootHartId returned boot hart ID = %Lu\n", (UINT64)BootHartId1);

  // Use loader-owned memory for the saved value.  A real loader must arrange
  // for its OS to reserve/consume this memory; this test frees it on return.
  Status = gBS->AllocatePool ( // Allocate a block of memory large enough to hold the handoff structure, mark it as EfiLoaderData, and use it to simulate the data saved by the bootloader.
                  EfiLoaderData,
                  sizeof (RISCV_TEST_BOOT_HANDOFF),
                  &Buffer
                  );
  if (EFI_ERROR (Status)) {
    Print (L"       AllocatePool(EfiLoaderData) failed: %r\n", Status);
    return Status;
  }

  if (Buffer == NULL) {
    Print (L"       AllocatePool returned a NULL buffer.\n");
    return EFI_DEVICE_ERROR;
  }

  Handoff             = (RISCV_TEST_BOOT_HANDOFF *)Buffer; // Populate the struct.
  Handoff->Signature  = RISCV_TEST_HANDOFF_SIGNATURE;
  Handoff->Version    = RISCV_TEST_HANDOFF_VERSION;
  Handoff->Size       = sizeof (*Handoff);
  Handoff->BootHartId = BootHartId1; // Copy values obtained from the protocol into independent memory objects.

  // Simulate the OS reading only the saved data; do not treat the protocol pointer as the handover content.
  ReceivedBootHartId = ~BootHartId1;
  Status = ReadBootHartIdFromHandoff (Handoff, &ReceivedBootHartId);
  if (EFI_ERROR (Status)) {
    Print (L"       Simulated handoff reader failed: %r\n", Status);
    goto Done;
  }

  if (ReceivedBootHartId != BootHartId1) {//If the read data differs from the expected value, mark the test as failed.
    Print (
      L"       Handoff value mismatch: expected %Lu, received %Lu\n",
      (UINT64)BootHartId1,
      (UINT64)ReceivedBootHartId
      );
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  Print (L"[INFO] Simulated consumer read saved boot hart ID = %Lu\n", (UINT64)ReceivedBootHartId);
  Status = EFI_SUCCESS;

Done:
  // No actual OS is started; release the test allocation before returning.
  FreePool (Buffer);
  return Status;
}

/**
  UEFI Shell entry point.

  @param[in] ImageHandle   The image handle of this application.
  @param[in] SystemTable   The UEFI system table.

  @retval EFI_SUCCESS     Pre-exit retrieval and simulated handoff passed.
  @retval Others          The test failed; the status is returned to Shell.
**/
EFI_STATUS
EFIAPI
RiscvBeforeExitBootServicesSctTestEntry ( //This is a Shell application; the Shell runs in the UEFI Boot Services (BS) phase.
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  (VOID)ImageHandle;
  (VOID)SystemTable;

  Print (L"RISC-V UEFI Protocol SCT-style test\n");
  Print (L"Test case: Chapter 3 protocol call before ExitBootServices\n");
  Print (L"Expected:  GetBootHartId works before exit; saved data is readable\n");
  Print (L"GUID:      ccd15fec-6f73-4eec-8395-3e69e4b940bf\n");
  Print (L"[INFO] Shell-safe test: ExitBootServices is not invoked.\n");
  Print (L"[INFO] OS handoff is simulated; no real OS transition is tested.\n");

  Status = CheckRiscvBootProtocolBeforeExitBootServices ();
  if (EFI_ERROR (Status)) {
    Print (L"[FAIL] Pre-exit protocol call or simulated handoff failed: %r\n", Status);
    return Status;
  }

  Print (L"[PASS] Pre-exit protocol calls succeeded; saved boot hart ID\n");
  Print (L"       passed the simulated handoff check.\n");
  return EFI_SUCCESS;
}
