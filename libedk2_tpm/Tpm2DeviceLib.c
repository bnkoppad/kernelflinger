/** @file
  Implement TPM2 SubmitCommand.

Copyright (c) 2013 - 2016, Intel Corporation. All rights reserved. <BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <efi.h>
#include <efiapi.h>
#include "Tpm2Help.h"
#include "Tcg2Protocol.h"
#include "Tpm2DeviceLib.h"
#include "Tpm2RcDecode.h"
#include <log.h>
#include "efidebug.h"
#include "tpm2_security.h"

#define TPM_RETRY_DELAY_MS   100     // 100ms between retries
#define TPM_MAX_RETRIES      1
/*EFI_STATUS
EFIAPI
Tpm2SubmitCommand_cmd (
*/ 
EFI_STATUS
EFIAPI
Tpm2SubmitCommand (
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN OUT UINT32        *OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
  )
{
  EFI_STATUS                Status = 0;
  EFI_STATUS                status = 0;
  TPM2_COMMAND_HEADER       *Command = NULL;
  TPM2_RESPONSE_HEADER      *Header = NULL;

  EFI_GUID gEfiTcg2ProtocolGuid = EFI_TCG2_PROTOCOL_GUID;
  EFI_TCG2_PROTOCOL *mTcg2Protocol;
  UINTN      Attempt;
  uint32_t responseCode = 0;

  debug(L"[BNK_TEST] Tpm2SubmitCommand - ENTRY");

  Status = LibLocateProtocol (&gEfiTcg2ProtocolGuid, (void **) &mTcg2Protocol);
    if (EFI_ERROR (Status) || mTcg2Protocol == NULL ) {
      //
      // Tcg2 protocol is not installed. So, TPM2 is not present.
      //
      debug(L"[BNK] Tpm2SubmitCommand - EFI_NOT_FOUND %x", Status);
      return EFI_NOT_FOUND;
    }
  //
  // Assume when Tcg2 Protocol is ready, RequestUseTpm already done.
  //

  // Decode and print the outgoing TPM command
  Tpm2DecodeCommand(InputParameterBlockSize, InputParameterBlock);

  for (Attempt = 0; Attempt < TPM_MAX_RETRIES; Attempt++) {
  Status = mTcg2Protocol->SubmitCommand (
                            mTcg2Protocol,
                            InputParameterBlockSize,
                            InputParameterBlock,
                            *OutputParameterBlockSize,
                            OutputParameterBlock
                            );

  Command = (TPM2_COMMAND_HEADER *)InputParameterBlock;
  Header = (TPM2_RESPONSE_HEADER *)OutputParameterBlock;
  *OutputParameterBlockSize = SwapBytes32 (Header->paramSize);
/* -------------------------PRINT response code - START---------------------------------- */
  {
    uint32_t cmdCode = SwapBytes32(Command->commandCode);
    const char *cmdName = Tpm2CommandCodeToString(cmdCode);
    debug(L"[BNK] TPM Command name and code  %s (%x)", cmdName, cmdCode);

    if (SwapBytes32(Header->responseCode) != TPM_RC_SUCCESS) {
      responseCode = SwapBytes32(Header->responseCode);
      const char *respStr = Tpm2ResponseCodeToString(responseCode);
      debug(L"[BNK] Tpm2SubmitCommand -cmdCode:%x, respCode:%x (%s)", cmdCode, responseCode, respStr);
    }
  }

  if (responseCode == 0x000) {
      debug(L"[BNK_TEST] Tpm2SubmitCommand - Success - EXIT");
      // Success
      return EFI_SUCCESS;
  } else {
      debug(L"[BNK] SubmitCommand EFI error (attempt %u/%u): %r", (UINT32)(Attempt + 1), TPM_MAX_RETRIES, Status);
      //gBS->Stall (TPM_RETRY_DELAY_MS * 1000);   // convert to microseconds
      //debug(L"[BNK] wait delay 100 ms - responseCode - %x", responseCode);
      continue;
    }
  }
/* -------------------------PRINT response code - END------------------------------------ */

  if (EFI_ERROR (Status)) {
    debug(L"[BNK] Tpm2SubmitCommand - Status - %x", Status);
    return Status;
  }

  return EFI_SUCCESS;
}

/*EFI_STATUS
EFIAPI
Tpm2SubmitCommand (
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN OUT UINT32        *OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
  )
{
  EFI_STATUS                Status = 0;
  EFI_STATUS                LockStatus = 0;

  //debug(L"[BNK] Tpm2SubmitCommand - ENTRY");
//  LockStatus = tpm2_get_cap_lockcounter();

 // debug(L"[BNK] 1. tpm2_get_cap_lockcounte - LockStatus - %x", LockStatus);
  Status = Tpm2SubmitCommand_cmd (InputParameterBlockSize,
  			          InputParameterBlock,
  			          OutputParameterBlockSize,
  			          OutputParameterBlock);

  debug(L"[BNK] Tpm2SubmitCommand - Status - %x", Status);

  LockStatus = tpm2_get_cap_lockcounter();
  debug(L"[BNK] 2. tpm2_get_cap_lockcounte - LockStatus - %x", LockStatus);

  return Status;
}
*/

#ifdef ENABLE_TPM_VERBOSE_OLD
EFI_STATUS
EFIAPI
Tpm2SubmitCommandVerbose (
    IN      UINT32  InputParameterBlockSize,
    IN      UINT8  *InputParameterBlock,
    IN OUT  UINT32 *OutputParameterBlockSize,
    IN OUT  UINT8  *OutputParameterBlock
) {
    EFI_STATUS Status = 0;
    uint32_t cmdCode = 0;
    uint32_t responseCode = 0;
//UUUUUUUU
    // Extract TPM command code from offset 0x0A (10)
    if (InputParameterBlockSize >= 14) {
        memcpy(&cmdCode, InputParameterBlock + 10, sizeof(uint32_t));
        cmdCode = __builtin_bswap32(cmdCode);  // TPM command header is big-endian
    }

    const char *cmdName = Tpm2GetCommandName(cmdCode);

    debug(L"[BNK] Tpm2SubmitCommandVerbose");
    debug(L"[TPM CMD] Tpm2SubmitCommandVerbose %s (0x%08X)\n", cmdName, cmdCode);

/*    Status = Tpm2SubmitCommand(
        InputParameterBlockSize,
        InputParameterBlock,
        OutputParameterBlockSize,
        OutputParameterBlock
    );
*/
   if (*OutputParameterBlockSize >= 10) {
        memcpy(&responseCode, OutputParameterBlock + 6, sizeof(uint32_t));
        responseCode = __builtin_bswap32(responseCode);  // TPM is big-endian
        debug(L"[BNK] TPM2 Response Code: 0x%08X (%s)\n",
               responseCode, Tpm2GetResponseToString(responseCode));
    } else {
        debug(L"[BNK] Invalid TPM response size: %u bytes\n", *OutputParameterBlockSize);
    }

    if (EFI_ERROR(Status)) {
        debug(L"EFI error during TPM command submission: 0x%X\n", Status);
        return Status;
    }

 
    return Status;
}
#endif  //#ifdef ENABLE_TPM_VERBOSE_OLD
