#ifndef __TPM2_RC_DECODE_H__
#define __TPM2_RC_DECODE_H__

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>
#include <log.h>
//
// TPM2 Command mapping structure
//
typedef struct {
    uint32_t CommandCode;
    const char *CommandName;
} Tpm2CommandName;

/**
  Convert a TPM 2.0 response code into a human-readable string.

  @param[in]  ResponseCode   32-bit TPM response code.
  @return     Pointer to a static wide string with the decoded name.
**/

//const char* Tpm2GetResponseString(uint32_t rc);
const char *
EFIAPI
Tpm2ResponseCodeToString (
  IN UINT32 ResponseCode
  );

/**
  Convert a TPM 2.0 command code into a human-readable string.
**/
const char *
EFIAPI
Tpm2CommandCodeToString (
  IN UINT32 CommandCode
  );

VOID
EFIAPI
Tpm2DecodeCommand (
  IN UINT32 InputParameterBlockSize,
  IN UINT8  *InputParameterBlock
  );

#endif // __TPM2_RC_DECODE_H__

