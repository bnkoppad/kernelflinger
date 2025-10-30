#include <efi.h>
#include <Tpm20.h>
#include "Tpm2RcDecode.h"
#include <efiapi.h>
#include "Tpm2Help.h"
#include "Tcg2Protocol.h"
#include "Tpm2DeviceLib.h"
#include "Tpm2RcDecode.h"
#include <log.h>


#pragma pack(1)

typedef struct {
  TPM2_COMMAND_HEADER  Header;
  TPM2B_AUTH           Auth;
  TPMI_ALG_HASH        HashAlg;
} TPM2_HASH_SEQUENCE_START_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER  Header;
  TPMI_DH_OBJECT        SequenceHandle;
} TPM2_HASH_SEQUENCE_START_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_DH_OBJECT            SequenceHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSessionSeq;
  TPM2B_MAX_BUFFER          Buffer;
} TPM2_SEQUENCE_UPDATE_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPMS_AUTH_RESPONSE         AuthSessionSeq;
} TPM2_SEQUENCE_UPDATE_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_DH_PCR               PcrHandle;
  TPMI_DH_OBJECT            SequenceHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSessionPcr;
  TPMS_AUTH_COMMAND         AuthSessionSeq;
  TPM2B_MAX_BUFFER          Buffer;
} TPM2_EVENT_SEQUENCE_COMPLETE_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPML_DIGEST_VALUES         Results;
  TPMS_AUTH_RESPONSE         AuthSessionPcr;
  TPMS_AUTH_RESPONSE         AuthSessionSeq;
} TPM2_EVENT_SEQUENCE_COMPLETE_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_DH_OBJECT            SequenceHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSessionSeq;
  TPM2B_MAX_BUFFER          Buffer;
  TPMI_RH_HIERARCHY         Hierarchy;
} TPM2_SEQUENCE_COMPLETE_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPM2B_DIGEST               Digest;
  TPMS_AUTH_RESPONSE         AuthSessionSeq;
} TPM2_SEQUENCE_COMPLETE_RESPONSE;


typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_NV_INDEX          NvIndex;
} TPM2_NV_READPUBLIC_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
  TPM2B_NV_PUBLIC           NvPublic;
  TPM2B_NAME                NvName;
} TPM2_NV_READPUBLIC_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_PROVISION         AuthHandle;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
  TPM2B_AUTH                Auth;
  TPM2B_NV_PUBLIC           NvPublic;
} TPM2_NV_DEFINESPACE_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_NV_DEFINESPACE_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_PROVISION         AuthHandle;
  TPMI_RH_NV_INDEX          NvIndex;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
} TPM2_NV_UNDEFINESPACE_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_NV_UNDEFINESPACE_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_NV_AUTH           AuthHandle;
  TPMI_RH_NV_INDEX          NvIndex;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
  UINT16                    Size;
  UINT16                    Offset;
} TPM2_NV_READ_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPM2B_MAX_BUFFER           Data;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_NV_READ_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_NV_AUTH           AuthHandle;
  TPMI_RH_NV_INDEX          NvIndex;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
  TPM2B_MAX_BUFFER          Data;
  UINT16                    Offset;
} TPM2_NV_WRITE_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_NV_WRITE_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_NV_AUTH           AuthHandle;
  TPMI_RH_NV_INDEX          NvIndex;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
} TPM2_NV_READLOCK_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_NV_READLOCK_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_NV_AUTH           AuthHandle;
  TPMI_RH_NV_INDEX          NvIndex;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
} TPM2_NV_WRITELOCK_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_NV_WRITELOCK_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_NV_AUTH           AuthHandle;
  TPMI_RH_NV_INDEX          NvIndex;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
} TPM2_NV_SETBITS_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_NV_SETBITS_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_PROVISION         AuthHandle;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
} TPM2_NV_GLOBALWRITELOCK_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_NV_GLOBALWRITELOCK_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPM_CAP                   Capability;
  UINT32                    Property;
  UINT32                    PropertyCount;
} TPM2_GET_CAPABILITY_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
  TPMI_YES_NO               MoreData;
  TPMS_CAPABILITY_DATA      CapabilityData;
} TPM2_GET_CAPABILITY_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMT_PUBLIC_PARMS         Parameters;
} TPM2_TEST_PARMS_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
} TPM2_TEST_PARMS_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_DH_CONTEXT           FlushHandle;
} TPM2_FLUSH_CONTEXT_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
} TPM2_FLUSH_CONTEXT_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_DH_ENTITY            AuthHandle;
  TPMI_SH_POLICY            PolicySession;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
  TPM2B_NONCE               NonceTPM;
  TPM2B_DIGEST              CpHashA;
  TPM2B_NONCE               PolicyRef;
  INT32                     Expiration;
} TPM2_POLICY_SECRET_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
  UINT32                    AuthSessionSize;
  TPM2B_TIMEOUT             Timeout;
  TPMT_TK_AUTH              PolicyTicket;
  TPMS_AUTH_RESPONSE        AuthSession;
} TPM2_POLICY_SECRET_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_SH_POLICY            PolicySession;
  TPML_DIGEST               HashList;
} TPM2_POLICY_OR_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
} TPM2_POLICY_OR_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_SH_POLICY            PolicySession;
  TPM_CC                    Code;
} TPM2_POLICY_COMMAND_CODE_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
} TPM2_POLICY_COMMAND_CODE_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_SH_POLICY            PolicySession;
} TPM2_POLICY_GET_DIGEST_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
  TPM2B_DIGEST              PolicyHash;
} TPM2_POLICY_GET_DIGEST_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_HIERARCHY_AUTH    AuthHandle;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
  TPM2B_DIGEST              AuthPolicy;
  TPMI_ALG_HASH             HashAlg;
} TPM2_SET_PRIMARY_POLICY_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_SET_PRIMARY_POLICY_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_CLEAR             AuthHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSession;
} TPM2_CLEAR_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_CLEAR_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_CLEAR             AuthHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSession;
  TPMI_YES_NO               Disable;
} TPM2_CLEAR_CONTROL_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_CLEAR_CONTROL_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_HIERARCHY_AUTH    AuthHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSession;
  TPM2B_AUTH                NewAuth;
} TPM2_HIERARCHY_CHANGE_AUTH_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_HIERARCHY_CHANGE_AUTH_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_PLATFORM          AuthHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSession;
} TPM2_CHANGE_EPS_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_CHANGE_EPS_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_PLATFORM          AuthHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSession;
} TPM2_CHANGE_PPS_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_CHANGE_PPS_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_HIERARCHY         AuthHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSession;
  TPMI_RH_HIERARCHY         Hierarchy;
  TPMI_YES_NO               State;
} TPM2_HIERARCHY_CONTROL_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_HIERARCHY_CONTROL_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_DH_PCR               PcrHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSessionPcr;
  TPML_DIGEST_VALUES        DigestValues;
} TPM2_PCR_EXTEND_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPMS_AUTH_RESPONSE         AuthSessionPcr;
} TPM2_PCR_EXTEND_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_DH_PCR               PcrHandle;
  UINT32                    AuthorizationSize;
  TPMS_AUTH_COMMAND         AuthSessionPcr;
  TPM2B_EVENT               EventData;
} TPM2_PCR_EVENT_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     ParameterSize;
  TPML_DIGEST_VALUES         Digests;
  TPMS_AUTH_RESPONSE         AuthSessionPcr;
} TPM2_PCR_EVENT_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPML_PCR_SELECTION        PcrSelectionIn;
} TPM2_PCR_READ_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
  UINT32                    PcrUpdateCounter;
  TPML_PCR_SELECTION        PcrSelectionOut;
  TPML_DIGEST               PcrValues;
} TPM2_PCR_READ_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_RH_PLATFORM          AuthHandle;
  UINT32                    AuthSessionSize;
  TPMS_AUTH_COMMAND         AuthSession;
  TPML_PCR_SELECTION        PcrAllocation;
} TPM2_PCR_ALLOCATE_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
  UINT32                     AuthSessionSize;
  TPMI_YES_NO                AllocationSuccess;
  UINT32                     MaxPCR;
  UINT32                     SizeNeeded;
  UINT32                     SizeAvailable;
  TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_PCR_ALLOCATE_RESPONSE;

typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPMI_SH_POLICY            PolicySession;
  TPM2B_DIGEST              PcrDigest;
  TPML_PCR_SELECTION        Pcrs;
} TPM2_PCR_POLICYPCR_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       Header;
} TPM2_PCR_POLICYPCR_RESPONSE;

#pragma pack()


//
// TPM 2.0 Command Code → Name Table
// Based on TCG TPM2.0 Library Spec Part 3, Commands.
//
const Tpm2CommandName Tpm2CommandTable[] = {
  {0x011F, "TPM2_Startup"},
  {0x0120, "TPM2_Shutdown"},
  {0x0121, "TPM2_SelfTest"},
  {0x0122, "TPM2_IncrementalSelfTest"},
  {0x0123, "TPM2_GetTestResult"},
  {0x0124, "TPM2_StartAuthSession"},
  {0x0125, "TPM2_PolicyRestart"},
  {0x0126, "TPM2_Create"},
  {0x0127, "TPM2_Load"},
  {0x0128, "TPM2_LoadExternal"},
  {0x0129, "TPM2_ReadPublic"},
  {0x012A, "TPM2_ActivateCredential"},
  {0x012B, "TPM2_MakeCredential"},
  {0x012C, "TPM2_Unseal"},
  {0x012D, "TPM2_ObjectChangeAuth"},
  {0x012E, "TPM2_CreateLoaded"},
  {0x012F, "TPM2_Duplicate"},
  {0x0130, "TPM2_Rewrap"},
  {0x0131, "TPM2_Import"},
  {0x0132, "TPM2_RSA_Encrypt"},
  {0x0133, "TPM2_RSA_Decrypt"},
  {0x0134, "TPM2_ECDH_KeyGen"},
  {0x0135, "TPM2_ZGen_2Phase"},
  {0x0136, "TPM2_ECDH_ZGen"},
  {0x0137, "TPM2_NV_Write"},
  {0x0138, "TPM2_NV_Increment"},
  {0x0139, "TPM2_NV_Extend"},
  {0x013A, "TPM2_NV_SetBits"},
  {0x013B, "TPM2_NV_WriteLock"},
  {0x013C, "TPM2_DictionaryAttackLockReset"},
  {0x013D, "TPM2_DictionaryAttackParameters"},
  {0x013E, "TPM2_NV_DefineSpace"},
  {0x013F, "TPM2_NV_UndefineSpace"},
  {0x0140, "TPM2_Clear"},
  {0x0141, "TPM2_ClearControl"},
  {0x0142, "TPM2_HierarchyChangeAuth"},
  {0x0143, "TPM2_NV_ReadLock"},
  {0x0144, "TPM2_NV_Read"},
  {0x0145, "TPM2_NV_ReadPublic"},
  {0x0146, "TPM2_NV_WritePublic"},
  {0x0147, "TPM2_PCR_Extend"},
  {0x0148, "TPM2_PCR_SetAuthPolicy"},
  {0x0149, "TPM2_PCR_SetAuthValue"},
  {0x014A, "TPM2_PCR_Read"},
  {0x014B, "TPM2_PolicyPCR"},
  {0x014C, "TPM2_PolicyLocality"},
  {0x014D, "TPM2_PolicyNV"},
  {0x014E, "TPM2_NV_Read"},
  {0x014F, "TPM2_NV_Write"},
  {0x0150, "TPM2_PolicyCommandCode"},
  {0x0151, "TPM2_PolicyCounterTimer"},
  {0x0152, "TPM2_PolicyPhysicalPresence"},
  {0x0153, "TPM2_PolicyCpHash"},
  {0x0154, "TPM2_PolicyNameHash"},
  {0x0155, "TPM2_PolicyDuplicationSelect"},
  {0x0156, "TPM2_PolicyAuthorize"},
  {0x0157, "TPM2_PolicyAuthValue"},
  {0x0158, "TPM2_PolicyPassword"},
  {0x0159, "TPM2_PolicyNvWritten"},
  {0x015A, "TPM2_PolicyTemplate"},
  {0x015B, "TPM2_PolicyAuthorizeNV"},
  {0x015C, "TPM2_CreatePrimary"},
  {0x015D, "TPM2_HierarchyControl"},
  {0x015E, "TPM2_SetPrimaryPolicy"},
  {0x015F, "TPM2_FieldUpgradeStart"},
  {0x0160, "TPM2_FieldUpgradeData"},
  {0x0161, "TPM2_FirmwareRead"},
  {0x0162, "TPM2_Certify"},
  {0x0163, "TPM2_CertifyCreation"},
  {0x0164, "TPM2_Quote"},
  {0x0165, "TPM2_GetSessionAuditDigest"},
  {0x0166, "TPM2_GetCommandAuditDigest"},
  {0x0167, "TPM2_GetTime"},
  {0x0168, "TPM2_Commit"},
  {0x0169, "TPM2_EC_Ephemeral"},
  {0x016A, "TPM2_VerifySignature"},
  {0x016B, "TPM2_Sign"},
  {0x016C, "TPM2_SetCommandCodeAuditStatus"},
  {0x016D, "TPM2_PolicySigned"},
  {0x016E, "TPM2_ContextLoad"},
  {0x016F, "TPM2_ContextSave"},
  {0x0170, "TPM2_FlushContext"},
  {0x0171, "TPM2_EvictControl"},
  {0x0172, "TPM2_ReadClock"},
  {0x0173, "TPM2_ClockSet"},
  {0x0174, "TPM2_ClockRateAdjust"},
  {0x0175, "TPM2_GetCapability"},
  {0x0176, "TPM2_TestParms"},
  {0x0177, "TPM2_NV_Certify"},
  {0x0178, "TPM2_NV_CertifyControl"},
  {0x0179, "TPM2_NV_ReadPublic"},
  {0x017A, "TPM2_NV_WriteLock"},
  {0x017B, "TPM2_PolicySecret"},
  {0x017C, "TPM2_NV_UndefineSpaceSpecial"},
  {0x017D, "TPM2_ChangeEPS"},
  {0x017E, "TPM2_ChangePPS"},
  {0x017F, "TPM2_ClearControl"},
  {0x0180, "TPM2_NV_GlobalWriteLock"},
  {0x0181, "TPM2_GetRandom"},
  {0x0182, "TPM2_StirRandom"},
  {0x0183, "TPM2_HMAC_Start"},
  {0x0184, "TPM2_SequenceUpdate"},
  {0x0185, "TPM2_SequenceComplete"},
  {0x0186, "TPM2_EventSequenceComplete"},
  {0x0187, "TPM2_HashSequenceStart"},
  {0x0188, "TPM2_PolicyPhysicalPresence"},
  {0x0189, "TPM2_PolicyCpHash"},
  {0x018A, "TPM2_PolicyDuplicationSelect"},
  {0x018B, "TPM2_PolicyGetDigest"},
  {0x018C, "TPM2_TestParms"},
  {0x018D, "TPM2_Commit"},
  {0x018E, "TPM2_EC_Ephemeral"},
  {0,      NULL } // End marker
};

const char *
EFIAPI
Tpm2CommandCodeToString (
  IN UINT32 CommandCode
  )
{
  UINT16 cmdShort = (UINT16)(CommandCode & 0xFFFF);   // normalize to your table format

  debug(L"[BNK] Tpm2CommandCodeToString - CommandCode %x, cmdShort %x", CommandCode, cmdShort);

  for (UINTN i = 0; Tpm2CommandTable[i].CommandName != NULL; i++) {
    if (Tpm2CommandTable[i].CommandCode == cmdShort) {
      return Tpm2CommandTable[i].CommandName;
    }
  }
  return "UnknownCommand";
}

/**
  Static mapping of TPM2 response codes to strings.
  Based on TCG TPM2.0 Library Specification Part 2: Structures, Rev 1.59.
**/

const char *
EFIAPI
Tpm2ResponseCodeToString (
  IN UINT32 ResponseCode
  )
{
  UINT16 rc = (UINT16)(ResponseCode & 0xFFFF);   // normalize to your table format
  debug(L"[BNK] Tpm2ResponseCodeToString - ResponseCode %x, rc %x", ResponseCode, rc);

    switch (rc) {

    // ---- Format 0 (base codes) ----
case (0x000): return "TPM_RC_SUCCESS           ";
case (0x030): return "TPM_RC_BAD_TAG           ";
case (RC_VER1 + 0x000): return "TPM_RC_INITIALIZE        ";
case (RC_VER1 + 0x001): return "TPM_RC_FAILURE           ";
case (RC_VER1 + 0x003): return "TPM_RC_SEQUENCE          ";
case (RC_VER1 + 0x00B): return "TPM_RC_PRIVATE           ";
case (RC_VER1 + 0x019): return "TPM_RC_HMAC              ";
case (RC_VER1 + 0x020): return "TPM_RC_DISABLED          ";
case (RC_VER1 + 0x021): return "TPM_RC_EXCLUSIVE         ";
case (RC_VER1 + 0x024): return "TPM_RC_AUTH_TYPE         ";
case (RC_VER1 + 0x025): return "TPM_RC_AUTH_MISSING      ";
case (RC_VER1 + 0x026): return "TPM_RC_POLICY            ";
case (RC_VER1 + 0x027): return "TPM_RC_PCR               ";
case (RC_VER1 + 0x028): return "TPM_RC_PCR_CHANGED       ";
case (RC_VER1 + 0x02D): return "TPM_RC_UPGRADE           ";
case (RC_VER1 + 0x02E): return "TPM_RC_TOO_MANY_CONTEXTS ";
case (RC_VER1 + 0x02F): return "TPM_RC_AUTH_UNAVAILABLE  ";
case (RC_VER1 + 0x030): return "TPM_RC_REBOOT            ";
case (RC_VER1 + 0x031): return "TPM_RC_UNBALANCED        ";
case (RC_VER1 + 0x042): return "TPM_RC_COMMAND_SIZE      ";
case (RC_VER1 + 0x043): return "TPM_RC_COMMAND_CODE      ";
case (RC_VER1 + 0x044): return "TPM_RC_AUTHSIZE          ";
case (RC_VER1 + 0x045): return "TPM_RC_AUTH_CONTEXT      ";
case (RC_VER1 + 0x046): return "TPM_RC_NV_RANGE          ";
case (RC_VER1 + 0x047): return "TPM_RC_NV_SIZE           ";
case (RC_VER1 + 0x048): return "TPM_RC_NV_LOCKED         ";
case (RC_VER1 + 0x049): return "TPM_RC_NV_AUTHORIZATION  ";
case (RC_VER1 + 0x04A): return "TPM_RC_NV_UNINITIALIZED  ";
case (RC_VER1 + 0x04B): return "TPM_RC_NV_SPACE          ";
case (RC_VER1 + 0x04C): return "TPM_RC_NV_DEFINED        ";
case (RC_VER1 + 0x050): return "TPM_RC_BAD_CONTEXT       ";
case (RC_VER1 + 0x051): return "TPM_RC_CPHASH            ";
case (RC_VER1 + 0x052): return "TPM_RC_PARENT            ";
case (RC_VER1 + 0x053): return "TPM_RC_NEEDS_TEST        ";
case (RC_VER1 + 0x054): return "TPM_RC_NO_RESULT         ";
case (RC_VER1 + 0x055): return "TPM_RC_SENSITIVE         ";
case (RC_VER1 + 0x07F): return "RC_MAX_FM0               ";

case (RC_FMT1 + 0x001): return "TPM_RC_ASYMMETRIC        ";
case (RC_FMT1 + 0x002): return "TPM_RC_ATTRIBUTES        ";
case (RC_FMT1 + 0x003): return "TPM_RC_HASH              ";
case (RC_FMT1 + 0x004): return "TPM_RC_VALUE             ";
case (RC_FMT1 + 0x005): return "TPM_RC_HIERARCHY         ";
case (RC_FMT1 + 0x007): return "TPM_RC_KEY_SIZE          ";
case (RC_FMT1 + 0x008): return "TPM_RC_MGF               ";
case (RC_FMT1 + 0x009): return "TPM_RC_MODE              ";
case (RC_FMT1 + 0x00A): return "TPM_RC_TYPE              ";
case (RC_FMT1 + 0x00B): return "TPM_RC_HANDLE            ";
case (RC_FMT1 + 0x00C): return "TPM_RC_KDF               ";
case (RC_FMT1 + 0x00D): return "TPM_RC_RANGE             ";
case (RC_FMT1 + 0x00E): return "TPM_RC_AUTH_FAIL         ";
case (RC_FMT1 + 0x00F): return "TPM_RC_NONCE             ";
case (RC_FMT1 + 0x010): return "TPM_RC_PP                ";
case (RC_FMT1 + 0x012): return "TPM_RC_SCHEME            ";
case (RC_FMT1 + 0x015): return "TPM_RC_SIZE              ";
case (RC_FMT1 + 0x016): return "TPM_RC_SYMMETRIC         ";
case (RC_FMT1 + 0x017): return "TPM_RC_TAG               ";
case (RC_FMT1 + 0x018): return "TPM_RC_SELECTOR          ";
case (RC_FMT1 + 0x01A): return "TPM_RC_INSUFFICIENT      ";
case (RC_FMT1 + 0x01B): return "TPM_RC_SIGNATURE         ";
case (RC_FMT1 + 0x01C): return "TPM_RC_KEY               ";
case (RC_FMT1 + 0x01D): return "TPM_RC_POLICY_FAIL       ";
case (RC_FMT1 + 0x01F): return "TPM_RC_INTEGRITY         ";
case (RC_FMT1 + 0x020): return "TPM_RC_TICKET            ";
case (RC_FMT1 + 0x021): return "TPM_RC_RESERVED_BITS     ";
case (RC_FMT1 + 0x022): return "TPM_RC_BAD_AUTH          ";
case (RC_FMT1 + 0x023): return "TPM_RC_EXPIRED           ";
case (RC_FMT1 + 0x024): return "TPM_RC_POLICY_CC        ";
case (RC_FMT1 + 0x025): return "TPM_RC_BINDING           ";
case (RC_FMT1 + 0x026): return "TPM_RC_CURVE             ";
case (RC_FMT1 + 0x027): return "TPM_RC_ECC_POINT         ";


    // ---- Format 1: handle / session / parameter ----
    // Handle errors 0x00000900–0x0000097F
case (RC_WARN + 0x001): return "TPM_RC_CONTEXT_GAP       ";
case (RC_WARN + 0x002): return "TPM_RC_OBJECT_MEMORY     ";
case (RC_WARN + 0x003): return "TPM_RC_SESSION_MEMORY    ";
case (RC_WARN + 0x004): return "TPM_RC_MEMORY            ";
case (RC_WARN + 0x005): return "TPM_RC_SESSION_HANDLES   ";
case (RC_WARN + 0x006): return "TPM_RC_OBJECT_HANDLES    ";
case (RC_WARN + 0x007): return "TPM_RC_LOCALITY          ";
case (RC_WARN + 0x008): return "TPM_RC_YIELDED           ";
case (RC_WARN + 0x009): return "TPM_RC_CANCELED          ";
case (RC_WARN + 0x00A): return "TPM_RC_TESTING           ";
case (RC_WARN + 0x010): return "TPM_RC_REFERENCE_H0      ";
case (RC_WARN + 0x011): return "TPM_RC_REFERENCE_H1      ";
case (RC_WARN + 0x012): return "TPM_RC_REFERENCE_H2      ";
case (RC_WARN + 0x013): return "TPM_RC_REFERENCE_H3      ";
case (RC_WARN + 0x014): return "TPM_RC_REFERENCE_H4      ";
case (RC_WARN + 0x015): return "TPM_RC_REFERENCE_H5      ";
case (RC_WARN + 0x016): return "TPM_RC_REFERENCE_H6      ";
case (RC_WARN + 0x018): return "TPM_RC_REFERENCE_S0      ";
case (RC_WARN + 0x019): return "TPM_RC_REFERENCE_S1      ";
case (RC_WARN + 0x01A): return "TPM_RC_REFERENCE_S2      ";
case (RC_WARN + 0x01B): return "TPM_RC_REFERENCE_S3      ";
case (RC_WARN + 0x01C): return "TPM_RC_REFERENCE_S4      ";
case (RC_WARN + 0x01D): return "TPM_RC_REFERENCE_S5      ";
case (RC_WARN + 0x01E): return "TPM_RC_REFERENCE_S6      ";
case (RC_WARN + 0x020): return "TPM_RC_NV_RATE           ";
case (RC_WARN + 0x021): return "TPM_RC_LOCKOUT           ";
case (RC_WARN + 0x022): return "TPM_RC_RETRY             ";
case (RC_WARN + 0x023): return "TPM_RC_NV_UNAVAILABLE    ";
case (RC_WARN + 0x7F): return "TPM_RC_NOT_USED          ";

    default: return "TPM_RC_UNKNOWN";
  }
}

#define MAX_HEX_DUMP_BYTES 64  // for safety

VOID
EFIAPI
Tpm2DecodeCommand (
  IN UINT32 InputParameterBlockSize,
  IN UINT8  *InputParameterBlock
  )
{
  debug(L"[BNK_TPMDBG] Tpm2DecodeCommand - ENTRY");

  if (InputParameterBlock == NULL || InputParameterBlockSize < sizeof(TPM2_COMMAND_HEADER)) {
    debug(L"[BNK_TPMDBG] Invalid command buffer\n");
    return;
  }

  TPM2_COMMAND_HEADER *cmd = (TPM2_COMMAND_HEADER *)InputParameterBlock;

  UINT16 tag        = SwapBytes16(cmd->tag);
  UINT32 totalSize  = SwapBytes32(cmd->paramSize);
  UINT32 commandCode = SwapBytes32(cmd->commandCode);

  const CHAR16 *tagStr;

  switch (tag) {
    case 0x8001: tagStr = L"TPM_ST_NO_SESSIONS"; break;
    case 0x8002: tagStr = L"TPM_ST_SESSIONS"; break;
    default:     tagStr = L"UNKNOWN"; break;
  }

  const char *cmdName = Tpm2CommandCodeToString(commandCode);

  debug(L"[BNK_TPMDBG] Decode Tag: 0x%04x (%s): ParamSize: %u, cmdcode %x, name %s", tag, tagStr, totalSize, commandCode, cmdName);

  // Print payload (if any)
  UINT32 payloadSize = totalSize - sizeof(TPM2_COMMAND_HEADER);
  if (payloadSize > 0) {
    debug(L"[BNK_TPMDBG] Payload (%u bytes):", payloadSize);
    UINT32 dumpSize = (payloadSize < MAX_HEX_DUMP_BYTES) ? payloadSize : MAX_HEX_DUMP_BYTES;

    for (UINT32 i = 0; i < dumpSize; i++) {
      //if (i % 16 == 0) DEBUG((EFI_D_INFO, L"  "));
      debug(L"%02x ", InputParameterBlock[sizeof(TPM2_COMMAND_HEADER) + i]);
    }
    if (payloadSize > MAX_HEX_DUMP_BYTES)
      debug(L"... (truncated)");
  } else {
    debug(L"[BNK_TPMDBG] No payload.");
  }

   UINT8 *params = (UINT8 *)InputParameterBlock + sizeof(TPM2_COMMAND_HEADER);
   UINT32 remaining = InputParameterBlockSize - sizeof(TPM2_COMMAND_HEADER);

switch (commandCode) {

    case TPM_CC_GetCapability: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      UINT32 cap = SwapBytes32(Cmd->Capability);
      UINT32 prop = SwapBytes32(Cmd->Property);
      UINT32 propCount = SwapBytes32(Cmd->PropertyCount);

      const CHAR16 *capName = L"Unknown";
      switch (cap) {
        case TPM_CAP_ALGS:              capName = L"TPM_CAP_ALGS"; break;
        case TPM_CAP_HANDLES:           capName = L"TPM_CAP_HANDLES"; break;
        case TPM_CAP_COMMANDS:          capName = L"TPM_CAP_COMMANDS"; break;
        case TPM_CAP_PP_COMMANDS:       capName = L"TPM_CAP_PP_COMMANDS"; break;
        case TPM_CAP_AUDIT_COMMANDS:    capName = L"TPM_CAP_AUDIT_COMMANDS"; break;
        case TPM_CAP_PCRS:              capName = L"TPM_CAP_PCRS"; break;
        case TPM_CAP_TPM_PROPERTIES:    capName = L"TPM_CAP_TPM_PROPERTIES"; break;
        case TPM_CAP_PCR_PROPERTIES:    capName = L"TPM_CAP_PCR_PROPERTIES"; break;
        case TPM_CAP_ECC_CURVES:        capName = L"TPM_CAP_ECC_CURVES"; break;
        case TPM_CAP_VENDOR_PROPERTY:   capName = L"TPM_CAP_VENDOR_PROPERTY"; break;
        default: break;
      }

      debug(L"[BNK_TPMDBG] TPM2_GetCapability (TPM_CC_GetCapability): Capability=0x%08x (%s) Property=0x%08x PropertyCount=%u",
            cap, capName, prop, propCount);

      break;
    }

    case TPM_CC_HashSequenceStart: {
      TPM2_HASH_SEQUENCE_START_COMMAND *Cmd = (TPM2_HASH_SEQUENCE_START_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_HashSequenceStart (TPM_CC_HashSequenceStart): AuthSize=%u", SwapBytes16(Cmd->Auth.size));
      break;
    }

    case TPM_CC_SequenceUpdate: {
      TPM2_SEQUENCE_UPDATE_COMMAND *Cmd = (TPM2_SEQUENCE_UPDATE_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_SequenceUpdate (TPM_CC_SequenceUpdate): SequenceHandle=0x%08x BufferSize=%u",
            SwapBytes32(Cmd->SequenceHandle), SwapBytes16(Cmd->Buffer.size));
      break;
    }

    case TPM_CC_EventSequenceComplete: {
      TPM2_EVENT_SEQUENCE_COMPLETE_COMMAND *Cmd = (TPM2_EVENT_SEQUENCE_COMPLETE_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_EventSequenceComplete (TPM_CC_EventSequenceComplete): PcrHandle=0x%08x SequenceHandle=0x%08x BufferSize=%u",
            SwapBytes32(Cmd->PcrHandle), SwapBytes32(Cmd->SequenceHandle), SwapBytes16(Cmd->Buffer.size));
      break;
    }

    case TPM_CC_SequenceComplete: {
      TPM2_SEQUENCE_COMPLETE_COMMAND *Cmd = (TPM2_SEQUENCE_COMPLETE_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_SequenceComplete (TPM_CC_SequenceComplete): SequenceHandle=0x%08x BufferSize=%u Hierarchy=0x%08x",
            SwapBytes32(Cmd->SequenceHandle), SwapBytes16(Cmd->Buffer.size), SwapBytes32(Cmd->Hierarchy));
      break;
    }

    // ---- Policy Commands ----
    //
    case TPM_CC_PolicySecret: {
      TPM2_POLICY_SECRET_COMMAND *Cmd = (TPM2_POLICY_SECRET_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_PolicySecret (TPM_CC_PolicySecret): AuthHandle=0x%08x PolicySession=0x%08x Expiration=%d",
            SwapBytes32(Cmd->AuthHandle), SwapBytes32(Cmd->PolicySession), SwapBytes32(Cmd->Expiration));
      break;
    }

    case TPM_CC_PolicyOR: {
      TPM2_POLICY_OR_COMMAND *Cmd = (TPM2_POLICY_OR_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_PolicyOR (TPM_CC_PolicyOR): PolicySession=0x%08x DigestCount=%u",
            SwapBytes32(Cmd->PolicySession), SwapBytes32(Cmd->HashList.count));
      break;
    }


    case TPM_CC_PolicyCommandCode: {
      TPM2_POLICY_COMMAND_CODE_COMMAND *Cmd = (TPM2_POLICY_COMMAND_CODE_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_PolicyCommandCode (TPM_CC_PolicyCommandCode): PolicySession=0x%08x Code=0x%08x",
            SwapBytes32(Cmd->PolicySession), SwapBytes32(Cmd->Code));
      break;
    }

    case TPM_CC_PolicyGetDigest: {
      TPM2_POLICY_GET_DIGEST_COMMAND *Cmd = (TPM2_POLICY_GET_DIGEST_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_PolicyGetDigest (TPM_CC_PolicyGetDigest): PolicySession=0x%08x",
            SwapBytes32(Cmd->PolicySession));
      break;
    }


    case TPM_CC_SetPrimaryPolicy: {
      TPM2_SET_PRIMARY_POLICY_COMMAND *Cmd = (TPM2_SET_PRIMARY_POLICY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_SetPrimaryPolicy (TPM_CC_SetPrimaryPolicy): AuthHandle=0x%08x PolicySize=%u HashAlg=0x%04x",
            SwapBytes32(Cmd->AuthHandle), SwapBytes16(Cmd->AuthPolicy.size), SwapBytes16(Cmd->HashAlg));
      break;
    }

    case TPM_CC_Clear: {
      TPM2_CLEAR_COMMAND *Cmd = (TPM2_CLEAR_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_Clear (TPM_CC_Clear): AuthHandle=0x%08x", SwapBytes32(Cmd->AuthHandle));
      break;
    }

    case TPM_CC_ClearControl: {
      TPM2_CLEAR_CONTROL_COMMAND *Cmd = (TPM2_CLEAR_CONTROL_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_ClearControl (TPM_CC_ClearControl): AuthHandle=0x%08x Disable=%u",
            SwapBytes32(Cmd->AuthHandle), Cmd->Disable);
      break;
    }

    case TPM_CC_HierarchyChangeAuth: {
      TPM2_HIERARCHY_CHANGE_AUTH_COMMAND *Cmd = (TPM2_HIERARCHY_CHANGE_AUTH_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_HierarchyChangeAuth (TPM_CC_HierarchyChangeAuth): AuthHandle=0x%08x NewAuthSize=%u",
            SwapBytes32(Cmd->AuthHandle), SwapBytes16(Cmd->NewAuth.size));
      break;
    }

    case TPM_CC_ChangeEPS: {
      TPM2_CHANGE_EPS_COMMAND *Cmd = (TPM2_CHANGE_EPS_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_ChangeEPS (TPM_CC_ChangeEPS): AuthHandle=0x%08x", SwapBytes32(Cmd->AuthHandle));
      break;
    }

    case TPM_CC_ChangePPS: {
      TPM2_CHANGE_PPS_COMMAND *Cmd = (TPM2_CHANGE_PPS_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_ChangePPS (TPM_CC_ChangePPS): AuthHandle=0x%08x", SwapBytes32(Cmd->AuthHandle));
      break;
    }

    case TPM_CC_HierarchyControl: {
      TPM2_HIERARCHY_CONTROL_COMMAND *Cmd = (TPM2_HIERARCHY_CONTROL_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_HierarchyControl (TPM_CC_HierarchyControl): AuthHandle=0x%08x State=%u",
            SwapBytes32(Cmd->AuthHandle), /*SwapBytes32(Cmd->Enable),*/ Cmd->State);
      break;
    }

    case TPM_CC_NV_ReadPublic: {
      TPM2_NV_READPUBLIC_COMMAND *Cmd = (TPM2_NV_READPUBLIC_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_NV_ReadPublic (TPM_CC_NV_ReadPublic): NvIndex=0x%08x", SwapBytes32(Cmd->NvIndex));
      break;
    }

    case TPM_CC_NV_DefineSpace: {
      TPM2_NV_DEFINESPACE_COMMAND *Cmd = (TPM2_NV_DEFINESPACE_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_NV_DefineSpace (TPM_CC_NV_DefineSpace): AuthHandle=0x%08x AuthSize=%u",
            SwapBytes32(Cmd->AuthHandle), SwapBytes16(Cmd->Auth.size));
      break;
    }

    case TPM_CC_NV_UndefineSpace: {
      TPM2_NV_UNDEFINESPACE_COMMAND *Cmd = (TPM2_NV_UNDEFINESPACE_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_NV_UndefineSpace (TPM_CC_NV_UndefineSpace): AuthHandle=0x%08x NvIndex=0x%08x",
            SwapBytes32(Cmd->AuthHandle), SwapBytes32(Cmd->NvIndex));
      break;
    }

    case TPM_CC_NV_Read: {
      TPM2_NV_READ_COMMAND *Cmd = (TPM2_NV_READ_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_NV_Read (TPM_CC_NV_Read): AuthHandle=0x%08x NvIndex=0x%08x Size=%u Offset=%u",
            SwapBytes32(Cmd->AuthHandle), SwapBytes32(Cmd->NvIndex), SwapBytes16(Cmd->Size), SwapBytes16(Cmd->Offset));
      break;
    }

    case TPM_CC_NV_Write: {
      TPM2_NV_WRITE_COMMAND *Cmd = (TPM2_NV_WRITE_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_NV_Write (TPM_CC_NV_Write): AuthHandle=0x%08x NvIndex=0x%08x DataSize=%u Offset=%u",
            SwapBytes32(Cmd->AuthHandle), SwapBytes32(Cmd->NvIndex), SwapBytes16(Cmd->Data.size), SwapBytes16(Cmd->Offset));
      break;
    }

    case TPM_CC_NV_ReadLock: {
      TPM2_NV_READLOCK_COMMAND *Cmd = (TPM2_NV_READLOCK_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_NV_ReadLock (TPM_CC_NV_ReadLock): AuthHandle=0x%08x NvIndex=0x%08x",
            SwapBytes32(Cmd->AuthHandle), SwapBytes32(Cmd->NvIndex));
      break;
    }

    case TPM_CC_NV_WriteLock: {
      TPM2_NV_WRITELOCK_COMMAND *Cmd = (TPM2_NV_WRITELOCK_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_NV_WriteLock (TPM_CC_NV_WriteLock): AuthHandle=0x%08x NvIndex=0x%08x",
            SwapBytes32(Cmd->AuthHandle), SwapBytes32(Cmd->NvIndex));
      break;
    }

    case TPM_CC_NV_GlobalWriteLock: {
      TPM2_NV_GLOBALWRITELOCK_COMMAND *Cmd = (TPM2_NV_GLOBALWRITELOCK_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_NV_GlobalWriteLock (TPM_CC_NV_GlobalWriteLock): AuthHandle=0x%08x",
            SwapBytes32(Cmd->AuthHandle));
      break;
    }

    case TPM_CC_NV_SetBits: {
      TPM2_NV_SETBITS_COMMAND *Cmd = (TPM2_NV_SETBITS_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_NV_SetBits (TPM_CC_NV_SetBits): AuthHandle=0x%08x NvIndex=0x%08x",
            SwapBytes32(Cmd->AuthHandle), SwapBytes32(Cmd->NvIndex));
      break;
    }

    case TPM_CC_PCR_Extend: {
      TPM2_PCR_EXTEND_COMMAND *Cmd = (TPM2_PCR_EXTEND_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_PCR_Extend (TPM_CC_PCR_Extend): PcrHandle=0x%08x DigestCount=%u",
            SwapBytes32(Cmd->PcrHandle), SwapBytes32(Cmd->DigestValues.count));
      break;
    }

    case TPM_CC_PCR_Event: {
      TPM2_PCR_EVENT_COMMAND *Cmd = (TPM2_PCR_EVENT_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_PCR_Event (TPM_CC_PCR_Event): PcrHandle=0x%08x EventSize=%u",
            SwapBytes32(Cmd->PcrHandle), SwapBytes16(Cmd->EventData.size));
      break;
    }

    case TPM_CC_PCR_Read: {
      TPM2_PCR_READ_COMMAND *Cmd = (TPM2_PCR_READ_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_PCR_Read (TPM_CC_PCR_Read): PcrSelectionCount=%u", SwapBytes32(Cmd->PcrSelectionIn.count));
      break;
    }
    //
    // ---- Additional supporting commands ----
    //
    case TPM_CC_TestParms: {
      TPM2_TEST_PARMS_COMMAND *Cmd = (TPM2_TEST_PARMS_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_TestParms (TPM_CC_TestParms): Algorithm=0x%04x", SwapBytes16(Cmd->Parameters.type));
      break;
    }

/*    case TPM_CC_DictionaryAttackLockReset: {
      TPM2_DICTIONARY_ATTACK_LOCK_RESET_COMMAND *Cmd = (TPM2_DICTIONARY_ATTACK_LOCK_RESET_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_DictionaryAttackLockReset (TPM_CC_DictionaryAttackLockReset): LockHandle=0x%08x",
            SwapBytes32(Cmd->LockHandle));
      break;
    }

    case TPM_CC_DictionaryAttackParameters: {
      TPM2_DICTIONARY_ATTACK_PARAMETERS_COMMAND *Cmd = (TPM2_DICTIONARY_ATTACK_PARAMETERS_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_DictionaryAttackParameters (TPM_CC_DictionaryAttackParameters): LockHandle=0x%08x MaxTries=%u RecoveryTime=%u LockoutRecovery=%u",
            SwapBytes32(Cmd->LockHandle), SwapBytes32(Cmd->MaxTries), SwapBytes32(Cmd->RecoveryTime), SwapBytes32(Cmd->LockoutRecovery));
      break;
    }

 
    case TPM_CC_Hash: {
      TPM2_HASH_COMMAND *Cmd = (TPM2_HASH_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_Hash (TPM_CC_Hash): DataSize=%u Algorithm=0x%04x Hierarchy=0x%08x",
            SwapBytes16(Cmd->Data.size), SwapBytes16(Cmd->HashAlg), SwapBytes32(Cmd->Hierarchy));
      break;
    }

    case TPM_CC_Startup: {
      TPM2_STARTUP_COMMAND *Cmd = (TPM2_STARTUP_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_Startup (TPM_CC_Startup): StartupType=0x%04x", SwapBytes16(Cmd->StartupType));
      break;
    }

    case TPM_CC_Shutdown: {
      TPM2_SHUTDOWN_COMMAND *Cmd = (TPM2_SHUTDOWN_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_Shutdown (TPM_CC_Shutdown): ShutdownType=0x%04x", SwapBytes16(Cmd->ShutdownType));
      break;
    }

    case TPM_CC_SelfTest: {
      TPM2_SELF_TEST_COMMAND *Cmd = (TPM2_SELF_TEST_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_SelfTest (TPM_CC_SelfTest): FullTest=%u", Cmd->FullTest);
      break;
    }


    case TPM_CC_GetRandom: {
      TPM2_GET_RANDOM_COMMAND *Cmd = (TPM2_GET_RANDOM_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetRandom (TPM_CC_GetRandom): BytesRequested=%u", SwapBytes16(Cmd->BytesRequested));
      break;
    }

//
    // ---- Extended GetCapability Variants ----
    //
    case TPM_CC_GetCapability: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapability (TPM_CC_GetCapability): Capability=0x%08x Property=0x%08x PropertyCount=%u",
            SwapBytes32(Cmd->Capability), SwapBytes32(Cmd->Property), SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilityFamily: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilityFamily (TPM_CC_GetCapability): Capability=TPM_CAP_TPM_PROPERTIES Property=TPM_PT_FAMILY_INDICATOR Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilityManufactureID: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilityManufactureID (TPM_CC_GetCapability): Capability=TPM_CAP_TPM_PROPERTIES Property=TPM_PT_MANUFACTURER Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilityFirmwareVersion: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilityFirmwareVersion (TPM_CC_GetCapability): Capability=TPM_CAP_TPM_PROPERTIES Property=TPM_PT_FIRMWARE_VERSION_1 Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilityMaxCommandResponseSize: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilityMaxCommandResponseSize (TPM_CC_GetCapability): Capability=TPM_CAP_TPM_PROPERTIES Property=TPM_PT_MAX_COMMAND_SIZE Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilitySupportedAlg: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilitySupportedAlg (TPM_CC_GetCapability): Capability=TPM_CAP_ALGS Property=0 Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilityLockoutCounter: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilityLockoutCounter (TPM_CC_GetCapability): Capability=TPM_CAP_TPM_PROPERTIES Property=TPM_PT_LOCKOUT_COUNTER Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilityLockoutInterval: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilityLockoutInterval (TPM_CC_GetCapability): Capability=TPM_CAP_TPM_PROPERTIES Property=TPM_PT_LOCKOUT_INTERVAL Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilityInputBufferSize: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilityInputBufferSize (TPM_CC_GetCapability): Capability=TPM_CAP_TPM_PROPERTIES Property=TPM_PT_INPUT_BUFFER Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilityPcrs: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilityPcrs (TPM_CC_GetCapability): Capability=TPM_CAP_PCRS Property=0 Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_GetCapabilityAlgorithmSet: {
      TPM2_GET_CAPABILITY_COMMAND *Cmd = (TPM2_GET_CAPABILITY_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_GetCapabilityAlgorithmSet (TPM_CC_GetCapability): Capability=TPM_CAP_TPM_PROPERTIES Property=TPM_PT_ALGORITHM_SET Count=%u",
            SwapBytes32(Cmd->PropertyCount));
      break;
    }

    case TPM_CC_SetAlgorithmSet: {
      TPM2_SET_ALGORITHM_SET_COMMAND *Cmd = (TPM2_SET_ALGORITHM_SET_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_SetAlgorithmSet (TPM_CC_SetAlgorithmSet): AlgorithmSet=0x%08x", SwapBytes32(Cmd->AlgorithmSet));
      break;
    }

    //
    // ---- Session / Context Commands ----
    //
    case TPM_CC_StartAuthSession: {
      TPM2_START_AUTH_SESSION_COMMAND *Cmd = (TPM2_START_AUTH_SESSION_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_StartAuthSession (TPM_CC_StartAuthSession): TpmKey=0x%08x Bind=0x%08x NonceCallerSize=%u",
            SwapBytes32(Cmd->TpmKey), SwapBytes32(Cmd->Bind), SwapBytes16(Cmd->NonceCaller.size));
      break;
    }

    case TPM_CC_FlushContext: {
      TPM2_FLUSH_CONTEXT_COMMAND *Cmd = (TPM2_FLUSH_CONTEXT_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_FlushContext (TPM_CC_FlushContext): FlushHandle=0x%08x", SwapBytes32(Cmd->FlushHandle));
      break;
    }

    //
    // ---- Policy Commands ----
    //
    case TPM_CC_PolicyAuthorize: {
      TPM2_POLICY_OR_COMMAND *Cmd = (TPM2_POLICY_OR_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_PolicyAuthorize (TPM_CC_PolicyAuthorize): PolicySession=0x%08x",
            SwapBytes32(Cmd->PolicySession));
      break;
    }

    case TPM_CC_PolicyAuthValue: {
      TPM2_POLICY_AUTH_VALUE_COMMAND *Cmd = (TPM2_POLICY_AUTH_VALUE_COMMAND *)InputParameterBlock;
      debug(L"[BNK_TPMDBG] TPM2_PolicyAuthValue (TPM_CC_PolicyAuthValue): PolicySession=0x%08x",
            SwapBytes32(Cmd->PolicySession));
      break;
    }


    case TPM_CC_ReadClock: {
      debug(L"[BNK_TPMDBG] TPM2_ReadClock (TPM_CC_ReadClock)");
      break;
    }
*/
  default:
    // fallback hex dump
    break;
}

}
