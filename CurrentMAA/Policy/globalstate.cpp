//
// Enclave-based attestation service
//
// Immutable lobal state and its accessor methods
//
// Copyright (c) Microsoft corporation. All rights reserved.
//

#include "ocl.h"
#include "state.h"
#include "enclave.h"
#include "globalstate.h"
#include "scopelock.h"
#include <enctypes.h>
#include "itemcollection.h"
#include <cassert>
#include <sgxquoteprocessor.h>
#include <cyresquoteprocessor.h>
#include <vsmquoteprocessor.h>
#include <azureguestquoteprocessor.h>
#include <sevsnpvmquoteprocessor.h>
#include <sgxpal.h>
#include <winquoteprocessor.h>
#include <OcallSink.h>
#include "hostmarshalledblob.h"

using namespace EnclavePal;
using namespace EnclaveShared;
using namespace QuoteProcessor;

static TrustedExecutionEnvironmentKind g_currentPlatform;
static std::shared_ptr<Pal> g_pPal;
std::vector<std::shared_ptr<IQuoteProcessor>> g_QuoteProcessors;

const TrustedExecutionEnvironmentKind g_aAttestablePlatforms[] = {
    TrustedExecutionEnvironmentKind::SgxEnclave,
    TrustedExecutionEnvironmentKind::CyResComponent,
    TrustedExecutionEnvironmentKind::VSMEnclave,
    TrustedExecutionEnvironmentKind::OpenEnclave,
    TrustedExecutionEnvironmentKind::AzureGuest,
    TrustedExecutionEnvironmentKind::SevSnpVm
};
const uint32_t g_cAttestablePlatforms = _countof(g_aAttestablePlatforms);

std::unique_ptr<ItemCollection<Enclave>> g_pEnclaves;

const Pal& PAL()
{
    assert(g_pPal != nullptr);
    return *g_pPal;
}


_Use_decl_annotations_
const IQuoteProcessor &GetQuoteProcessor(
    TrustedExecutionEnvironmentKind teeKind)
{
    assert(g_QuoteProcessors[static_cast<uint32_t>(teeKind)]);
    assert(g_QuoteProcessors[static_cast<uint32_t>(teeKind)]->TeeKind() == teeKind);
    return *g_QuoteProcessors[static_cast<uint32_t>(teeKind)];
}


TrustedExecutionEnvironmentKind TeeSelf()
{
    return g_currentPlatform;
}


_Use_decl_annotations_
bool IsAttestablePlatform(
    _In_ TrustedExecutionEnvironmentKind teeKind)
{
    assert(g_QuoteProcessors[static_cast<uint32_t>(teeKind)]);
    assert(g_QuoteProcessors[static_cast<uint32_t>(teeKind)]->TeeKind() == teeKind);
    return g_QuoteProcessors[static_cast<uint32_t>(teeKind)]->IsAttestatable();
}


_Use_decl_annotations_
uint32_t GetPlatformIndex(
    _In_ TrustedExecutionEnvironmentKind teeKind)
{
    assert(IsAttestablePlatform(teeKind));

    switch (teeKind)
    {
    case TrustedExecutionEnvironmentKind::SgxEnclave:
        return 0;
    case TrustedExecutionEnvironmentKind::CyResComponent:
        return 1;
    case TrustedExecutionEnvironmentKind::VSMEnclave:
        return 2;
    case TrustedExecutionEnvironmentKind::OpenEnclave:
        return 3;
    case TrustedExecutionEnvironmentKind::AzureGuest:
        return 4;
    case TrustedExecutionEnvironmentKind::SevSnpVm:
        return 5;

    default:
        assert(false);
        return 0xFFFFFFFF;  // TODO: maybe throw exception?
    }
}


_Use_decl_annotations_
std::unique_ptr<Buffer> GetDefaultAttestationPolicy(
    _In_ TrustedExecutionEnvironmentKind teeKind)
{
    std::unique_ptr<Buffer> pResult;

    assert(IsAttestablePlatform(teeKind));

    switch (teeKind)
    {
    case TrustedExecutionEnvironmentKind::SgxEnclave:
    case TrustedExecutionEnvironmentKind::OpenEnclave:
    {
        static constexpr const uint8_t defaultSgxAttestationPolicy[] =
            "version= 1.0;"
            "authorizationrules"
            "{"
                "c:[type==\"$is-debuggable\"] => permit();"
            "};"
            "issuancerules"
            "{"
                    "c:[type==\"$is-debuggable\"] => issue(type=\"is-debuggable\", value=c.value);"
                    "c:[type==\"$sgx-mrsigner\"] => issue(type=\"sgx-mrsigner\", value=c.value);"
                    "c:[type==\"$sgx-mrenclave\"] => issue(type=\"sgx-mrenclave\", value=c.value);"
                    "c:[type==\"$product-id\"] => issue(type=\"product-id\", value=c.value);"
                    "c:[type==\"$svn\"] => issue(type=\"svn\", value=c.value);"
                    "c:[type==\"$tee\"] => issue(type=\"tee\", value=c.value);"
             "};";
        pResult = Buffer::Create(
            defaultSgxAttestationPolicy,
            sizeof(defaultSgxAttestationPolicy),
            false);
        break;
    }
    case TrustedExecutionEnvironmentKind::CyResComponent:
    {
        static constexpr const uint8_t defaultCyResAttestationPolicy[] =
            "version= 1.0;"
            "authorizationrules"
            "{"
                "c:[type==\"$is-debuggable\"] => permit();"
            "};"
            "issuancerules"
            "{"
                "c:[type==\"$public_key_0\"] => issue(type=\"device_id\", value=c.value);"
                "c:[type==\"$product_id_0\"] => issue(type=\"component_0_id\", value=c.value);"
                "=> issue(type=\"expected_components\", value=\"component_0\");"
                "c:[type==\"$tee\"] => issue(type=\"tee\", value=c.value);"
            "};";
        pResult = Buffer::Create(
            defaultCyResAttestationPolicy,
            sizeof(defaultCyResAttestationPolicy),
            false);
        break;
    }
    case TrustedExecutionEnvironmentKind::VSMEnclave:
    {
        static constexpr const uint8_t defaultVSMAttestationPolicy[] = "";
        pResult = Buffer::Create(
            defaultVSMAttestationPolicy,
            sizeof(defaultVSMAttestationPolicy),
            false);
        break;
    }
    case TrustedExecutionEnvironmentKind::AzureGuest:
    {
        static constexpr const uint8_t defaultAzureGuestAttestationPolicy[] =
            R"(
                version= 1.0;
                authorizationrules
                {
                    [type=="$bootdebug-enabled", value==false] &&
                    [type=="$hypervisordebug-enabled", value==false] &&
                    [type=="$kerneldebug-enabled", value==false]
                    => add (type="debuggers-enabled", value=false);

                    [type=="EV_EFI_Variable_Driver_Config/SHA256/pcr7/8be4df61-93ca-11d2-aa0d-00e098032b8c/PK", value=="827F3AD1828BD20CC03A5624D4CE3F1CF74910715CC764F69800FEFD8F406DC6"] &&
                    [type=="EV_EFI_Variable_Driver_Config/SHA256/pcr7/8be4df61-93ca-11d2-aa0d-00e098032b8c/KEK", value=="63C0EE78EB49B91AC213B03768A827EBF9B12370F65851B19A883BF32EAF2A14"] &&
                    [type=="EV_EFI_Variable_Driver_Config/SHA256/pcr7/d719b2cb-3d3a-4596-a3bc-dad00e67656f/db", value=="557D6499C5B8CF01576C44BEA8B5320D9723DEDEA6883BBD42566DB56CE888FC"] && 
                    [type=="EV_EFI_Variable_Driver_Config/SHA256/pcr7/d719b2cb-3d3a-4596-a3bc-dad00e67656f/dbx", value=="A044B4CE4A4DCA9AF312C897DC56EE1727C385EB88F7CFB9092B8265029D5B1E"]
                    => add (type="windows-securebootkeys-validated", value=true);

                    [type=="EV_EFI_Variable_Driver_Config/SHA256/pcr7/8be4df61-93ca-11d2-aa0d-00e098032b8c/PK", value=="827F3AD1828BD20CC03A5624D4CE3F1CF74910715CC764F69800FEFD8F406DC6"] &&
                    [type=="EV_EFI_Variable_Driver_Config/SHA256/pcr7/8be4df61-93ca-11d2-aa0d-00e098032b8c/KEK", value=="63C0EE78EB49B91AC213B03768A827EBF9B12370F65851B19A883BF32EAF2A14"] &&
                    [type=="EV_EFI_Variable_Driver_Config/SHA256/pcr7/d719b2cb-3d3a-4596-a3bc-dad00e67656f/db", value=="F54DBC80B0C8E64CF184A8AD3314295153285B493B921FEB67DE14C6CADD43F4"] && 
                    [type=="EV_EFI_Variable_Driver_Config/SHA256/pcr7/d719b2cb-3d3a-4596-a3bc-dad00e67656f/dbx", value=="4EE879DAB4D6F835A6CADC6BBA242CE00BA6F3D03EB31B5D5635F0CE07381D11"]
                    => add (type="linux-securebootkeys-validated", value=true);

                    [type=="$is-windows", value==true] &&
                    [type=="debuggers-enabled", value==false] &&
                    [type=="$testsigning-enabled", value==false] &&
                    [type=="$secureboot", value==true] &&
                    [type=="windows-securebootkeys-validated", value==true] => permit();

                    [type=="$is-windows", value==false] &&
                    [type=="EV_EFI_Variable_Authority/SHA256/pcr7/605dab50-e046-4300-abb6-3dd810dd8b23/Shim", value!="70F0DCA0FD93403E2ED2E7106781DB1E002B1CBAE77FF3A2E23CAB46EB6349D2"]
                    => deny();

                    [type=="$is-windows", value==false] &&
                    [type=="EV_EFI_Variable_Authority/SHA256/pcr7/605dab50-e046-4300-abb6-3dd810dd8b23/MokList"] => deny();

                    [type=="$is-windows", value==false] &&
                    [type=="$secureboot", value==true] &&
                    [type=="linux-securebootkeys-validated", value==true] &&
                    [type=="EV_EFI_Variable_Authority/SHA256/pcr7/605dab50-e046-4300-abb6-3dd810dd8b23/Shim", value=="70F0DCA0FD93403E2ED2E7106781DB1E002B1CBAE77FF3A2E23CAB46EB6349D2"]
                    => permit();
                };
                issuancerules
                {
                    => issue(type = "token-ver", value = "1.0");
                    c:[type=="$attestation-protocol-ver"] => issue(claim=c);
                    c:[type=="$vmid"] => issue(claim=c);
                    c:[type=="$tee"] => issue(claim=c);
                    c:[type=="$nonce"] => issue(claim=c);
                    c:[type=="$encryption-key"] => issue(claim=c);
                    c:[type=="$attested-pcrs"] => issue(claim=c);
                    c:[type=="$nonce"] => issue(claim=c);
                    c:[type=="$ostype"] => issue(claim=c);
                    c:[type=="$osdistro"] => issue(claim=c);
                    c:[type=="$osbuild"] => issue(claim=c);
                    c:[type=="$osversion-major"] => issue(claim=c);
                    c:[type=="$osversion-minor"] => issue(claim=c);
                    c:[type=="$bootdebug-enabled"] => issue(claim=c);
                    c:[type=="$hypervisordebug-enabled"] => issue(claim=c);
                    c:[type=="$kerneldebug-enabled"] => issue(claim=c);
                    c:[type=="$testsigning-enabled"] => issue(claim=c);
                    c:[type=="$flightsigning-enabled"] => issue(claim=c);
                    c:[type=="$elam-enabled"] => issue(claim=c);
                    c:[type=="$codeintegrity"] => issue(claim=c);
                    c:[type=="$secureboot"] => issue(claim=c);
                    c:[type=="$pcr0"] => issue(claim=c);
                    c:[type=="$pcr1"] => issue(claim=c);
                    c:[type=="$pcr2"] => issue(claim=c);
                    c:[type=="$pcr3"] => issue(claim=c);
                    c:[type=="$pcr4"] => issue(claim=c);
                    c:[type=="$pcr5"] => issue(claim=c);
                    c:[type=="$pcr6"] => issue(claim=c);
                    c:[type=="$pcr7"] => issue(claim=c);
                    c:[type=="$pcr8"] => issue(claim=c);
                    c:[type=="$pcr9"] => issue(claim=c);
                    c:[type=="$pcr10"] => issue(claim=c);
                    c:[type=="$pcr11"] => issue(claim=c);
                    c:[type=="$pcr12"] => issue(claim=c);
                    c:[type=="$pcr13"] => issue(claim=c);
                    c:[type=="$pcr14"] => issue(claim=c);
                    c:[type=="$pcr15"] => issue(claim=c);
                    c:[type=="$pcr16"] => issue(claim=c);
                    c:[type=="$pcr17"] => issue(claim=c);
                    c:[type=="$pcr18"] => issue(claim=c);
                    c:[type=="$pcr19"] => issue(claim=c);
                    c:[type=="$pcr20"] => issue(claim=c);
                    c:[type=="$pcr21"] => issue(claim=c);
                    c:[type=="$pcr22"] => issue(claim=c);
                    c:[type=="$pcr23"] => issue(claim=c);
                };)";
        pResult = Buffer::Create(
            defaultAzureGuestAttestationPolicy,
            sizeof(defaultAzureGuestAttestationPolicy),
            false);
        break;
    }

    case TrustedExecutionEnvironmentKind::SevSnpVm:
    {
        static constexpr const uint8_t defaultSevSnpVmAttestationPolicy[] =
            "version= 1.0;"
            "authorizationrules"
            "{"
            "=> permit();"
            "};"
            "issuancerules"
            "{"
            "c:[type==\"$familyId\"] => issue(type=\"familyId\", value=c.value);"
            "c:[type==\"$imageId\"] => issue(type=\"imageId\", value=c.value);"
            "c:[type==\"$launchmeasurement\"] => issue(type=\"launchmeasurement\", value=c.value);"
            "c:[type==\"$hostdata\"] => issue(type=\"hostdata\", value=c.value);"
            "c:[type==\"$reportdata\"] => issue(type=\"reportdata\", value=c.value);"
            "c:[type==\"$reportid\"] => issue(type=\"reportid\", value=c.value);"
            "c:[type==\"$guestsvn\"] => issue(type=\"guestsvn\", value=c.value);"
            "c:[type==\"$vmpl\"] => issue(type=\"vmpl\", value=c.value);"
            "c:[type==\"$policy\"] => issue(type=\"policy\", value=c.value);"
            "c:[type==\"$tcbversion\"] => issue(type=\"tcbversion\", value=c.value);"
            "c:[type==\"$platforminfo\"] => issue(type=\"platforminfo\", value=c.value);"
            "c:[type==\"$idkeydigest\"] => issue(type=\"idkeydigest\", value=c.value);"
            "c:[type==\"$authorkeydigest\"] => issue(type=\"authorkeydigest\", value=c.value);"
            "c:[type==\"$tee\"] => issue(type=\"tee\", value=c.value);"
            "};";
        pResult = Buffer::Create(
            defaultSevSnpVmAttestationPolicy,
            sizeof(defaultSevSnpVmAttestationPolicy),
            false);
        break;
    }

    default:
        break;
    }

    return pResult;
}


_Use_decl_annotations_
errno_t VerifyQuoteMatchesData(
    const IQuote& quote,
    const Buffer& enclaveSuppliedData,
    const Buffer& nonce)
{
    std::unique_ptr<Buffer> pEnclaveSuppliedDataHash;
    std::unique_ptr<SecureHash> pHash;

    pHash = PAL().CreateSecureHash();

    if (!enclaveSuppliedData.IsEmpty())
    {
        pEnclaveSuppliedDataHash = pHash->HashAndFinish(enclaveSuppliedData);
    }
    else
    {
        pEnclaveSuppliedDataHash = Buffer::Create(pHash->GetHashLength());
    }

    if (!nonce.IsEmpty())
    {
        pHash = PAL().CreateSecureHash();
        pHash->HashAndContinue(*pEnclaveSuppliedDataHash);
        pEnclaveSuppliedDataHash = pHash->HashAndFinish(nonce);
    }

    RETURN_IF_FALSE(EBADQUOTECOLLATERAL, (*pEnclaveSuppliedDataHash == quote.GetEnclaveSuppliedDataDigest()));

    return EOK;
}

_Use_decl_annotations_
errno_t InitializeGlobalState(
    TrustedExecutionEnvironmentKind currentPlatform)
{
    constexpr uint32_t cMaxNodes = 64;

    std::unique_ptr<SrwLock> pLock;
    bool successReturn = false;
    auto cleanup(wilcopy::scope_exit([&] {if (!successReturn) { CleanupGlobalState(); }}));

    std::shared_ptr<Pal> pPal;

    pPal = SgxPal::Create();

    std::shared_ptr<WinQuoteProcessor> pWinQuoteProcessor;
    RETURN_IF_ERRNO_FAILED(WinQuoteProcessor::Create(
        *pPal,
        &pWinQuoteProcessor));

    std::shared_ptr<SgxQuoteProcessor> pSgxQuoteProcessor;
    RETURN_IF_ERRNO_FAILED(SgxQuoteProcessor::Create(
        *pPal,
        false,
        &pSgxQuoteProcessor));

    std::shared_ptr<SgxQuoteProcessor> pOpenEnclaveQuoteProcessor;
    RETURN_IF_ERRNO_FAILED(SgxQuoteProcessor::Create(
        *pPal,
        true,
        &pOpenEnclaveQuoteProcessor));

    std::shared_ptr<CyResQuoteProcessor> pCyResQuoteProcessor;
    RETURN_IF_ERRNO_FAILED(CyResQuoteProcessor::Create(
        *pPal,
        &pCyResQuoteProcessor));

    std::shared_ptr<VSMQuoteProcessor> pVSMQuoteProcessor;
    RETURN_IF_ERRNO_FAILED(VSMQuoteProcessor::Create(
        *pPal,
        &pVSMQuoteProcessor));

    std::shared_ptr<AzureGuestQuoteProcessor> pAzureGuestQuoteProcessor;
    RETURN_IF_ERRNO_FAILED(AzureGuestQuoteProcessor::Create(
        *pPal,
        &pAzureGuestQuoteProcessor));

    std::shared_ptr<SevSnpVmQuoteProcessor> pSevSnpVmQuoteProcessor;
    RETURN_IF_ERRNO_FAILED(SevSnpVmQuoteProcessor::Create(
        *pPal,
        &pSevSnpVmQuoteProcessor));

    std::vector<std::shared_ptr<QuoteProcessor::IQuoteProcessor>> quoteProcessors(static_cast<size_t>(TrustedExecutionEnvironmentKind::MaxTeeKinds));

    quoteProcessors[static_cast<uint32_t>(TrustedExecutionEnvironmentKind::Windows)] = pWinQuoteProcessor;
    quoteProcessors[static_cast<uint32_t>(TrustedExecutionEnvironmentKind::SgxEnclave)] = pSgxQuoteProcessor;
    quoteProcessors[static_cast<uint32_t>(TrustedExecutionEnvironmentKind::OpenEnclave)] = pOpenEnclaveQuoteProcessor;
    quoteProcessors[static_cast<uint32_t>(TrustedExecutionEnvironmentKind::CyResComponent)] = pCyResQuoteProcessor;
    quoteProcessors[static_cast<uint32_t>(TrustedExecutionEnvironmentKind::VSMEnclave)] = pVSMQuoteProcessor;
    quoteProcessors[static_cast<uint32_t>(TrustedExecutionEnvironmentKind::AzureGuest)] = pAzureGuestQuoteProcessor;;
    quoteProcessors[static_cast<uint32_t>(TrustedExecutionEnvironmentKind::SevSnpVm)] = pSevSnpVmQuoteProcessor;;

    RETURN_IF_FALSE(EASSERT, (currentPlatform == TrustedExecutionEnvironmentKind::Windows || currentPlatform == TrustedExecutionEnvironmentKind::SgxEnclave));
    g_currentPlatform = currentPlatform;
    g_pPal = pPal;

    // Move the quote processors to local storage.
    g_QuoteProcessors = std::move(quoteProcessors);

    RETURN_IF_ERRNO_FAILED(ItemCollection<Enclave>::Create(
        cMaxNodes,
        &g_pEnclaves));

    successReturn = true;

    return EOK;
}

void
CleanupGlobalState()
{
    g_pPal.reset();
    g_QuoteProcessors.clear();
    g_pEnclaves.reset();
}

//  Retrieve a value from global state.
_Use_decl_annotations_
void
GetGlobalStateValue(
    const char *stateKey,
    EnclaveShared::Buffer &stateData)
{
    HostMarshalledBlob stateBlob(true);

    GetGlobalStateOcall(stateKey, &stateBlob);
    if((stateBlob._pb == nullptr) || (stateBlob._cb == 0))
    {
        stateData = EnclaveShared::Buffer::Empty();
    }
    else
    {
        auto localStateData = Buffer::Create(stateBlob._pb, stateBlob._cb, false);
        stateData = std::move(*localStateData);
    }
}