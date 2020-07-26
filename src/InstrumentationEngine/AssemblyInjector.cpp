// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "stdafx.h"

#include "AssemblyInjector.h"
#include "Util.h"
#ifdef _WINDOWS_
#include <metahost.h>
#endif

/* This code transfers metadata and code from a source assembly to a target assembly. The source assembly must be loaded
enough to provide IMetaDataImport and a memory mapped image, but it need not be executable.
The target assembly should be loaded within the runtime and ready for modification by the profiler APIs.
The algorithm starts in ImportAll() using all the TypeDefs and CAs as a set of roots for graph exploration.
From the types we branch out to methods, fields, base types, code bodies, signatures and tokens in that code, etc.
As we traverse the metadata amd signatures we cache the translated results both for better
performance and to eliminate infinite recursion. It is possible that the assembly has content in it that
is never reached by the graph traversal in which case it won't Imported. The content may have been
superfluous for execution purposes, or if it does matter then we should adjust the set of roots in the graph traversal to include it.
*/

MicrosoftInstrumentationEngine::AssemblyInjector::AssemblyInjector(_In_ ICorProfilerInfo2* pProfilerInfo,
    _In_ IMetaDataImport2* pSourceImport,
    _In_ const LPCBYTE pSourceImageBaseAddress,
    _In_ DWORD sourceImageSize,
    _In_ MappingKind mapping,
    _In_ IMetaDataImport2* pTargetImport,
    _In_ IMetaDataEmit2* pTargetEmit,
    _In_ ModuleID pTargetImage,
    _In_ IMethodMalloc* pTargetMethodMalloc) : m_pProfilerInfo(pProfilerInfo),
        m_pSourceImport(pSourceImport),
        m_pSourceImageBaseAddress(pSourceImageBaseAddress),
        m_sourceImageSize(sourceImageSize),
        m_mapping(mapping),
        m_pTargetImport(pTargetImport),
        m_pTargetEmit(pTargetEmit),
        m_pTargetImage(pTargetImage),
        m_pTargetMethodMalloc(pTargetMethodMalloc)
{
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportAll(bool importCustomAttributes)
{
    HRESULT hr = S_OK;

    IfFalseRet(m_pProfilerInfo != nullptr, E_FAIL);
    IfFalseRet(m_pSourceImport != nullptr, E_FAIL);
    IfFalseRet(m_pSourceImageBaseAddress != nullptr, E_FAIL);
    IfFalseRet(m_pTargetImport != nullptr, E_FAIL);
    IfFalseRet(m_pTargetEmit != nullptr, E_FAIL);
    IfFalseRet(m_pTargetMethodMalloc != nullptr, E_FAIL);

    CLogging::LogDumpMessage(_T("<?xml version=\"1.0\"?>\r\n<ImportModule>\r\n"));

    IfFailRet(ReadModuleHeaders());
    IfFailRet(EnsureSourceMetadataReader());
    CMetadataEnumCloser<IMetaDataImport2> spHEnSourceTypeDefs(m_pSourceImport, nullptr);

    mdTypeDef typeDef = mdTypeDefNil;
    ULONG cTokens = 0;
    while (S_OK == (hr = m_pSourceImport->EnumTypeDefs(spHEnSourceTypeDefs.Get(), &typeDef, 1, &cTokens)))
    {
        mdTypeDef targetTypeDef = mdTypeDefNil;
        IfFailRet(ImportTypeDef(typeDef, &targetTypeDef));
    }
    IfFailRet(hr);

    if (importCustomAttributes)
    {
        CMetadataEnumCloser<IMetaDataImport2> spHEnSourceAttributes(m_pSourceImport, nullptr);
        mdCustomAttribute curSourceCustomAttribute = mdCustomAttributeNil;
        while (S_OK == (hr = m_pSourceImport->EnumCustomAttributes(spHEnSourceAttributes.Get(), mdTokenNil, mdTokenNil, &curSourceCustomAttribute, 1, &cTokens)))
        {
            mdCustomAttribute targetCustomAttribute = mdCustomAttributeNil;
            IfFailRet(ImportCustomAttribute(curSourceCustomAttribute, &targetCustomAttribute));
        }
        IfFailRet(hr);
    }

    CLogging::LogDumpMessage(_T("</ImportModule>\r\n"));

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportType(const WCHAR* typeName)
{
    HRESULT hr = S_OK;

    IfFalseRet(m_pProfilerInfo != nullptr, E_FAIL);
    IfFalseRet(m_pSourceImageBaseAddress != nullptr, E_FAIL);
    IfFalseRet(m_pTargetImport != nullptr, E_FAIL);
    IfFalseRet(m_pTargetEmit != nullptr, E_FAIL);
    IfFalseRet(m_pTargetMethodMalloc != nullptr, E_FAIL);

    CLogging::LogDumpMessage(_T("<?xml version=\"1.0\"?>\r\n<ImportType>\r\n"));

    IfFailRet(ReadModuleHeaders());
    IfFailRet(EnsureSourceMetadataReader());
    mdTypeDef typeDef = mdTypeDefNil;
    ULONG cTokens = 0;
    IfFailRet(m_pSourceImport->FindTypeDefByName(typeName, mdTypeDefNil, &typeDef));
    mdTypeDef targetTypeDef = mdTypeDefNil;
    IfFailRet(ImportTypeDef(typeDef, &targetTypeDef));

    CLogging::LogDumpMessage(_T("</ImportType>\r\n"));

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ReadModuleHeaders()
{
    HRESULT hr = S_OK;
    CLogging::LogMessage(_T("Begin AssemblyInjector::ReadModuleHeaders"));

    if (m_pSourceImageBaseAddress == NULL)
    {
        CLogging::LogError(_T("AssemblyInjector::ReadModuleHeaders - No load address"));
        return E_FAIL;
    }

    IMAGE_DOS_HEADER const* pDOSHeader = reinterpret_cast<IMAGE_DOS_HEADER const*>(m_pSourceImageBaseAddress);

    // Check for DOS signature
    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        CLogging::LogError(_T("AssemblyInjector::ReadModuleHeaders - Incorrect dos header magic number"));
        return E_FAIL;
    }

    // Check for NT signature (signature is at the same offset for both 32-bit and 64-bit PEs)
    IMAGE_NT_HEADERS32 const* pNTHeader = reinterpret_cast<IMAGE_NT_HEADERS32 const*>(m_pSourceImageBaseAddress + pDOSHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        CLogging::LogError(_T("AssemblyInjector::ReadModuleHeaders - Incorrect NT Signature"));
        return E_FAIL;
    }

    // The magic field is the same offset for both 32-bit and 64-bit PEs
    bool bIs64bit = pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    // The .NET header is stored in the optional header's data directory, so we need to use the right one
    IMAGE_DATA_DIRECTORY const* pDirectory = 0;
    if (bIs64bit)
    {
        pDirectory = &reinterpret_cast<IMAGE_NT_HEADERS64 const*>(pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COMHEADER];
        m_pbSectionStart = (LPCBYTE) & (pNTHeader->OptionalHeader) + sizeof(IMAGE_OPTIONAL_HEADER64);
    }
    else
    {
        pDirectory = &pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COMHEADER];
        m_pbSectionStart = (LPCBYTE) & (pNTHeader->OptionalHeader) + sizeof(IMAGE_OPTIONAL_HEADER32);
    }

    m_numSections = pNTHeader->FileHeader.NumberOfSections;

    
    // Get the COR header
    IMAGE_COR20_HEADER const* pCLRHeader = 0;
    if (pDirectory->Size > 0 && pDirectory->VirtualAddress)
    {
        LPCBYTE pbCLRHeader;
        IfFailRet(ResolveRva(pDirectory->VirtualAddress, &pbCLRHeader));
        pCLRHeader = reinterpret_cast<IMAGE_COR20_HEADER const*>(pbCLRHeader);
    }
    else
    {
        CLogging::LogError(_T("AssemblyInjector::ReadModuleHeaders - No CLR header. Why did the CLR send this module?"));
        return E_FAIL;
    }

    m_pCorHeader = pCLRHeader;

    CLogging::LogMessage(_T("End AssemblyInjector::ReadModuleHeaders"));
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ResolveRva(_In_ DWORD rva, _Out_ LPCBYTE* ppbResolvedAddress)
{
    HRESULT hr = S_OK;

    IfNullRet(ppbResolvedAddress);
    *ppbResolvedAddress = nullptr;

    if (m_pSourceImageBaseAddress == 0)
    {
        return E_NOTIMPL;
    }

    IfNullRet(m_pbSectionStart);

    if (m_mapping == MappingKind_Flat)
    {

        // Module was loaded using "Flat" layout (aka. on-disk format).

        if (m_pSourceImageBaseAddress + rva < m_pbSectionStart)
        {
            // The RVA belongs to one of the image headers, not to one of the sections, so the
            // RVA and the flat offset are the same.
            *ppbResolvedAddress = m_pSourceImageBaseAddress + rva;
            return S_OK;
        }

        // RVA is inside a section.
        const IMAGE_SECTION_HEADER* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(m_pbSectionStart);
        for (int i = 0; i < m_numSections; i++)
        {
            IMAGE_SECTION_HEADER section = sections[i];
            if (section.VirtualAddress <= rva && rva < section.VirtualAddress + section.SizeOfRawData)
            {
                // Beginning of section is at offset "PointerToRawData" from pbImage, after
                // that point the section is laid out contiguously so work out how far RVA is
                // from beginning of section.
                DWORD offset = section.PointerToRawData + (rva - section.VirtualAddress);
                if (offset > m_sourceImageSize) {
                    return E_FAIL; // RVA references data that is outside the byte array we were provided
                }
                *ppbResolvedAddress = m_pSourceImageBaseAddress + offset;
                return S_OK;
            }
        }

        return E_POINTER;
    }

    // Module was loaded using "Mapped" layout (aka. in-memory format) so we can treat all
    // virtual address read from headers as offsets from pbImage.
    *ppbResolvedAddress = m_pSourceImageBaseAddress + rva;
    return S_OK;
}

typedef HRESULT(*MetaDataGetDispenserFunc)(REFCLSID rclsid, REFIID riid, LPVOID FAR* ppv);

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::EnsureSourceMetadataReader()
{
    if (m_pSourceImport != nullptr)
    {
        return S_OK;
    }

    HRESULT hr = S_OK;
    DWORD metadataRVA = m_pCorHeader->MetaData.VirtualAddress;
    LPCBYTE pMetadata = nullptr;
    IfFailRet(ResolveRva(metadataRVA, &pMetadata));
    if (m_mapping == MappingKind_Flat &&
        ((m_pCorHeader->MetaData.Size > m_sourceImageSize) ||
            ((DWORD)(pMetadata - m_pSourceImageBaseAddress) > (m_sourceImageSize - m_pCorHeader->MetaData.Size))))
    {
        return E_FAIL; // buffer isn't big enough to hold metadata range
    }

    ATL::CComPtr<IMetaDataDispenserEx> pDisp;
#ifdef _WINDOWS_
    /* TODO: if we knew coreclr was already loaded we could get the metadata dispenser from there
     * to avoid the perf overhead of loading clr.dll
    HMODULE hCoreClr = LoadLibrary(L"coreclr.dll");
    if (hCoreClr != 0)
    {
        MetaDataGetDispenserFunc pMetaDataGetDispenser = nullptr;
        pMetaDataGetDispenser = (MetaDataGetDispenserFunc)GetProcAddress(hCoreClr, "MetaDataGetDispenser");
        if (pMetaDataGetDispenser != nullptr)
        {
            pMetaDataGetDispenser(CLSID_CorMetaDataDispenser, IID_IMetaDataDispenserEx, (void**)&pDisp);
        }
    }
    else // use clr.dll
    */
    {
        ATL::CComPtr<ICLRMetaHost> pMetaHost;
        ATL::CComPtr<ICLRRuntimeInfo> pRuntime;
        IfFailRet(CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, reinterpret_cast<void**>(&pMetaHost)));
        IfFailRet(pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, reinterpret_cast<void**>(&pRuntime)));
        IfFailRet(pRuntime->GetInterface(CLSID_CorMetaDataDispenser, IID_IMetaDataDispenserEx, reinterpret_cast<void**>(&pDisp)));
    }
#else
    // NYI: On other OSes we could use coreclr's exported MetaDataGetDispenser API
    return E_FAIL;
#endif

    IfFailRet(pDisp->OpenScopeOnMemory(pMetadata, m_pCorHeader->MetaData.Size, ofReadOnly, IID_IMetaDataImport2, reinterpret_cast<IUnknown**>(&m_pSourceImport)));
    return S_OK;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportTypeDef(_In_ mdTypeDef sourceTypeDef, _Out_ mdTypeDef *pTargetTypeDef)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceTypeDef != mdTokenNil && sourceTypeDef != mdTypeDefNil, E_FAIL);

    TokenMap::const_iterator itr = m_typeDefMap.find(sourceTypeDef);
    if (itr != m_typeDefMap.end())
    {
        *pTargetTypeDef = itr->second;
        return S_OK;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportTypeDef", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceTypeDef);

    WCHAR szTypeDef[MAX_NAME] = { 0 };
    ULONG cchTypeDef = 0;
    DWORD dwTypeDefFlags = 0;
    mdToken tkExtends = mdTokenNil;
    IfFailRet(m_pSourceImport->GetTypeDefProps(sourceTypeDef, szTypeDef, _countof(szTypeDef), &cchTypeDef, &dwTypeDefFlags, &tkExtends));

    dumpLogHelper.WriteStringNode(L"Name", szTypeDef);

    mdToken targetExtends = mdTokenNil;
    IfFailRet(ConvertToken(tkExtends, &targetExtends));

    ATL::CAutoVectorPtr<mdInterfaceImpl> pInterfaceImpls;
    ATL::CAutoVectorPtr<mdToken> pImplements;
    //On x86 machines this EnumInterfaceImpls returns nullptr enum and CountEnum will return 0xcccccccc as ulCount.
    //Thus we need to validate the Enum returned S_OK, not S_FALSE
    CMetadataEnumCloser<IMetaDataImport2> spHCorEnum(m_pSourceImport, nullptr);
    IfFailRet(hr = m_pSourceImport->EnumInterfaceImpls(spHCorEnum.Get(), sourceTypeDef, nullptr, 0, nullptr));
    if (hr == S_OK)
    {
        ULONG ulCount = 0;
        IfFailRet(hr = m_pSourceImport->CountEnum(spHCorEnum.Get(), &ulCount));
        if (hr == S_OK)
        {
            if (ulCount != 0)
            {
                pInterfaceImpls.Attach(new mdInterfaceImpl[ulCount]);
                spHCorEnum.Reset(nullptr);
                IfFailRet(m_pSourceImport->EnumInterfaceImpls(spHCorEnum.Get(), sourceTypeDef, pInterfaceImpls, ulCount, nullptr));
                pImplements.Attach(new mdToken[ulCount + 1]);
                for (ULONG i = 0; i < ulCount; i++)
                {
                    IfFailRet(m_pSourceImport->GetInterfaceImplProps(pInterfaceImpls[i], nullptr, &(pImplements[i])));
                    IfFailRet(ConvertToken(pImplements[i], &(pImplements[i])));
                }
                pImplements[ulCount] = mdTokenNil;
            }
        }
    }

    if (!IsTdNested(dwTypeDefFlags))
    {
        //find matching class by name
        HRESULT hrFound = CLDB_E_RECORD_NOTFOUND;
        if (szTypeDef[0] == MERGE_TYPE_PREFIX)
        {
            hrFound = m_pTargetImport->FindTypeDefByName(szTypeDef + 1, mdTokenNil, pTargetTypeDef);
            dumpLogHelper.WriteStringNode(L"MergedToType", szTypeDef + 1);
        }

        if (hrFound == CLDB_E_RECORD_NOTFOUND)
        {
            IfFailRet(m_pTargetEmit->DefineTypeDef(szTypeDef,
                dwTypeDefFlags,
                targetExtends,
                pImplements,
                pTargetTypeDef));
        }
        else
        {
            IfFailRet(hrFound);
        }
    }
    else
    {
        mdTypeDef sourceEnclosingTypeDef = mdTypeDefNil;
        mdTypeDef targetEnclosingTypeDef = mdTypeDefNil;
        IfFailRet(m_pSourceImport->GetNestedClassProps(sourceTypeDef, &sourceEnclosingTypeDef));
        IfFailRet(ConvertToken(sourceEnclosingTypeDef, &targetEnclosingTypeDef));

        //find matching class by name
        HRESULT hrFound = CLDB_E_RECORD_NOTFOUND;
        if (szTypeDef[0] == MERGE_TYPE_PREFIX)
        {
            hrFound = m_pTargetImport->FindTypeDefByName(szTypeDef + 1, targetEnclosingTypeDef, pTargetTypeDef);
            dumpLogHelper.WriteStringNode(L"MergedToType", szTypeDef + 1);
        }

        if (hrFound == CLDB_E_RECORD_NOTFOUND)
        {
            IfFailRet(m_pTargetEmit->DefineNestedType(szTypeDef,
                dwTypeDefFlags,
                targetExtends,
                pImplements,
                targetEnclosingTypeDef,
                pTargetTypeDef));
        }
        else
        {
            IfFailRet(hrFound);
        }
    }

    m_typeDefMap[sourceTypeDef] = *pTargetTypeDef;
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetTypeDef);

    CMetadataEnumCloser<IMetaDataImport2> spHEnSourceFields(m_pSourceImport, nullptr);
    mdFieldDef curSourceField = mdFieldDefNil;
    ULONG cTokens = 0;
    while (S_OK == (hr = m_pSourceImport->EnumFields(spHEnSourceFields.Get(), sourceTypeDef, &curSourceField, 1, &cTokens)))
    {
        mdFieldDef targetFieldDef = mdFieldDefNil;
        IfFailRet(ImportFieldDef(curSourceField, &targetFieldDef));
    }
    IfFailRet(hr);

    spHCorEnum.Reset(nullptr);
    mdMethodDef curSourceMethod = mdMethodDefNil;
    while (S_OK == (hr = m_pSourceImport->EnumMethods(spHCorEnum.Get(), sourceTypeDef, &curSourceMethod, 1, &cTokens)))
    {
        mdMethodDef targetMethodDef = mdMethodDefNil;
        IfFailRet(ImportMethodDef(curSourceMethod, &targetMethodDef));
    }
    IfFailRet(hr);

    spHCorEnum.Reset(nullptr);
    mdProperty curSourceProperty = mdPropertyNil;
    while (S_OK == (hr = m_pSourceImport->EnumProperties(spHCorEnum.Get(), sourceTypeDef, &curSourceProperty, 1, &cTokens)))
    {
        mdProperty targetProperty = mdPropertyNil;
        IfFailRet(ImportProperty(curSourceProperty, &targetProperty));
    }
    IfFailRet(hr);

    spHCorEnum.Reset(nullptr);
    mdEvent curSourceEvent = mdEventNil;
    while (S_OK == (hr = m_pSourceImport->EnumEvents(spHCorEnum.Get(), sourceTypeDef, &curSourceEvent, 1, &cTokens)))
    {
        mdEvent targetEvent = mdEventNil;
        IfFailRet(ImportEvent(curSourceEvent, &targetEvent));
    }
    IfFailRet(hr);

    spHCorEnum.Reset(nullptr);
    mdToken sourceImplementationMethod = mdTokenNil;
    mdToken sourceDeclarationMethod = mdTokenNil;
    while (S_OK == (hr = m_pSourceImport->EnumMethodImpls(spHCorEnum.Get(), sourceTypeDef, &sourceImplementationMethod, &sourceDeclarationMethod, 1, &cTokens)))
    {
        IfFailRet(ImportMethodImpl(sourceTypeDef, sourceImplementationMethod, sourceDeclarationMethod));
    }
    IfFailRet(hr);

    if ((dwTypeDefFlags & tdExplicitLayout) != 0)
    {
        ULONG cFieldOffset = 0;
        IfFailRet(m_pSourceImport->GetClassLayout(sourceTypeDef, nullptr, nullptr, 0, &cFieldOffset, nullptr));
        ATL::CAutoVectorPtr<COR_FIELD_OFFSET> fieldOffsets(new COR_FIELD_OFFSET[cFieldOffset + 1]);

        DWORD dwPackSize = 0;
        ULONG ulClassSize = 0;
        IfFailRet(m_pSourceImport->GetClassLayout(sourceTypeDef, &dwPackSize, fieldOffsets, cFieldOffset, nullptr, &ulClassSize));
        for (ULONG i = 0; i < cFieldOffset; i++)
        {
            IfFailRet(ImportFieldDef(fieldOffsets[i].ridOfField, &(fieldOffsets[i].ridOfField)));
        }
        fieldOffsets[cFieldOffset].ridOfField = mdFieldDefNil;
        fieldOffsets[cFieldOffset].ulOffset = 0;
        IfFailRet(m_pTargetEmit->SetClassLayout(*pTargetTypeDef, dwPackSize, fieldOffsets, ulClassSize));
    }

    spHCorEnum.Reset(nullptr);
    mdGenericParam curSourceGenericParam = mdGenericParamNil;
    while (S_OK == (hr = m_pSourceImport->EnumGenericParams(spHCorEnum.Get(), sourceTypeDef, &curSourceGenericParam, 1, nullptr)))
    {
        mdGenericParam targetGenericParam = mdGenericParamNil;
        IfFailRet(ImportGenericParam(curSourceGenericParam, &targetGenericParam));
    }
    IfFailRet(hr);

    return S_OK;
}


HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportTypeRef(_In_ mdTypeRef sourceTypeRef, _Out_ mdToken *pTargetTypeRef)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceTypeRef != mdTokenNil && sourceTypeRef != mdTypeRefNil, E_FAIL);

    TokenMap::const_iterator itr = m_typeRefMap.find(sourceTypeRef);
    if (itr != m_typeRefMap.end())
    {
        *pTargetTypeRef = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportTypeDef", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceTypeRef);

    mdToken tkResolutionScope = mdTokenNil;
    WCHAR szName[MAX_NAME] = { 0 };
    ULONG cchName = 0;
    IfFailRet(m_pSourceImport->GetTypeRefProps(sourceTypeRef,
        &tkResolutionScope,
        szName,
        _countof(szName),
        &cchName));

    dumpLogHelper.WriteStringNode(L"Name", szName);

    if (TypeFromToken(tkResolutionScope) == mdtModuleRef)
    {
        //FAILURE(L"TypeRef in module scope NYI");
        return E_NOTIMPL;
    }

    mdToken targetAssemblyScope = mdTokenNil;
    IfFailRet(ConvertToken(tkResolutionScope, &targetAssemblyScope));
    if ((TypeFromToken(targetAssemblyScope) == mdtAssembly && TypeFromToken(tkResolutionScope) == mdtAssemblyRef) ||
        (TypeFromToken(targetAssemblyScope) == mdtTypeDef))
    {
        mdToken tkEnclosingClass = mdTokenNil;
        if (TypeFromToken(targetAssemblyScope) == mdtTypeDef)
        {
            tkEnclosingClass = targetAssemblyScope;
        }
        IfFailRet(m_pTargetImport->FindTypeDefByName(szName, tkEnclosingClass, pTargetTypeRef));
    }
    else
    {
        HRESULT hr2 = m_pTargetImport->FindTypeRef(targetAssemblyScope, szName, pTargetTypeRef);
        if (FAILED(hr2) && hr2 != CLDB_E_RECORD_NOTFOUND)
        {
            return hr2;
        }
        if (*pTargetTypeRef == mdTypeRefNil || *pTargetTypeRef == mdTokenNil)
        {
            IfFailRet(m_pTargetEmit->DefineTypeRefByName(targetAssemblyScope, szName, pTargetTypeRef));
        }
    }
    m_typeRefMap[sourceTypeRef] = *pTargetTypeRef;
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetTypeRef);

    return hr;
}


HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportAssemblyRef(_In_ mdAssemblyRef sourceAssemblyRef, _Out_ mdToken *pTargetAssemblyScope)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceAssemblyRef != mdTokenNil && sourceAssemblyRef != mdAssemblyRefNil, E_FAIL);

    TokenMap::const_iterator itr = m_assemblyRefMap.find(sourceAssemblyRef);
    if (itr != m_assemblyRefMap.end())
    {
        *pTargetAssemblyScope = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportAssemblyRef", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceAssemblyRef);


    ATL::CComPtr<IMetaDataAssemblyImport> pAssemblyImport;
    IfFailRet(m_pSourceImport->QueryInterface(IID_IMetaDataAssemblyImport, reinterpret_cast<void**>(&pAssemblyImport)));

    ATL::CComPtr<IMetaDataAssemblyImport> pTargetAssemblyImport;
    IfFailRet(m_pTargetImport->QueryInterface(IID_IMetaDataAssemblyImport, reinterpret_cast<void**>(&pTargetAssemblyImport)));

    const void* pbPublicKeyOrToken = nullptr;
    ULONG cbPublicKeyOrToken = 0;
    WCHAR szName[MAX_NAME] = { 0 };
    ULONG cchName = 0;
    WCHAR szLocale[MAX_NAME] = { 0 };
    ASSEMBLYMETADATA assemblyMetadata = { 0 };
    assemblyMetadata.cbLocale = MAX_NAME;
    assemblyMetadata.szLocale = szLocale;
    const void* pbHashValue = nullptr;
    ULONG cbHashValue = 0;
    DWORD dwAssemblyRefFlags = 0;
    IfFailRet(pAssemblyImport->GetAssemblyRefProps(sourceAssemblyRef,
        &pbPublicKeyOrToken,
        &cbPublicKeyOrToken,
        szName,
        _countof(szName),
        &cchName,
        &assemblyMetadata,
        &pbHashValue,
        &cbHashValue,
        &dwAssemblyRefFlags));

    CMetadataEnumCloser<IMetaDataAssemblyImport> spHCorEnumTarget(pTargetAssemblyImport, nullptr);

    mdAssemblyRef cur = mdAssemblyRefNil;
    ULONG cTokens = 0;
    while (S_OK == (hr = pTargetAssemblyImport->EnumAssemblyRefs(spHCorEnumTarget.Get(), &cur, 1, &cTokens)))
    {
        const void* pbPublicKeyOrTokenTarget = nullptr;
        ULONG cbPublicKeyOrTokenTarget = 0;
        WCHAR szNameTarget[MAX_NAME] = { 0 };
        ULONG cchNameTarget = 0;
        const void* pbHashValueTarget = nullptr;
        ULONG cbHashValueTarget = 0;
        DWORD dwAssemblyRefFlagsTarget = 0;
        IfFailRet(pTargetAssemblyImport->GetAssemblyRefProps(cur,
            &pbPublicKeyOrTokenTarget,
            &cbPublicKeyOrTokenTarget,
            szNameTarget,
            _countof(szName),
            &cchNameTarget,
            nullptr,
            &pbHashValueTarget,
            &cbHashValueTarget,
            &dwAssemblyRefFlagsTarget));

        if (wcscmp(szName, szNameTarget) == 0)
        {
            break;
        }
    }

    IfFailRet(hr);
    if (hr == S_OK)
    {
        *pTargetAssemblyScope = cur;
        m_assemblyRefMap[sourceAssemblyRef] = *pTargetAssemblyScope;
        dumpLogHelper.WriteStringNode(L"UseExistingRef", L"true");
        dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetAssemblyScope);
        return hr;
    }

    // didn't find a matching ref - perhaps the reference is to the assembly we are Importing within?
    mdAssembly targetAssembly = mdAssemblyNil;
    IfFailRet(pTargetAssemblyImport->GetAssemblyFromScope(&targetAssembly));

    const void* pbPublicKeyOrTokenTarget = nullptr;
    ULONG cbPublicKeyOrTokenTarget = 0;
    ULONG ulHashAlgIdTarget = 0;
    WCHAR szNameTarget[MAX_NAME] = { 0 };
    DWORD dwAssemblyFlagsTarget = 0;
    IfFailRet(pTargetAssemblyImport->GetAssemblyProps(targetAssembly,
        &pbPublicKeyOrTokenTarget,
        &cbPublicKeyOrTokenTarget,
        &ulHashAlgIdTarget,
        szNameTarget,
        _countof(szNameTarget),
        &cchName,
        nullptr,
        &dwAssemblyFlagsTarget));

    if (wcscmp(szName, szNameTarget) == 0)
    {
        *pTargetAssemblyScope = targetAssembly;
        m_assemblyRefMap[sourceAssemblyRef] = *pTargetAssemblyScope;
        dumpLogHelper.WriteStringNode(L"UseTarget", L"true");
        dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetAssemblyScope);
        return S_OK;
    }

    // maybe the reference is to a contract assembly which is ultimately implemented by the assembly we are Importing into
    // this is an ad-hoc list and isn't comprehensive
    if (wcscmp(L"mscorlib", szNameTarget) == 0)
    {
        if (wcscmp(szName, L"System.Runtime") == 0 ||
            wcscmp(szName, L"System.Collections") == 0 ||
            wcscmp(szName, L"System.Console") == 0 ||
            wcscmp(szName, L"System.Reflection") == 0
            )
        {
            *pTargetAssemblyScope = targetAssembly;
            m_assemblyRefMap[sourceAssemblyRef] = *pTargetAssemblyScope;
            dumpLogHelper.WriteStringNode(L"ContractAssembly", L"true");
            dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetAssemblyScope);
            return S_OK;
        }
    }

    ATL::CComPtr<IMetaDataAssemblyEmit> pTargetAssemblyEmit;
    IfFailRet(m_pTargetEmit->QueryInterface(IID_IMetaDataAssemblyEmit, reinterpret_cast<void**>(&pTargetAssemblyEmit)));
    IfFailRet(pTargetAssemblyEmit->DefineAssemblyRef(
        pbPublicKeyOrToken,
        cbPublicKeyOrToken,
        szName,
        &assemblyMetadata,
        pbHashValue,
        cbHashValue,
        dwAssemblyRefFlags,
        pTargetAssemblyScope));

    m_assemblyRefMap[sourceAssemblyRef] = *pTargetAssemblyScope;
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetAssemblyScope);
    return S_OK;
}
HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportFieldDef(_In_ mdFieldDef sourceFieldDef, _Out_ mdFieldDef *pTargetFieldDef)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceFieldDef != mdTokenNil && sourceFieldDef != mdFieldDefNil, E_FAIL);

    TokenMap::const_iterator itr = m_fieldDefMap.find(sourceFieldDef);
    if (itr != m_fieldDefMap.end())
    {
        *pTargetFieldDef = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportFieldDef", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceFieldDef);


    mdTypeDef tkClass = mdTypeDefNil;
    WCHAR szName[MAX_NAME] = { 0 };
    ULONG cchName = 0;
    DWORD dwAttr = 0;
    PCCOR_SIGNATURE pvSigBlob = nullptr;
    ULONG cbSigBlob = 0;
    DWORD dwCPlusTypeFlag = 0;
    UVCP_CONSTANT pValue = nullptr;
    ULONG cchValue = 0;
    IfFailRet(m_pSourceImport->GetFieldProps(sourceFieldDef,
        &tkClass,
        szName,
        _countof(szName),
        &cchName,
        &dwAttr,
        &pvSigBlob,
        &cbSigBlob,
        &dwCPlusTypeFlag,
        &pValue,
        &cchValue));

    dumpLogHelper.WriteStringNode(L"Name", szName);
    dumpLogHelper.WriteUlongNode(L"Class", tkClass);

    mdTypeDef targetTypeDef = mdTypeDefNil;
    IfFailRet(ImportTypeDef(tkClass, &targetTypeDef));
    IfFailRet(ConvertNonTypeSignatureCached(&pvSigBlob, &cbSigBlob));
    IfFailRet(m_pTargetEmit->DefineField(targetTypeDef,
        szName,
        dwAttr & ~(fdReservedMask&~(fdHasFieldRVA | fdRTSpecialName)),
        pvSigBlob,
        cbSigBlob,
        dwCPlusTypeFlag,
        pValue,
        cchValue,
        pTargetFieldDef));

    m_fieldDefMap[sourceFieldDef] = *pTargetFieldDef;

    if ((dwAttr & fdHasFieldMarshal) != 0)
    {
        PCCOR_SIGNATURE pvNativeType = nullptr;
        ULONG cbNativeType = 0;
        IfFailRet(m_pSourceImport->GetFieldMarshal(sourceFieldDef, &pvNativeType, &cbNativeType));
        IfFailRet(m_pTargetEmit->SetFieldMarshal(*pTargetFieldDef, pvNativeType, cbNativeType));
    }

    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetFieldDef);

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportMethodDef(_In_ mdMethodDef sourceMethodDef, _Out_ mdMethodDef *pTargetMethodDef)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceMethodDef != mdTokenNil && sourceMethodDef != mdMethodDefNil, E_FAIL);

    TokenMap::const_iterator itr = m_methodDefMap.find(sourceMethodDef);
    if (itr != m_methodDefMap.end())
    {
        *pTargetMethodDef = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportMethodDef", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceMethodDef);

    mdTypeDef tkClass = mdTypeDefNil;
    WCHAR szName[MAX_NAME] = { 0 };
    ULONG cchName = 0;
    DWORD dwAttr = 0;
    PCCOR_SIGNATURE pvSigBlob = nullptr;
    ULONG cbSigBlob = 0;
    ULONG ulCodeRVA = 0;
    DWORD dwImplFlags = 0;
    IfFailRet(m_pSourceImport->GetMethodProps(sourceMethodDef,
        &tkClass,
        szName,
        _countof(szName),
        &cchName,
        &dwAttr,
        &pvSigBlob,
        &cbSigBlob,
        &ulCodeRVA,
        &dwImplFlags));

    dumpLogHelper.WriteStringNode(L"Name", szName);
    dumpLogHelper.WriteUlongNode(L"Class", tkClass);

    mdTypeDef targetTypeDef = mdTypeDefNil;
    IfFailRet(ImportTypeDef(tkClass, &targetTypeDef));
    IfFailRet(ConvertNonTypeSignatureCached(&pvSigBlob, &cbSigBlob));

    //this type might already have method def if type was merged. Use existing methods in this situation
    HRESULT hrFound = m_pTargetImport->FindMethod(targetTypeDef, szName, pvSigBlob, cbSigBlob, pTargetMethodDef);
    if (hrFound == CLDB_E_RECORD_NOTFOUND)
    {
        IfFailRet(m_pTargetEmit->DefineMethod(targetTypeDef,
            szName,
            dwAttr,
            pvSigBlob,
            cbSigBlob,
            0,
            dwImplFlags,
            pTargetMethodDef));
    }
    else if (FAILED(hrFound))
    {
        IfFailRet(hrFound);
    }
    else
    {
        dumpLogHelper.WriteStringNode(L"UseExisting", L"true");
    }


    m_methodDefMap[sourceMethodDef] = *pTargetMethodDef;
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetMethodDef);


    CMetadataEnumCloser<IMetaDataImport2> spHCorEnum(m_pSourceImport, nullptr);
    mdParamDef curSourceParam = mdParamDefNil;
    while (S_OK == (hr = m_pSourceImport->EnumParams(spHCorEnum.Get(), sourceMethodDef, &curSourceParam, 1, nullptr)))
    {
        mdParamDef curTargetParam = mdParamDefNil;
        IfFailRet(ImportParam(curSourceParam, &curTargetParam));
    }
    IfFailRet(hr);

    if ((dwAttr & mdPinvokeImpl) != 0)
    {
        DWORD dwMappingFlags = 0;
        WCHAR szImportName[MAX_NAME] = { 0 };
        ULONG cchImportName = 0;
        mdModuleRef sourceImportDll = mdModuleRefNil;
        IfFailRet(m_pSourceImport->GetPinvokeMap(sourceMethodDef,
            &dwMappingFlags,
            szImportName,
            _countof(szImportName),
            &cchImportName,
            &sourceImportDll));

        mdModuleRef targetImportDll = mdModuleRefNil;
        IfFailRet(ImportModuleRef(sourceImportDll, &targetImportDll));
        IfFailRet(m_pTargetEmit->DefinePinvokeMap(*pTargetMethodDef, dwMappingFlags, szImportName, targetImportDll));
    }

    spHCorEnum.Reset(nullptr);
    mdGenericParam curSourceGenericParam = mdGenericParamNil;
    while (S_OK == (hr = m_pSourceImport->EnumGenericParams(spHCorEnum.Get(), sourceMethodDef, &curSourceGenericParam, 1, nullptr)))
    {
        mdGenericParam targetGenericParam = mdGenericParamNil;
        IfFailRet(ImportGenericParam(curSourceGenericParam, &targetGenericParam));
    }
    IfFailRet(hr);

    if (ulCodeRVA != 0)
    {
        LPCBYTE pSourceCode = nullptr;
        IfFailRet(ResolveRva(ulCodeRVA, &pSourceCode));
        IMAGE_COR_ILMETHOD_TINY* pSourceCodeTinyHeader = (IMAGE_COR_ILMETHOD_TINY*)pSourceCode;
        IMAGE_COR_ILMETHOD_FAT* pSourceCodeFatHeader = (IMAGE_COR_ILMETHOD_FAT*)pSourceCode;
        bool isTinyHeader = ((pSourceCodeTinyHeader->Flags_CodeSize & (CorILMethod_FormatMask >> 1)) == CorILMethod_TinyFormat);
        ULONG ilCodeSize = 0;
        ULONG headerSize = 0;
        ULONG ehClauseHeaderRVA = 0;
        IMAGE_COR_ILMETHOD_SECT_FAT* pFatEHHeader = nullptr;
        IMAGE_COR_ILMETHOD_SECT_SMALL* pSmallEHHeader = nullptr;
        ULONG totalCodeBlobSize = 0;
        if (isTinyHeader)
        {
            ilCodeSize = (((unsigned)pSourceCodeTinyHeader->Flags_CodeSize) >> (CorILMethod_FormatShift - 1));
            headerSize = sizeof(IMAGE_COR_ILMETHOD_TINY);
            totalCodeBlobSize = ilCodeSize + headerSize;
        }
        else
        {
            ilCodeSize = pSourceCodeFatHeader->CodeSize;
            // IMAGE_COR_ILMETHOD_FAT->Size represents size in DWords of this structure (currently 3) - see cor.h for details
            headerSize = pSourceCodeFatHeader->Size * 4;
            if ((pSourceCodeFatHeader->Flags & CorILMethod_MoreSects) == 0)
            {
                totalCodeBlobSize = ilCodeSize + headerSize;
            }
            else
            {
                // EH section starts at the 4 byte aligned address after the code
                ehClauseHeaderRVA = ((ulCodeRVA + headerSize + ilCodeSize - 1) & ~3) + 4;
                LPCBYTE pEHSectionHeader = nullptr;
                IfFailRet(ResolveRva(ehClauseHeaderRVA, &pEHSectionHeader));
                BYTE kind = *(BYTE*)pEHSectionHeader;
                ULONG dataSize = 0;
                if (kind & CorILMethod_Sect_FatFormat)
                {
                    pFatEHHeader = (IMAGE_COR_ILMETHOD_SECT_FAT*)pEHSectionHeader;
                    dataSize = pFatEHHeader->DataSize;
                }
                else
                {
                    pSmallEHHeader = (IMAGE_COR_ILMETHOD_SECT_SMALL*)pEHSectionHeader;
                    dataSize = pSmallEHHeader->DataSize;
                }
                // take the difference between the RVAs to ensure we account for the padding
                // bytes between the end of the IL code and the start of the EH clauses
                totalCodeBlobSize = (ehClauseHeaderRVA - ulCodeRVA) + dataSize;
            }
        }

        VOID* pTargetCode = m_pTargetMethodMalloc->Alloc(totalCodeBlobSize);
        //IfNullRetOOM(pTargetCode);

        // convert header
        memcpy_s(pTargetCode, headerSize, pSourceCode, headerSize);
        if (!isTinyHeader)
        {
            IMAGE_COR_ILMETHOD_FAT* pTargetCodeFatHeader = (IMAGE_COR_ILMETHOD_FAT*)pTargetCode;
            IfFailRet(ImportLocalVarSig(pTargetCodeFatHeader->LocalVarSigTok, &(pTargetCodeFatHeader->LocalVarSigTok)));
        }

        // convert IL code
        IfFailRet(ConvertILCode((BYTE*)pSourceCode + headerSize, (BYTE*)pTargetCode + headerSize, ilCodeSize));

        //convert EH
        if (pFatEHHeader != nullptr)
        {
            IMAGE_COR_ILMETHOD_SECT_FAT* pTargetEHHeader = (IMAGE_COR_ILMETHOD_SECT_FAT*)((BYTE*)pTargetCode + (ehClauseHeaderRVA - ulCodeRVA));
            pTargetEHHeader->Kind = pFatEHHeader->Kind;
            pTargetEHHeader->DataSize = pFatEHHeader->DataSize;
            IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT* pSourceEHClause = (IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT*)(pFatEHHeader + 1);
            IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT* pTargetEHClause = (IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT*)(pTargetEHHeader + 1);
            int numClauses = (pTargetEHHeader->DataSize - 4) / sizeof(IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT);
            for (int i = 0; i < numClauses; i++)
            {
                pTargetEHClause->Flags = pSourceEHClause->Flags;
                pTargetEHClause->TryOffset = pSourceEHClause->TryOffset;
                pTargetEHClause->TryLength = pSourceEHClause->TryLength;
                pTargetEHClause->HandlerOffset = pSourceEHClause->HandlerOffset;
                pTargetEHClause->HandlerLength = pSourceEHClause->HandlerLength;
                if ((pSourceEHClause->Flags & COR_ILEXCEPTION_CLAUSE_FILTER) != 0)
                {
                    IfFailRet(ConvertToken(pSourceEHClause->ClassToken, (mdToken*)&(pTargetEHClause->ClassToken)));
                }
                else
                {
                    pTargetEHClause->FilterOffset = pSourceEHClause->FilterOffset;
                }
                pTargetEHClause++;
                pSourceEHClause++;
            }
        }
        else if (pSmallEHHeader != nullptr)
        {
            IMAGE_COR_ILMETHOD_SECT_SMALL* pTargetEHHeader = (IMAGE_COR_ILMETHOD_SECT_SMALL*)((BYTE*)pTargetCode + (ehClauseHeaderRVA - ulCodeRVA));
            pTargetEHHeader->Kind = pSmallEHHeader->Kind;
            pTargetEHHeader->DataSize = pSmallEHHeader->DataSize;
            IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL* pSourceEHClause = (IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL*)(pSmallEHHeader + 1);
            IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL* pTargetEHClause = (IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL*)(pTargetEHHeader + 1);
            int numClauses = (pSmallEHHeader->DataSize - 4) / sizeof(IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL);
            for (int i = 0; i < numClauses; i++)
            {
                pTargetEHClause->Flags = pSourceEHClause->Flags;
                pTargetEHClause->TryOffset = pSourceEHClause->TryOffset;
                pTargetEHClause->TryLength = pSourceEHClause->TryLength;
                pTargetEHClause->HandlerOffset = pSourceEHClause->HandlerOffset;
                pTargetEHClause->HandlerLength = pSourceEHClause->HandlerLength;
                if ((pSourceEHClause->Flags & COR_ILEXCEPTION_CLAUSE_FILTER) != 0)
                {
                    IfFailRet(ConvertToken(pSourceEHClause->ClassToken, (mdToken*)&(pTargetEHClause->ClassToken)));
                }
                else
                {
                    pTargetEHClause->FilterOffset = pSourceEHClause->FilterOffset;
                }
                pTargetEHClause++;
                pSourceEHClause++;
            }
        }

        //because the metadata record wasn't created with an RVA, this connects the methodDef to the code
        IfFailRet(m_pProfilerInfo->SetILFunctionBody((ModuleID)m_pTargetImage, *pTargetMethodDef, (LPCBYTE)pTargetCode));
    }
    else
    {
    }

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportLocalVarSig(_In_ mdSignature sourceLocalVarSig, _Out_ mdSignature *pTargetLocalVarSig)
{
    HRESULT hr = S_OK;

    if (sourceLocalVarSig == mdTokenNil || sourceLocalVarSig == mdSignatureNil)
    {
        //This will happen when method doesn't have local variables. It is expected behavior thus we do not need to fail
        *pTargetLocalVarSig = sourceLocalVarSig;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportLocalVarSig", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceLocalVarSig);

    PCCOR_SIGNATURE pvSig = nullptr;
    ULONG cbSig = 0;
    IfFailRet(m_pSourceImport->GetSigFromToken(sourceLocalVarSig, &pvSig, &cbSig));
    IfFailRet(ConvertNonTypeSignatureCached(&pvSig, &cbSig));
    IfFailRet(m_pTargetEmit->GetTokenFromSig(pvSig, cbSig, pTargetLocalVarSig));

    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetLocalVarSig);

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportMemberRef(_In_ const mdSignature sourceMemberRef, _Out_ mdSignature *pTargetMemberRef)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceMemberRef != mdTokenNil && sourceMemberRef != mdMemberRefNil, E_FAIL);

    TokenMap::const_iterator itr = m_memberRefMap.find(sourceMemberRef);
    if (itr != m_memberRefMap.end())
    {
        *pTargetMemberRef = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportMemberRef", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceMemberRef);

    mdToken declaringType = mdTokenNil;
    WCHAR szName[MAX_NAME] = { 0 };
    ULONG cchName = 0;
    PCCOR_SIGNATURE pvSigBlob = nullptr;
    ULONG cbSig = 0;
    IfFailRet(m_pSourceImport->GetMemberRefProps(sourceMemberRef,
        &declaringType,
        szName,
        _countof(szName),
        &cchName,
        &pvSigBlob,
        &cbSig));

    dumpLogHelper.WriteStringNode(L"Name", szName);
    dumpLogHelper.WriteUlongNode(L"DeclaringType", declaringType);

    IfFailRet(ConvertNonTypeSignatureCached(&pvSigBlob, &cbSig));
    mdToken targetDeclaringType = mdTokenNil;
    IfFailRet(ConvertToken(declaringType, &targetDeclaringType));


    mdMemberRef existingTargetMemberRef = mdMemberRefNil;
    hr = m_pTargetImport->FindMemberRef(targetDeclaringType, szName, pvSigBlob, cbSig, &existingTargetMemberRef);
    if (FAILED(hr) && hr != CLDB_E_RECORD_NOTFOUND)
    {
        IfFailRet(hr);
        return hr; //this needs to prevent compiler warning. IfFailRet will trace and return error
    }
    else if (SUCCEEDED(hr))
    {
        *pTargetMemberRef = existingTargetMemberRef;
        m_memberRefMap[sourceMemberRef] = *pTargetMemberRef;
        dumpLogHelper.WriteStringNode(L"UseExisting", L"true");
        dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetMemberRef);
        return S_OK;
    }
    else
    {
        // Some of the member refs we emit will be more verbose than is necessary. If the reference
        // resolves within the assembly we are Importing into then a member ref could be collapsed to
        // a FieldDef or MethodDef. At this point however compactness/canonicalization isn't a priority
        IfFailRet(m_pTargetEmit->DefineMemberRef(targetDeclaringType, szName, pvSigBlob, cbSig, pTargetMemberRef));
        m_memberRefMap[sourceMemberRef] = *pTargetMemberRef;
        dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetMemberRef);
        return S_OK;
    }
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportString(_In_ mdString sourceString, _Out_ mdString *pTargetString)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceString != mdTokenNil && sourceString != mdStringNil, E_FAIL);

    //check the cache
    TokenMap::const_iterator itr = m_stringMap.find(sourceString);
    if (itr != m_stringMap.end())
    {
        *pTargetString = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportString", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceString);

    ULONG cchString = 0;
    IfFailRet(m_pSourceImport->GetUserString(sourceString, nullptr, 0, &cchString));
    ATL::CAutoVectorPtr<WCHAR> pStringBuffer(new WCHAR[cchString]);
    IfFailRet(m_pSourceImport->GetUserString(sourceString, pStringBuffer, cchString, &cchString));

    // Some of the strings we emit may already exist in the target assembly. If we care more about
    // target assembly size we could search all existing strings first before adding a new one
    IfFailRet(m_pTargetEmit->DefineUserString(pStringBuffer, cchString, pTargetString));
    m_stringMap[sourceString] = *pTargetString;

    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetString);

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportProperty(_In_ mdProperty sourceProperty, _Out_ mdProperty *pTargetProperty)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceProperty != mdTokenNil && sourceProperty != mdPropertyNil, E_FAIL);

    TokenMap::const_iterator itr = m_propertyMap.find(sourceProperty);
    if (itr != m_propertyMap.end())
    {
        *pTargetProperty = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportProperty", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceProperty);

    mdTypeDef sourceClass = mdTypeDefNil;
    WCHAR szName[MAX_NAME] = { 0 };
    ULONG cchName = 0;
    DWORD dwPropFlags = 0;
    PCCOR_SIGNATURE pvSig = nullptr;
    ULONG pbSig = 0;
    DWORD dwCPlusTypeFlag = 0;
    UVCP_CONSTANT pDefaultValue = nullptr;
    ULONG cchDefaultValue = 0;
    mdMethodDef mdSourceSetter = mdMethodDefNil;
    mdMethodDef mdSourceGetter = mdMethodDefNil;
    ULONG cOtherMethod = 0;
    IfFailRet(m_pSourceImport->GetPropertyProps(sourceProperty,
        &sourceClass,
        szName,
        _countof(szName),
        &cchName,
        &dwPropFlags,
        &pvSig,
        &pbSig,
        &dwCPlusTypeFlag,
        &pDefaultValue,
        &cchDefaultValue,
        &mdSourceSetter,
        &mdSourceGetter,
        nullptr,
        0,
        &cOtherMethod));

    dumpLogHelper.WriteStringNode(L"Name", szName);
    dumpLogHelper.WriteUlongNode(L"SourceClass", sourceClass);
    if (cOtherMethod > 0)
    {
        CLogging::LogError(_T("Property with other associated methods not yet implemented"));
        return E_NOTIMPL;
    }

    IfFailRet(ConvertNonTypeSignatureCached(&pvSig, &pbSig));
    mdTypeDef targetClass = mdTypeDefNil;
    IfFailRet(ImportTypeDef(sourceClass, &targetClass));
    mdMethodDef mdTargetGetter = mdMethodDefNil;
    mdMethodDef mdTargetSetter = mdMethodDefNil;
    IfFailRet(ImportMethodDef(mdSourceGetter, &mdTargetGetter));
    IfFailRet(ImportMethodDef(mdSourceSetter, &mdTargetSetter));

    IfFailRet(m_pTargetEmit->DefineProperty(targetClass,
        szName,
        dwPropFlags,
        pvSig,
        pbSig,
        dwCPlusTypeFlag,
        pDefaultValue,
        cchDefaultValue,
        mdTargetGetter,
        mdTargetSetter,
        nullptr,
        pTargetProperty));

    m_propertyMap[sourceProperty] = *pTargetProperty;

    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetProperty);

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportEvent(_In_ mdEvent sourceEvent, _Out_ mdEvent *pTargetEvent)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceEvent != mdTokenNil && sourceEvent != mdEventNil, E_FAIL);

    TokenMap::const_iterator itr = m_eventMap.find(sourceEvent);
    if (itr != m_eventMap.end())
    {
        *pTargetEvent = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportEvent", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceEvent);

    mdTypeDef sourceClass = mdTypeDefNil;
    WCHAR szName[MAX_NAME] = { 0 };
    ULONG cchName = 0;
    DWORD dwEventFlags = 0;
    mdToken sourceEventType = mdTokenNil;
    mdMethodDef mdSourceAddOn = mdMethodDefNil;
    mdMethodDef mdSourceRemoveOn = mdMethodDefNil;
    mdMethodDef mdSourceFire = mdMethodDefNil;
    ULONG cOtherMethod = 0;
    IfFailRet(m_pSourceImport->GetEventProps(sourceEvent,
        &sourceClass,
        szName,
        _countof(szName),
        &cchName,
        &dwEventFlags,
        &sourceEventType,
        &mdSourceAddOn,
        &mdSourceRemoveOn,
        &mdSourceFire,
        nullptr,
        0,
        &cOtherMethod));

    dumpLogHelper.WriteStringNode(L"Name", szName);
    if (cOtherMethod > 0)
    {
        //FAILURE(L"Event with other associated methods NYI");
        return E_NOTIMPL;
    }


    mdTypeDef targetClass = mdTypeDefNil;
    IfFailRet(ImportTypeDef(sourceClass, &targetClass));
    mdToken targetEventType = mdTokenNil;
    IfFailRet(ConvertToken(sourceEventType, &targetEventType));
    mdMethodDef mdTargetAddOn = mdMethodDefNil;
    mdMethodDef mdTargetRemoveOn = mdMethodDefNil;
    mdMethodDef mdTargetFire = mdMethodDefNil;
    IfFailRet(ImportMethodDef(mdSourceAddOn, &mdTargetAddOn));
    IfFailRet(ImportMethodDef(mdSourceRemoveOn, &mdTargetRemoveOn));
    IfFailRet(ImportMethodDef(mdSourceFire, &mdTargetFire));


    IfFailRet(m_pTargetEmit->DefineEvent(targetClass,
        szName,
        dwEventFlags,
        targetEventType,
        mdTargetAddOn,
        mdTargetRemoveOn,
        mdTargetFire,
        nullptr,
        pTargetEvent));

    m_eventMap[sourceEvent] = *pTargetEvent;
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetEvent);

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportCustomAttribute(_In_ mdCustomAttribute sourceCustomAttribute, _Out_ mdCustomAttribute *pTargetCustomAttribute)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceCustomAttribute != mdTokenNil && sourceCustomAttribute != mdCustomAttributeNil, E_FAIL);

    TokenMap::const_iterator itr = m_eventMap.find(sourceCustomAttribute);
    if (itr != m_eventMap.end())
    {
        *pTargetCustomAttribute = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportCustomAttribute", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceCustomAttribute);

    mdToken sourceObj = mdTokenNil;
    mdToken sourceType = mdTokenNil;
    void const * pBlob = nullptr;
    ULONG cbSize = 0;
    IfFailRet(m_pSourceImport->GetCustomAttributeProps(sourceCustomAttribute,
        &sourceObj,
        &sourceType,
        &pBlob,
        &cbSize));

    mdToken targetObj = mdTokenNil;
    mdToken targetType = mdTokenNil;
    hr = ConvertToken(sourceObj, &targetObj);
    IfFailRet(hr);
    hr = ConvertToken(sourceType, &targetType);
    IfFailRet(hr);
    hr = m_pTargetEmit->DefineCustomAttribute(targetObj,
        targetType,
        pBlob,
        cbSize,
        pTargetCustomAttribute);
    IfFailRet(hr);
    m_eventMap[sourceCustomAttribute] = *pTargetCustomAttribute;
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetCustomAttribute);
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportMethodImpl(_In_ mdTypeDef sourceImplementationClass, _In_ mdToken sourceImplementationMethod, _In_ mdToken sourceDeclarationMethod)
{
    HRESULT hr = S_OK;
    CLogging::XmlDumpHelper dumpLogHelper(L"ImportMethodImpl", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceImplementationClass);

    mdToken targetImplementationClass = mdTokenNil;
    IfFailRet(ConvertToken(sourceImplementationClass, &targetImplementationClass));
    mdToken targetImplementationMethod = mdTokenNil;
    IfFailRet(ConvertToken(sourceImplementationMethod, &targetImplementationMethod));
    mdToken targetDeclarationMethod = mdTokenNil;
    IfFailRet(ConvertToken(sourceDeclarationMethod, &targetDeclarationMethod));

    IfFailRet(m_pTargetEmit->DefineMethodImpl(targetImplementationClass, targetImplementationMethod, targetDeclarationMethod));
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportParam(_In_ mdParamDef sourceParam, _Out_ mdParamDef* pTargetParam)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceParam != mdTokenNil && sourceParam != mdParamDefNil, E_FAIL);

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportParam", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceParam);

    mdMethodDef sourceMethod = mdMethodDefNil;
    ULONG ulSequence = 0;
    WCHAR szName[MAX_NAME] = { 0 };
    ULONG cchName = 0;
    DWORD dwAttr = 0;
    DWORD dwCPlusTypeFlag = 0;
    UVCP_CONSTANT pValue = nullptr;
    ULONG cchValue = 0;
    IfFailRet(m_pSourceImport->GetParamProps(sourceParam,
        &sourceMethod,
        &ulSequence,
        szName,
        _countof(szName),
        &cchName,
        &dwAttr,
        &dwCPlusTypeFlag,
        &pValue,
        &cchValue));

    dumpLogHelper.WriteStringNode(L"Name", szName);

    mdMethodDef targetMethod = mdMethodDefNil;
    IfFailRet(ImportMethodDef(sourceMethod, &targetMethod));
    IfFailRet(m_pTargetEmit->DefineParam(targetMethod,
        ulSequence,
        szName,
        dwAttr,
        dwCPlusTypeFlag,
        pValue,
        cchValue,
        pTargetParam));

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportModuleRef(_In_ mdModuleRef sourceModuleRef, _Out_ mdModuleRef* pTargetModuleRef)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceModuleRef != mdTokenNil && sourceModuleRef != mdModuleRefNil, E_FAIL);

    TokenMap::const_iterator itr = m_moduleRefMap.find(sourceModuleRef);
    if (itr != m_moduleRefMap.end())
    {
        *pTargetModuleRef = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportModuleRef", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceModuleRef);

    WCHAR szName[MAX_NAME] = { 0 };
    IfFailRet(m_pSourceImport->GetModuleRefProps(sourceModuleRef, szName, _countof(szName), nullptr));

    dumpLogHelper.WriteStringNode(L"Name", szName);


    CMetadataEnumCloser<IMetaDataImport2> spHCorEnumTarget(m_pTargetImport, nullptr);
    mdModuleRef curTargetModuleRef = mdModuleRefNil;
    BOOL bFoundMatch = FALSE;
    while (S_OK == (hr = m_pTargetImport->EnumModuleRefs(spHCorEnumTarget.Get(), &curTargetModuleRef, 1, nullptr)))
    {
        WCHAR szTargetModuleRefName[MAX_NAME] = { 0 };
        IfFailRet(m_pTargetImport->GetModuleRefProps(curTargetModuleRef, szTargetModuleRefName, _countof(szTargetModuleRefName), nullptr));
        if (wcscmp(szName, szTargetModuleRefName) == 0)
        {
            bFoundMatch = TRUE;
            m_moduleRefMap[sourceModuleRef] = curTargetModuleRef;
            *pTargetModuleRef = curTargetModuleRef;
            dumpLogHelper.WriteStringNode(L"UseExisting", L"true");
            break;
        }
    }
    IfFailRet(hr);

    if (!bFoundMatch)
    {
        IfFailRet(m_pTargetEmit->DefineModuleRef(szName, pTargetModuleRef));
        m_moduleRefMap[sourceModuleRef] = *pTargetModuleRef;
    }
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetModuleRef);
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportTypeSpec(_In_ mdTypeSpec sourceTypeSpec, _Out_ mdTypeSpec* pTargetTypeSpec)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceTypeSpec != mdTokenNil && sourceTypeSpec != mdTypeSpecNil, E_FAIL);

    TokenMap::const_iterator itr = m_typeSpecMap.find(sourceTypeSpec);
    if (itr != m_typeSpecMap.end())
    {
        *pTargetTypeSpec = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportTypeSpec", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceTypeSpec);

    PCCOR_SIGNATURE pvSig = nullptr;
    ULONG cbSig = 0;
    IfFailRet(m_pSourceImport->GetTypeSpecFromToken(sourceTypeSpec, &pvSig, &cbSig));
    IfFailRet(ConvertTypeSignatureCached(&pvSig, &cbSig));
    IfFailRet(m_pTargetEmit->GetTokenFromTypeSpec(pvSig, cbSig, pTargetTypeSpec));

    m_typeSpecMap[sourceTypeSpec] = *pTargetTypeSpec;
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetTypeSpec);

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportGenericParam(_In_ mdGenericParam sourceGenericParam, _Out_ mdGenericParam* pTargetGenericParam)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceGenericParam != mdTokenNil && sourceGenericParam != mdGenericParamNil, E_FAIL);

    TokenMap::const_iterator itr = m_genericParamMap.find(sourceGenericParam);
    if (itr != m_genericParamMap.end())
    {
        *pTargetGenericParam = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportGenericParam", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceGenericParam);

    ULONG ulParamSeq = 0;
    DWORD dwParamFlags = 0;
    mdToken sourceOwner = mdTokenNil;
    DWORD reserved = 0;
    WCHAR szName[MAX_NAME] = { 0 };
    IfFailRet(m_pSourceImport->GetGenericParamProps(sourceGenericParam,
        &ulParamSeq,
        &dwParamFlags,
        &sourceOwner,
        &reserved,
        szName,
        _countof(szName),
        nullptr));

    dumpLogHelper.WriteStringNode(L"Name", szName);

    ATL::CAutoVectorPtr<mdToken> pConstraintTypes;
    ATL::CAutoVectorPtr<mdGenericParamConstraint> pGenericParamConstraints;
    CMetadataEnumCloser<IMetaDataImport2> spHCorEnum(m_pSourceImport, nullptr);
    IfFailRet(hr = m_pSourceImport->EnumGenericParamConstraints(spHCorEnum.Get(), sourceGenericParam, nullptr, 0, nullptr));
    if (hr == S_OK)
    {
        ULONG cGenericParamConstraints = 0;
        pGenericParamConstraints.Allocate(MAX_SUPPORTED_GENERIC_CONSTRAINTS);
        pConstraintTypes.Allocate(MAX_SUPPORTED_GENERIC_CONSTRAINTS + 1);
        spHCorEnum.Reset(nullptr);
        IfFailRet(m_pSourceImport->EnumGenericParamConstraints(spHCorEnum.Get(), sourceGenericParam, pGenericParamConstraints, MAX_SUPPORTED_GENERIC_CONSTRAINTS, &cGenericParamConstraints));
        if (cGenericParamConstraints > 0)
        {
            for (ULONG i = 0; i < cGenericParamConstraints; i++)
            {
                mdToken sourceConstraintType = mdTokenNil;
                IfFailRet(m_pSourceImport->GetGenericParamConstraintProps(pGenericParamConstraints[i], nullptr, &sourceConstraintType));
                IfFailRet(ConvertToken(sourceConstraintType, &(pConstraintTypes[i])));
            }
        }
        pConstraintTypes[cGenericParamConstraints] = mdTokenNil;
    }

    mdToken targetOwner = mdTokenNil;
    IfFailRet(ConvertToken(sourceOwner, &targetOwner));
    IfFailRet(m_pTargetEmit->DefineGenericParam(targetOwner,
        ulParamSeq,
        dwParamFlags,
        szName,
        reserved,
        pConstraintTypes,
        pTargetGenericParam));

    m_genericParamMap[sourceGenericParam] = *pTargetGenericParam;
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetGenericParam);
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ImportMethodSpec(_In_ mdMethodSpec sourceMethodSpec, _Out_ mdMethodSpec* pTargetMethodSpec)
{
    HRESULT hr = S_OK;

    IfFalseRet(sourceMethodSpec != mdTokenNil && sourceMethodSpec != mdMethodSpecNil, E_FAIL);

    TokenMap::const_iterator itr = m_methodSpecMap.find(sourceMethodSpec);
    if (itr != m_methodSpecMap.end())
    {
        *pTargetMethodSpec = itr->second;
        return hr;
    }

    CLogging::XmlDumpHelper dumpLogHelper(L"ImportMethodSpec", 1);
    dumpLogHelper.WriteUlongNode(L"token", sourceMethodSpec);

    mdToken sourceParent = mdTokenNil;
    PCCOR_SIGNATURE pvSigBlob = nullptr;
    ULONG cbSigBlob = 0;
    IfFailRet(m_pSourceImport->GetMethodSpecProps(sourceMethodSpec,
        &sourceParent,
        &pvSigBlob,
        &cbSigBlob));
    mdToken targetParent = mdTokenNil;
    IfFailRet(ConvertToken(sourceParent, &targetParent));
    IfFailRet(ConvertNonTypeSignatureCached(&pvSigBlob, &cbSigBlob));
    IfFailRet(m_pTargetEmit->DefineMethodSpec(targetParent, pvSigBlob, cbSigBlob, pTargetMethodSpec));

    m_methodSpecMap[sourceMethodSpec] = *pTargetMethodSpec;
    dumpLogHelper.WriteUlongNode(L"targetToken", *pTargetMethodSpec);
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertToken(_In_ mdToken sourceToken, _Out_ mdToken* pTargetToken)
{
    HRESULT hr = S_OK;

    if (TypeFromToken(sourceToken) == mdtTypeDef)
    {
        IfFailRet(ImportTypeDef(sourceToken, pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtTypeRef)
    {
        IfFailRet(ImportTypeRef(sourceToken, pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtFieldDef)
    {
        IfFailRet(ImportFieldDef(sourceToken, pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtMethodDef)
    {
        IfFailRet(ImportMethodDef(sourceToken, pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtMemberRef)
    {
        IfFailRet(ImportMemberRef(sourceToken, pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtString)
    {
        IfFailRet(ImportString(sourceToken, pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtAssembly)
    {
        ATL::CComPtr<IMetaDataAssemblyImport> pTargetAssemblyImport;
        IfFailRet(m_pTargetImport->QueryInterface(IID_IMetaDataAssemblyImport, reinterpret_cast<void**>(&pTargetAssemblyImport)));
        IfFailRet(pTargetAssemblyImport->GetAssemblyFromScope(pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtAssemblyRef)
    {
        IfFailRet(ImportAssemblyRef(sourceToken, pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtModuleRef)
    {
        IfFailRet(ImportModuleRef(sourceToken, pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtTypeSpec)
    {
        IfFailRet(ImportTypeSpec(sourceToken, pTargetToken));
    }
    else if (TypeFromToken(sourceToken) == mdtMethodSpec)
    {
        IfFailRet(ImportMethodSpec(sourceToken, pTargetToken));
    }
    else
    {
        CLogging::LogError(_T("Token conversion doesn't handle this token type yet - NYI: %d"), TypeFromToken(sourceToken));
        return E_NOTIMPL;
    }
    return hr;
}

enum OPCLSA				  // Operand Class
{
    opclsaInlineNone,   // No operand

    // Immediate constants
    opclsaShortInlineI,		  // I1: signed  8-bit immediate value
    opclsaInlineI,			  // I4: signed 32-bit immediate value
    opclsaInlineI8,			  // I8: signed 64-bit immediate value
    opclsaShortInlineR,		  // R4: single precision real immediate
    opclsaInlineR,			  // R8: double precising real immediate

    // Locals and args
    opclsaShortInlineVar,		  // U1: local or arg index, unsigned 8-bit
    opclsaInlineVar,			  // U2: local or arg index, unsigned 16-bit

    // Branch labels
    opclsaShortInlineBrTarget,	   // I1: signed 8-bit offset from instruction after the branch
    opclsaInlineBrTarget,		  // I4: signed 32-bit offset from instruction after the branch
    opclsaInlineSwitch,		  // Multiple operands for switch statement

    // Relative Virtual Address
    opclsaInlineRVA,			  // U4: for ldptr

    // Token operands (T is equivalent to U4)
    opclsaInlineMethod,		  // T: Token for identifying a methods
    opclsaInlineType, 		  // T: Token for identifying an object type (box, unbox, ldobj, cpobj, initobj, stobj, mkrefany, refanyval, castclass, isinst, newarr, ldelema)
    opclsaInlineSig,			  // T: Token for identifying a method signature (calli)
    opclsaInlineField,		  // T: Token for identifying a field (ldflda, ldsflda, ldfld, ldsfld, ldsfld, stfld, stsfld)
    opclsaInlineString,		  // T: Token for identifying a string (ldstr)
    opclsaInlineTok,			  // T: Token for ldtoken
};

static OPCLSA g_opcodeInlineValues[] = {
#define OPDEF(op, name, stack1, stack2, i, kind, length, b1, b2, controlflow) opclsa ## i,
#include "opcode.def"
#undef OPDEF
};

#define MAX_MSIL_OPCODE (0x22+0x100)


HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertILCode(_In_ const BYTE* pSourceILCode, _In_ BYTE* pTargetILCode, ULONG32 bufferSize)
{
    HRESULT hr = S_OK;

    for (ULONG32 cursor = 0; cursor < bufferSize;)
    {
        // MSIL opcodes can be either 1 byte or 2 bytes, possible followed by an inline value whose size is opcode dependent.
        ULONG32 opCode = pSourceILCode[cursor];
        pTargetILCode[cursor] = pSourceILCode[cursor];
        cursor++;
        // All valid 2 byte opcodes start with 0xFE, otherwise it is invalid or a 1 byte opcode.
        if (opCode == 0xFE)
        {
            if (cursor >= bufferSize)
                return E_FAIL;
            pTargetILCode[cursor] = pSourceILCode[cursor];
            opCode = pSourceILCode[cursor] + 256;
            cursor++;
        }
        // make sure we stay within the array
        if (opCode > MAX_MSIL_OPCODE)
            return E_FAIL;
        OPCLSA inlineValueKind = g_opcodeInlineValues[opCode];
        switch (inlineValueKind)
        {
        case opclsaInlineNone:
            break;

        case opclsaShortInlineI:		  // I1: signed  8-bit immediate value
        case opclsaShortInlineVar:		  // U1: local or arg index, unsigned 8-bit
        case opclsaShortInlineBrTarget:	   // I1: signed 8-bit offset from instruction after the branch
        {
            if (cursor + 1 > bufferSize)
                return E_FAIL;
            pTargetILCode[cursor] = pSourceILCode[cursor];
            cursor++;
            break;
        }

        case opclsaInlineVar:			  // U2: local or arg index, unsigned 16-bit
        {
            if (cursor + 2 > bufferSize)
                return E_FAIL;
            pTargetILCode[cursor] = pSourceILCode[cursor];
            pTargetILCode[cursor + 1] = pSourceILCode[cursor + 1];
            cursor += 2;
            break;
        }
        case opclsaInlineRVA:			  // U4: for ldptr
        {
            //FAILURE(L"Converting IL code with inline RVA not supported");
            return E_NOTIMPL;
        }
        case opclsaInlineSig:			  // T: Token for identifying a method signature (calli)
        {
            //FAILURE(L"Converting IL code with calli not supported");
            return E_NOTIMPL;
        }
        case opclsaInlineI:			  // I4: signed 32-bit immediate value
        case opclsaShortInlineR:      // R4: single precision real immediate
        case opclsaInlineBrTarget:		  // I4: signed 32-bit offset from instruction after the branch
        {
            if (cursor + 4 > bufferSize)
                return E_FAIL;
            memcpy_s(pTargetILCode + cursor, (bufferSize - cursor), pSourceILCode + cursor, 4);
            cursor += 4;
            break;
        }

        case opclsaInlineI8:	      // I8: signed 64-bit immediate value
        case opclsaInlineR:			  // R8: double precising real immediate
        {
            if (cursor + 8 > bufferSize)
                return E_FAIL;
            memcpy_s(pTargetILCode + cursor, (bufferSize - cursor), pSourceILCode + cursor, 8);
            cursor += 8;
            break;
        }

        case opclsaInlineSwitch:		  // Multiple operands for switch statement
        {
            if (cursor + 4 > bufferSize)
                return E_FAIL;
            ULONG32 numCases = *(ULONG32*)(pSourceILCode + cursor);
            memcpy_s(pTargetILCode + cursor, (bufferSize - cursor), pSourceILCode + cursor, 4);
            cursor += 4;
            if (cursor + 4 * numCases > bufferSize)
                return E_FAIL;
            memcpy_s(pTargetILCode + cursor, (bufferSize - cursor), pSourceILCode + cursor, 4 * numCases);
            cursor += 4 * numCases;
            break;
        }

        case opclsaInlineMethod:		  // T: Token for identifying a methods
        case opclsaInlineType: 		  // T: Token for identifying an object type (box, unbox, ldobj, cpobj, initobj, stobj, mkrefany, refanyval, castclass, isinst, newarr, ldelema)
        case opclsaInlineField:		  // T: Token for identifying a field (ldflda, ldsflda, ldfld, ldsfld, ldsfld, stfld, stsfld)
        case opclsaInlineTok:			  // T: Token for ldtoken
        case opclsaInlineString:		  // T: Token for identifying a string (ldstr)
        {
            if (cursor + 4 > bufferSize)
                return E_FAIL;
            mdToken tk = *(mdToken*)(pSourceILCode + cursor);
            IfFailRet(ConvertToken(tk, &tk));
            *(mdToken*)(pTargetILCode + cursor) = tk;
            cursor += 4;
            break;
        }
        }
    }
    return hr;
}


HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertNonTypeSignatureCached(_Inout_ PCCOR_SIGNATURE* ppSignature, _Inout_ DWORD* pcbSignature)
{
    HRESULT hr = S_OK;

    IfFalseRet(ppSignature != nullptr && pcbSignature != nullptr, E_FAIL);
    CComPtr<ISignatureBuilder> sigTargetSignature = nullptr;
    TSignatureMap::const_iterator itr = m_sigToConvertedSigMap.find(*ppSignature);
    if (itr == m_sigToConvertedSigMap.end())
    {
        sigTargetSignature.Attach(new CSignatureBuilder());
        SigParser parser(*ppSignature, *pcbSignature);
        IfFailRet(ConvertNonTypeSignature(parser, sigTargetSignature));
        m_sigToConvertedSigMap[*ppSignature] = sigTargetSignature;
    }
    else
    {
        sigTargetSignature = itr->second;
    }

    IfFailRet(sigTargetSignature->GetCorSignaturePtr(static_cast<const BYTE**>(ppSignature)));
    IfFailRet(sigTargetSignature->GetSize(pcbSignature));

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertTypeSignatureCached(_Inout_ PCCOR_SIGNATURE* ppSignature, _Inout_ DWORD* pcbSignature)
{
    HRESULT hr = S_OK;

    IfFalseRet(ppSignature != nullptr && pcbSignature != nullptr, E_FAIL);

    CComPtr<ISignatureBuilder> sigTargetSignature;
    TSignatureMap::const_iterator itr = m_sigToConvertedSigMap.find(*ppSignature);
    if (itr == m_sigToConvertedSigMap.end())
    {
        sigTargetSignature.Attach(new CSignatureBuilder());
        SigParser parser(*ppSignature, *pcbSignature);
        IfFailRet(ConvertTypeSignature(parser, sigTargetSignature));
        m_sigToConvertedSigMap[*ppSignature] = sigTargetSignature;
    }
    else
    {
        sigTargetSignature = itr->second;
    }

    IfFailRet(sigTargetSignature->GetCorSignaturePtr(static_cast<const BYTE**>(ppSignature)));
    IfFailRet(sigTargetSignature->GetSize(pcbSignature));

    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertMethodDefRefOrPropertySignature(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig, _In_ BYTE callConv)
{
    HRESULT hr = S_OK;
    if ((callConv & IMAGE_CEE_CS_CALLCONV_GENERIC) != 0)
    {
        IfFailRet(ConvertData(sig, newSig)); // genericParamCount
    }

    ULONG countParams = 0;
    IfFailRet(sig.PeekData(&countParams));
    IfFailRet(ConvertData(sig, newSig));

    IfFailRet(ConvertParamSignature(sig, newSig)); // return value
    for (ULONG i = 0; i < countParams; i++)
    {
        IfFailRet(ConvertParamSignature(sig, newSig));
    }
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertNonTypeSignature(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    ULONG callConvTmp = 0;
    IfFailRet(sig.GetCallingConvInfo(&callConvTmp));
    BYTE callConv = (BYTE)(callConvTmp & 0xFF);
    IfFailRet(newSig->AddData(&callConv, 1));
    ULONG maskedCallConv = callConv & IMAGE_CEE_CS_CALLCONV_MASK;
    if (maskedCallConv == IMAGE_CEE_CS_CALLCONV_DEFAULT || maskedCallConv == IMAGE_CEE_CS_CALLCONV_VARARG ||
        maskedCallConv == IMAGE_CEE_CS_CALLCONV_PROPERTY)
    {
        IfFailRet(ConvertMethodDefRefOrPropertySignature(sig, newSig, callConv));
    }
    else if (maskedCallConv == IMAGE_CEE_CS_CALLCONV_FIELD)
    {
        IfFailRet(ConvertFieldSignature(sig, newSig));
    }
    else if (maskedCallConv == IMAGE_CEE_CS_CALLCONV_GENERICINST)
    {
        IfFailRet(ConvertMethodSpecSignature(sig, newSig));
    }
    else if (maskedCallConv == IMAGE_CEE_CS_CALLCONV_LOCAL_SIG)
    {
        IfFailRet(ConvertLocalVarSignature(sig, newSig));
    }
    else
    {
        CLogging::LogError(_T("Unexpected signature type"));
    }
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertLocalVarSignature(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    ULONG argCount = 0;
    IfFailRet(sig.PeekData(&argCount));
    IfFailRet(ConvertData(sig, newSig));
    for (ULONG i = 0; i < argCount; i++)
    {
        CorElementType et = ELEMENT_TYPE_END;
        IfFailRet(sig.PeekElemType(&et));
        if (et == ELEMENT_TYPE_TYPEDBYREF)
        {
            IfFailRet(ConvertElemType(sig, newSig));
        }
        else
        {
            while (et == ELEMENT_TYPE_CMOD_OPT || et == ELEMENT_TYPE_CMOD_REQD || et == ELEMENT_TYPE_PINNED)
            {
                if (et == ELEMENT_TYPE_PINNED)
                {
                    IfFailRet(ConvertElemType(sig, newSig));
                }
                else
                {
                    IfFailRet(ConvertCustomModSignature(sig, newSig));
                }
                IfFailRet(sig.PeekElemType(&et));
            }
            if (et == ELEMENT_TYPE_BYREF)
            {
                IfFailRet(ConvertElemType(sig, newSig));
            }
            IfFailRet(ConvertTypeSignature(sig, newSig));
        }
    }
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertMethodSpecSignature(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    ULONG argCount = 0;
    IfFailRet(sig.PeekData(&argCount));
    IfFailRet(ConvertData(sig, newSig));
    for (ULONG i = 0; i < argCount; i++)
    {
        IfFailRet(ConvertTypeSignature(sig, newSig));
    }
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertFieldSignature(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    IfFailRet(ConvertCustomModSignatureList(sig, newSig));
    IfFailRet(ConvertTypeSignature(sig, newSig));
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertTypeSignature(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    CorElementType et = ELEMENT_TYPE_END;
    IfFailRet(sig.PeekData((ULONG*)&et)); // avoid implicit conversion that occurs in PeekElemType
    IfFailRet(ConvertElemType(sig, newSig));
    if (!CorIsPrimitiveType(et))
    {
        switch (et)
        {
        case ELEMENT_TYPE_ARRAY:
            IfFailRet(ConvertTypeSignature(sig, newSig)); // componentType
            IfFailRet(ConvertData(sig, newSig)); // rank
            IfFailRet(ConvertLengthPrefixedDataList(sig, newSig)); // sizes
            IfFailRet(ConvertLengthPrefixedDataList(sig, newSig)); // low bounds
            break;
        case ELEMENT_TYPE_FNPTR:
            IfFailRet(ConvertNonTypeSignature(sig, newSig)); // methodref sig for function
            break;
        case ELEMENT_TYPE_PTR:
            IfFailRet(ConvertCustomModSignatureList(sig, newSig));
            IfFailRet(ConvertTypeSignature(sig, newSig)); // component type
            break;
        case ELEMENT_TYPE_SZARRAY:
            IfFailRet(ConvertCustomModSignatureList(sig, newSig));
            IfFailRet(ConvertTypeSignature(sig, newSig)); // component type
            break;
        case ELEMENT_TYPE_CLASS:
            IfFailRet(ConvertToken(sig, newSig)); // typeDefOrRef
            break;
        case ELEMENT_TYPE_GENERICINST:
        {
            IfFailRet(ConvertElemType(sig, newSig)); // VALUETYPE or CLASS
            IfFailRet(ConvertToken(sig, newSig)); // typeDefOrRef, open type
            ULONG numTypes = 0;
            IfFailRet(sig.PeekData(&numTypes));
            IfFailRet(ConvertData(sig, newSig)); // # type arguments
            for (ULONG i = 0; i < numTypes; i++)
            {
                IfFailRet(ConvertTypeSignature(sig, newSig)); // type arguments
            }
            break;
        }
        case ELEMENT_TYPE_OBJECT:
            break;
        case ELEMENT_TYPE_MVAR:
            IfFailRet(ConvertData(sig, newSig)); // param #
            break;
        case ELEMENT_TYPE_VAR:
            IfFailRet(ConvertData(sig, newSig)); // param #
            break;
        case ELEMENT_TYPE_VALUETYPE:
            IfFailRet(ConvertToken(sig, newSig)); // typeDefOrRef
            break;
        case ELEMENT_TYPE_BYREF:
            IfFailRet(ConvertTypeSignature(sig, newSig)); // component type
            break;
        case ELEMENT_TYPE_TYPEDBYREF:
            break;
        default:
            CLogging::LogError(_T("Unexpected CorElementType"));
        }
    }
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertToken(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    mdToken tk = mdTokenNil;
    IfFailRet(sig.GetToken(&tk));
    IfFailRet(ConvertToken(tk, &tk));
    IfFailRet(newSig->AddToken(tk));
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertElemType(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    CorElementType et = ELEMENT_TYPE_END;
    IfFailRet(sig.GetElemType(&et));
    IfFailRet(newSig->AddElementType(et));
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertData(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    ULONG data = 0;
    IfFailRet(sig.GetData(&data));
    IfFailRet(newSig->Add(data));
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertLengthPrefixedDataList(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    ULONG length = 0;
    IfFailRet(sig.PeekData(&length));
    IfFailRet(ConvertData(sig, newSig)); // length
    for (ULONG i = 0; i < length; i++)
    {
        IfFailRet(ConvertData(sig, newSig));
    }
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertParamSignature(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    IfFailRet(ConvertCustomModSignatureList(sig, newSig));
    IfFailRet(ConvertTypeSignature(sig, newSig));
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertCustomModSignatureList(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    for (;;)
    {
        // peak at the next CorElementType to distinguish custom mod from
        // following Type/VOID
        CorElementType et = ELEMENT_TYPE_END;
        hr = sig.PeekElemType(&et);
        if (hr == S_OK && (et == ELEMENT_TYPE_CMOD_REQD || et == ELEMENT_TYPE_CMOD_OPT))
        {
            ConvertCustomModSignature(sig, newSig);
        }
        else
        {
            break;
        }
    }
    return hr;
}

HRESULT MicrosoftInstrumentationEngine::AssemblyInjector::ConvertCustomModSignature(_In_ SigParser & sig, _In_ const CComPtr<ISignatureBuilder>& newSig)
{
    HRESULT hr = S_OK;
    IfFailRet(ConvertElemType(sig, newSig));
    IfFailRet(ConvertToken(sig, newSig));
    return S_OK;
}