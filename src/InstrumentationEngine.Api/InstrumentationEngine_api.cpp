

/* this ALWAYS GENERATED file contains the IIDs and CLSIDs */

/* link this file in with the server and any clients */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Mon Jan 18 19:14:07 2038
 */
/* Compiler settings for InstrumentationEngine.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



#ifdef __cplusplus
extern "C"{
#endif 


#include <rpc.h>
#include <rpcndr.h>

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

#else // !_MIDL_USE_GUIDDEF_

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef struct _IID
{
    unsigned long x;
    unsigned short s1;
    unsigned short s2;
    unsigned char  c[8];
} IID;

#endif // __IID_DEFINED__

#ifndef CLSID_DEFINED
#define CLSID_DEFINED
typedef IID CLSID;
#endif // CLSID_DEFINED

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        EXTERN_C __declspec(selectany) const type name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#endif // !_MIDL_USE_GUIDDEF_

MIDL_DEFINE_GUID(IID, LIBID_MicrosoftInstrumentationEngine,0x54DD4A02,0x1C02,0x43FF,0x8E,0xC8,0xFA,0x42,0x44,0xB5,0x2E,0x60);


MIDL_DEFINE_GUID(IID, IID_IProfilerManager,0x3A09AD0A,0x25C6,0x4093,0x93,0xE1,0x3F,0x64,0xEB,0x16,0x0A,0x9D);


MIDL_DEFINE_GUID(IID, IID_IProfilerManagerHost,0xBA9193B4,0x287F,0x4BF4,0x8E,0x1B,0x00,0xFC,0xE3,0x38,0x62,0xEB);


MIDL_DEFINE_GUID(IID, IID_IProfilerManagerLogging,0x9CFECED7,0x2123,0x4115,0xBF,0x06,0x36,0x93,0xD1,0xD1,0x9E,0x22);


MIDL_DEFINE_GUID(IID, IID_IProfilerManagerLoggingHost,0x99F828EE,0xEA00,0x473C,0xA8,0x29,0xD4,0x00,0x23,0x5C,0x11,0xC1);


MIDL_DEFINE_GUID(IID, IID_IInstrumentationMethod,0x0D92A8D9,0x6645,0x4803,0xB9,0x4B,0x06,0xA1,0xC4,0xF4,0xE6,0x33);


MIDL_DEFINE_GUID(IID, IID_IDataContainer,0x2A4FDF66,0xFC5B,0x442D,0x8F,0xAA,0x41,0x37,0xF0,0x23,0xA4,0xEA);


MIDL_DEFINE_GUID(IID, IID_IInstruction,0xE80D8434,0x2976,0x4242,0x8F,0x3B,0x0C,0x83,0x7C,0x34,0x3F,0x6C);


MIDL_DEFINE_GUID(IID, IID_IExceptionSection,0x42CE95A2,0xF814,0x4DCD,0x95,0x2F,0x68,0xCE,0x98,0x01,0xFD,0xD3);


MIDL_DEFINE_GUID(IID, IID_IExceptionClause,0x1D57EAF6,0xFCFE,0x4874,0xAA,0x0E,0xC9,0xD1,0xDF,0x71,0x49,0x50);


MIDL_DEFINE_GUID(IID, IID_IEnumExceptionClauses,0x85B0B99F,0x73D7,0x4C69,0x86,0x59,0xBF,0x61,0x96,0xF5,0x26,0x4F);


MIDL_DEFINE_GUID(IID, IID_IOperandInstruction,0x1F014299,0xF383,0x46CE,0xB7,0xA6,0x19,0x82,0xC8,0x5F,0x9F,0xEA);


MIDL_DEFINE_GUID(IID, IID_IBranchInstruction,0x73728F9D,0xB4B5,0x4149,0x83,0x96,0xA7,0x9C,0x47,0x26,0x63,0x6E);


MIDL_DEFINE_GUID(IID, IID_ISwitchInstruction,0x66B79035,0x4F18,0x4689,0xA1,0x6D,0x95,0xAF,0x46,0x94,0x60,0xA3);


MIDL_DEFINE_GUID(IID, IID_IInstructionGraph,0x9165F2D1,0x2D6D,0x4B89,0xB2,0xAB,0x2C,0xAC,0xA6,0x6C,0xAA,0x48);


MIDL_DEFINE_GUID(IID, IID_IMethodInfo,0xCC21A894,0xF4DF,0x4726,0x83,0x18,0xD6,0xC2,0x4C,0x49,0x85,0xB1);


MIDL_DEFINE_GUID(IID, IID_IMethodInfo2,0xCDF098F7,0xD04A,0x4B58,0xB4,0x6E,0x18,0x4C,0x4F,0x22,0x3E,0x5F);


MIDL_DEFINE_GUID(IID, IID_IAssemblyInfo,0x110FE5BA,0x57CD,0x4308,0x86,0xBE,0x48,0x74,0x78,0xAB,0xE2,0xCD);


MIDL_DEFINE_GUID(IID, IID_IEnumAssemblyInfo,0x71001B79,0xB50A,0x4103,0x9D,0x19,0xFF,0xCF,0x9F,0x6C,0xE1,0xE9);


MIDL_DEFINE_GUID(IID, IID_IModuleInfo,0x0BD963B1,0xFD87,0x4492,0xA4,0x17,0x15,0x2F,0x3D,0x0C,0x9C,0xBC);


MIDL_DEFINE_GUID(IID, IID_IModuleInfo2,0x4200c448,0x7ede,0x4e61,0xae,0x67,0xb0,0x17,0xd3,0x02,0x1f,0x12);


MIDL_DEFINE_GUID(IID, IID_IModuleInfo3,0xB4C10B86,0xE3D3,0x4514,0x91,0xB9,0xB2,0xBA,0xA8,0x4E,0x7D,0x8B);


MIDL_DEFINE_GUID(IID, IID_IEnumModuleInfo,0x683b3d0b,0x5cab,0x49ac,0x92,0x42,0xc7,0xde,0x19,0x0c,0x77,0x64);


MIDL_DEFINE_GUID(IID, IID_IAppDomainInfo,0xA81A5232,0x4693,0x47E9,0xA7,0x4D,0xBB,0x4C,0x71,0x16,0x46,0x59);


MIDL_DEFINE_GUID(IID, IID_IEnumAppDomainInfo,0xC2A3E353,0x08BB,0x4A13,0x85,0x1E,0x07,0xB1,0xBB,0x4A,0xD5,0x7C);


MIDL_DEFINE_GUID(IID, IID_ILocalVariableCollection,0x353F806F,0x6563,0x40E0,0x8E,0xBE,0xB9,0x3A,0x58,0xC0,0x14,0x5F);


MIDL_DEFINE_GUID(IID, IID_IType,0x6FC96859,0xED89,0x4D9F,0xA7,0xC9,0x1D,0xAD,0x7E,0xC3,0x5F,0x67);


MIDL_DEFINE_GUID(IID, IID_IAppDomainCollection,0xC79F6730,0xC5FB,0x40C4,0xB5,0x28,0x0A,0x02,0x48,0xCA,0x4D,0xEB);


MIDL_DEFINE_GUID(IID, IID_ISignatureBuilder,0xF574823E,0x4863,0x4013,0xA4,0xEA,0xC6,0xD9,0x94,0x32,0x46,0xE6);


MIDL_DEFINE_GUID(IID, IID_ITypeCreator,0xC6D612FA,0xB550,0x48E3,0x88,0x59,0xDE,0x44,0x0C,0xF6,0x66,0x27);


MIDL_DEFINE_GUID(IID, IID_IMethodLocal,0xF8C007DB,0x0D35,0x4726,0x9E,0xDC,0x78,0x15,0x90,0xE3,0x06,0x88);


MIDL_DEFINE_GUID(IID, IID_IMethodParameter,0x26255678,0x9F51,0x433F,0x89,0xB1,0x51,0xB9,0x78,0xEB,0x4C,0x2B);


MIDL_DEFINE_GUID(IID, IID_IEnumMethodLocals,0xC4440146,0x7E2D,0x4B1A,0x8F,0x69,0xD6,0xE4,0x81,0x7D,0x72,0x95);


MIDL_DEFINE_GUID(IID, IID_IEnumMethodParameters,0x2DBC9FAB,0x93BD,0x4733,0x82,0xFA,0xEA,0x3B,0x3D,0x55,0x8A,0x0B);


MIDL_DEFINE_GUID(IID, IID_ISingleRetDefaultInstrumentation,0x2ED40F43,0xE51A,0x41A6,0x91,0xFC,0x6F,0xA9,0x16,0x3C,0x62,0xE9);


MIDL_DEFINE_GUID(IID, IID_IProfilerManager2,0xDCB0764D,0xE18F,0x4F9A,0x91,0xE8,0x6A,0x40,0xFC,0xFE,0x67,0x75);


MIDL_DEFINE_GUID(IID, IID_IProfilerManager3,0x0B097E56,0x55EE,0x4EC4,0xB2,0xF4,0x38,0x0B,0x82,0x44,0x8B,0x63);


MIDL_DEFINE_GUID(IID, IID_IProfilerManager4,0x24100BD8,0x58F2,0x483A,0x94,0x8A,0x5B,0x0B,0x81,0x86,0xE4,0x51);


MIDL_DEFINE_GUID(IID, IID_IProfilerManager5,0xAF78C11D,0x385A,0x47B1,0xA4,0xFB,0x8D,0x6B,0xA7,0xFE,0x9B,0x2D);


MIDL_DEFINE_GUID(IID, IID_IInstrumentationMethodExceptionEvents,0x8310B758,0x6642,0x46AD,0x94,0x23,0xDD,0xA5,0xF9,0xE2,0x78,0xAE);


MIDL_DEFINE_GUID(IID, IID_IEnumInstructions,0x2A4A827A,0x046D,0x4927,0xBD,0x90,0xCE,0x96,0x07,0x60,0x72,0x80);


MIDL_DEFINE_GUID(IID, IID_IInstructionFactory,0xCF059876,0xC5CA,0x4EBF,0xAC,0xB9,0x9C,0x58,0x00,0x9C,0xE3,0x1A);


MIDL_DEFINE_GUID(IID, IID_IEnumAppMethodInfo,0x541A45B7,0xD194,0x47EE,0x92,0x31,0xAB,0x69,0xD2,0x7D,0x1D,0x59);


MIDL_DEFINE_GUID(IID, IID_IModuleInfo4,0xA751B4C1,0xB03E,0x4790,0x8B,0xB8,0xD8,0x6D,0x7D,0xF8,0xDF,0xF2);


MIDL_DEFINE_GUID(IID, IID_ILocalVariableCollection2,0x61657FE7,0xBFBB,0x4B60,0xBB,0xA7,0x1D,0x3C,0x32,0x6F,0xA4,0x70);


MIDL_DEFINE_GUID(IID, IID_IEnumTypes,0x5618BD13,0x12FC,0x4198,0xA3,0x9D,0x8E,0xD6,0x02,0x65,0xAA,0xC6);


MIDL_DEFINE_GUID(IID, IID_ISignatureParser,0x33BD020E,0x372B,0x40F9,0xA7,0x35,0x4B,0x40,0x17,0xED,0x56,0xAC);


MIDL_DEFINE_GUID(IID, IID_ITokenType,0x77655B33,0x1B29,0x4285,0x9F,0x2D,0xFF,0x95,0x26,0xE3,0xA0,0xAA);


MIDL_DEFINE_GUID(IID, IID_ICompositeType,0x06B9FD79,0x0386,0x4CF3,0x93,0xDD,0xA2,0x3E,0x95,0xEB,0xC2,0x25);


MIDL_DEFINE_GUID(IID, IID_IGenericParameterType,0x1D5C1393,0xDC7E,0x4FEF,0x8A,0x9D,0xA3,0xDA,0xF7,0xA5,0x5C,0x6E);


MIDL_DEFINE_GUID(IID, IID_ISingleRetDefaultInstrumentation2,0x7A88FF19,0xF3A1,0x4C43,0x89,0xDB,0x61,0xDF,0x37,0x64,0x41,0xB5);


MIDL_DEFINE_GUID(IID, IID_IInstrumentationMethodJitEvents,0x9B028F9E,0xE2E0,0x4A61,0x86,0x2B,0xA4,0xE1,0x15,0x86,0x57,0xD0);


MIDL_DEFINE_GUID(IID, IID_IMethodJitInfo,0xA2A780D6,0xF337,0x406C,0xBA,0x57,0xF1,0x0F,0xBD,0x6C,0x46,0xF9);


MIDL_DEFINE_GUID(IID, IID_IMethodJitInfo2,0x8311A7CF,0x30EC,0x42C9,0x85,0xA4,0xF5,0x97,0x13,0xA4,0xF3,0x7D);


MIDL_DEFINE_GUID(IID, IID_IInstrumentationMethodJitEvents2,0xDC5B373D,0xC38D,0x4299,0x83,0xD9,0x12,0x9B,0x6A,0xCC,0xEE,0x2F);


MIDL_DEFINE_GUID(IID, IID_IInstrumentationMethodSetting,0xEF0B0C79,0x08E7,0x4C3A,0xA4,0xC5,0x02,0xA9,0xC9,0xCE,0x88,0x09);


MIDL_DEFINE_GUID(IID, IID_IEnumInstrumentationMethodSettings,0x9B03D87E,0x72F0,0x4D8E,0xA4,0xB1,0x15,0xBC,0xD8,0x22,0x70,0x73);


MIDL_DEFINE_GUID(IID, IID_IInstrumentationMethodAttachContext,0x2C37B76C,0xB350,0x4738,0x8B,0x29,0xB9,0x2C,0x7E,0xD6,0xC5,0x22);


MIDL_DEFINE_GUID(IID, IID_IInstrumentationMethodAttach,0x3BD6C171,0x4F3C,0x45C3,0x8C,0xB9,0xBC,0x8C,0x33,0x7D,0x16,0x83);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif



