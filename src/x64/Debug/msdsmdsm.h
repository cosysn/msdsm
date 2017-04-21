#ifndef _msdsmdsm_h_
#define _msdsmdsm_h_

// MSDSM_DEFAULT_LOAD_BALANCE_POLICY - MSDSM_DEFAULT_LOAD_BALANCE_POLICY
// MSDSM-wide default load balance policies.
#define MSDSM_DEFAULT_LOAD_BALANCE_POLICYGuid \
    { 0xc81b5681,0xf3ca,0x4c98, { 0x93,0x25,0x70,0x7d,0x0d,0x62,0xff,0xc4 } }

#if ! (defined(MIDL_PASS))
DEFINE_GUID(MSDSM_DEFAULT_LOAD_BALANCE_POLICY_GUID, \
            0xc81b5681,0xf3ca,0x4c98,0x93,0x25,0x70,0x7d,0x0d,0x62,0xff,0xc4);
#endif


typedef struct _MSDSM_DEFAULT_LOAD_BALANCE_POLICY
{
    // Load Balance Policy to be applied to devices controlled by MSDSM.
    ULONG LoadBalancePolicy;
    #define MSDSM_DEFAULT_LOAD_BALANCE_POLICY_LoadBalancePolicy_SIZE sizeof(ULONG)
    #define MSDSM_DEFAULT_LOAD_BALANCE_POLICY_LoadBalancePolicy_ID 1

    // Reserved.
    ULONG Reserved;
    #define MSDSM_DEFAULT_LOAD_BALANCE_POLICY_Reserved_SIZE sizeof(ULONG)
    #define MSDSM_DEFAULT_LOAD_BALANCE_POLICY_Reserved_ID 2

    // Preferred Path.
    ULONGLONG PreferredPath;
    #define MSDSM_DEFAULT_LOAD_BALANCE_POLICY_PreferredPath_SIZE sizeof(ULONGLONG)
    #define MSDSM_DEFAULT_LOAD_BALANCE_POLICY_PreferredPath_ID 3

} MSDSM_DEFAULT_LOAD_BALANCE_POLICY, *PMSDSM_DEFAULT_LOAD_BALANCE_POLICY;

#define MSDSM_DEFAULT_LOAD_BALANCE_POLICY_SIZE (FIELD_OFFSET(MSDSM_DEFAULT_LOAD_BALANCE_POLICY, PreferredPath) + MSDSM_DEFAULT_LOAD_BALANCE_POLICY_PreferredPath_SIZE)

// MSDSM_TARGET_DEFAULT_POLICY_INFO - MSDSM_TARGET_DEFAULT_POLICY_INFO
#define MSDSM_TARGET_DEFAULT_POLICY_INFOGuid \
    { 0xddb00a72,0x0fab,0x418b, { 0xa8,0x9e,0x97,0x37,0x0a,0xe2,0x93,0xa4 } }

#if ! (defined(MIDL_PASS))
DEFINE_GUID(MSDSM_TARGET_DEFAULT_POLICY_INFO_GUID, \
            0xddb00a72,0x0fab,0x418b,0xa8,0x9e,0x97,0x37,0x0a,0xe2,0x93,0xa4);
#endif


typedef struct _MSDSM_TARGET_DEFAULT_POLICY_INFO
{
    // Concatenated VendorID (8 characters) and ProductID (16 characters).
    WCHAR HardwareId[31 + 1];
    #define MSDSM_TARGET_DEFAULT_POLICY_INFO_HardwareId_ID 1

    // 
    ULONG LoadBalancePolicy;
    #define MSDSM_TARGET_DEFAULT_POLICY_INFO_LoadBalancePolicy_SIZE sizeof(ULONG)
    #define MSDSM_TARGET_DEFAULT_POLICY_INFO_LoadBalancePolicy_ID 2

    // 
    ULONG Reserved;
    #define MSDSM_TARGET_DEFAULT_POLICY_INFO_Reserved_SIZE sizeof(ULONG)
    #define MSDSM_TARGET_DEFAULT_POLICY_INFO_Reserved_ID 3

    // 
    ULONGLONG PreferredPath;
    #define MSDSM_TARGET_DEFAULT_POLICY_INFO_PreferredPath_SIZE sizeof(ULONGLONG)
    #define MSDSM_TARGET_DEFAULT_POLICY_INFO_PreferredPath_ID 4

} MSDSM_TARGET_DEFAULT_POLICY_INFO, *PMSDSM_TARGET_DEFAULT_POLICY_INFO;

#define MSDSM_TARGET_DEFAULT_POLICY_INFO_SIZE (FIELD_OFFSET(MSDSM_TARGET_DEFAULT_POLICY_INFO, PreferredPath) + MSDSM_TARGET_DEFAULT_POLICY_INFO_PreferredPath_SIZE)

// MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY - MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY
// Target-level default load balance policies.
#define MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICYGuid \
    { 0x5ccbcd91,0x1b56,0x4327, { 0xa2,0xf3,0x09,0x60,0x33,0x5f,0x88,0x46 } }

#if ! (defined(MIDL_PASS))
DEFINE_GUID(MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY_GUID, \
            0x5ccbcd91,0x1b56,0x4327,0xa2,0xf3,0x09,0x60,0x33,0x5f,0x88,0x46);
#endif


typedef struct _MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY
{
    // Number of targets specified.
    ULONG NumberDevices;
    #define MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY_NumberDevices_SIZE sizeof(ULONG)
    #define MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY_NumberDevices_ID 1

    // Reserved.
    ULONG Reserved;
    #define MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY_Reserved_SIZE sizeof(ULONG)
    #define MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY_Reserved_ID 2

    // Array of target hardware identifiers with policy and preferred path information.
    MSDSM_TARGET_DEFAULT_POLICY_INFO TargetDefaultPolicyInfo[1];
    #define MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY_TargetDefaultPolicyInfo_ID 3

} MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY, *PMSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY;

// MSDSM_SUPPORTED_DEVICES_LIST - MSDSM_SUPPORTED_DEVICES_LIST
// Retrieve MSDSM's supported devices list.
#define MSDSM_SUPPORTED_DEVICES_LISTGuid \
    { 0xc362d67c,0x371e,0x44d8, { 0x8b,0xba,0x04,0x46,0x19,0xe4,0xf2,0x45 } }

#if ! (defined(MIDL_PASS))
DEFINE_GUID(MSDSM_SUPPORTED_DEVICES_LIST_GUID, \
            0xc362d67c,0x371e,0x44d8,0x8b,0xba,0x04,0x46,0x19,0xe4,0xf2,0x45);
#endif


typedef struct _MSDSM_SUPPORTED_DEVICES_LIST
{
    // Number of supported devices.
    ULONG NumberDevices;
    #define MSDSM_SUPPORTED_DEVICES_LIST_NumberDevices_SIZE sizeof(ULONG)
    #define MSDSM_SUPPORTED_DEVICES_LIST_NumberDevices_ID 1

    // Reserved.
    ULONG Reserved;
    #define MSDSM_SUPPORTED_DEVICES_LIST_Reserved_SIZE sizeof(ULONG)
    #define MSDSM_SUPPORTED_DEVICES_LIST_Reserved_ID 2

    // Array of device hardware identifiers.
    WCHAR DeviceId[1];
    #define MSDSM_SUPPORTED_DEVICES_LIST_DeviceId_ID 3

} MSDSM_SUPPORTED_DEVICES_LIST, *PMSDSM_SUPPORTED_DEVICES_LIST;

#endif
