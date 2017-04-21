#ifndef _msdsmwmi_h_
#define _msdsmwmi_h_

// MSDSM_DEVICEPATH_PERF - MSDSM_DEVICEPATH_PERF
#define MSDSM_DEVICEPATH_PERFGuid \
    { 0xa34d03ec,0x6b0b,0x46a1, { 0x91,0x78,0x82,0x52,0x5f,0x41,0x13,0x3f } }

#if ! (defined(MIDL_PASS))
DEFINE_GUID(MSDSM_DEVICEPATH_PERF_GUID, \
            0xa34d03ec,0x6b0b,0x46a1,0x91,0x78,0x82,0x52,0x5f,0x41,0x13,0x3f);
#endif


typedef struct _MSDSM_DEVICEPATH_PERF
{
    // Path Identifier.
    ULONGLONG PathId;
    #define MSDSM_DEVICEPATH_PERF_PathId_SIZE sizeof(ULONGLONG)
    #define MSDSM_DEVICEPATH_PERF_PathId_ID 1

    // Number of Read Requests.
    ULONG NumberReads;
    #define MSDSM_DEVICEPATH_PERF_NumberReads_SIZE sizeof(ULONG)
    #define MSDSM_DEVICEPATH_PERF_NumberReads_ID 2

    // Number of Write Requests.
    ULONG NumberWrites;
    #define MSDSM_DEVICEPATH_PERF_NumberWrites_SIZE sizeof(ULONG)
    #define MSDSM_DEVICEPATH_PERF_NumberWrites_ID 3

    // Total Bytes Read.
    ULONGLONG BytesRead;
    #define MSDSM_DEVICEPATH_PERF_BytesRead_SIZE sizeof(ULONGLONG)
    #define MSDSM_DEVICEPATH_PERF_BytesRead_ID 4

    // Total Bytes Written.
    ULONGLONG BytesWritten;
    #define MSDSM_DEVICEPATH_PERF_BytesWritten_SIZE sizeof(ULONGLONG)
    #define MSDSM_DEVICEPATH_PERF_BytesWritten_ID 5

} MSDSM_DEVICEPATH_PERF, *PMSDSM_DEVICEPATH_PERF;

#define MSDSM_DEVICEPATH_PERF_SIZE (FIELD_OFFSET(MSDSM_DEVICEPATH_PERF, BytesWritten) + MSDSM_DEVICEPATH_PERF_BytesWritten_SIZE)

// MSDSM_DEVICE_PERF - MSDSM_DEVICE_PERF
// Retrieve MSDSM Performance Information.
#define MSDSM_DEVICE_PERFGuid \
    { 0x875b8871,0x4889,0x4114, { 0x93,0xf6,0xcd,0x06,0x4c,0x00,0x1c,0xea } }

#if ! (defined(MIDL_PASS))
DEFINE_GUID(MSDSM_DEVICE_PERF_GUID, \
            0x875b8871,0x4889,0x4114,0x93,0xf6,0xcd,0x06,0x4c,0x00,0x1c,0xea);
#endif


typedef struct _MSDSM_DEVICE_PERF
{
    // Number of paths.
    ULONG NumberPaths;
    #define MSDSM_DEVICE_PERF_NumberPaths_SIZE sizeof(ULONG)
    #define MSDSM_DEVICE_PERF_NumberPaths_ID 1

    // Array of Performance Information per path for the device.
    MSDSM_DEVICEPATH_PERF PerfInfo[1];
    #define MSDSM_DEVICE_PERF_PerfInfo_ID 2

} MSDSM_DEVICE_PERF, *PMSDSM_DEVICE_PERF;

// MSDSM_WMI_METHODS - MSDSM_WMI_METHODS
// MSDSM WMI Methods
#define MSDSM_WMI_METHODSGuid \
    { 0x04517f7e,0x92bb,0x4ebe, { 0xae,0xd0,0x54,0x33,0x9f,0xa5,0xf5,0x44 } }

#if ! (defined(MIDL_PASS))
DEFINE_GUID(MSDSM_WMI_METHODS_GUID, \
            0x04517f7e,0x92bb,0x4ebe,0xae,0xd0,0x54,0x33,0x9f,0xa5,0xf5,0x44);
#endif

//
// Method id definitions for MSDSM_WMI_METHODS
#define MSDsmClearCounters     1

#endif
