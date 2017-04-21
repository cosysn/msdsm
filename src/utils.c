
/*++

Copyright (C) 2004-2010  Microsoft Corporation

Module Name:

    utils.c

Abstract:

    This driver is the Microsoft Device Specific Module (DSM).
    It exports behaviours that mpio.sys will use to determine how to
    multipath SPC-3 compliant devices.

    This file contains utility routines.

Environment:

    kernel mode only

Notes:

--*/

#include "precomp.h"
#include "debugs.h"

#ifdef DEBUG_USE_WPP
#include "utils.tmh"
#endif

#pragma warning (disable:4305)

extern BOOLEAN DoAssert;

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, DsmpBuildDeviceNameLegacyPage0x80)
    #pragma alloc_text(PAGE, DsmpBuildDeviceName)
    #pragma alloc_text(PAGE, DsmpApplyDeviceNameCorrection)
    #pragma alloc_text(PAGE, DsmpOpenLoadBalanceSettingsKey)
    #pragma alloc_text(PAGE, DsmpQueryLBPolicyForDevice)
    #pragma alloc_text(PAGE, DsmpOpenTargetsLoadBalanceSettingKey)
    #pragma alloc_text(PAGE, DsmpOpenDsmServicesParametersKey)
#endif

_Success_(return != NULL)
__drv_allocatesMem(Mem)
_When_(((PoolType&0x1))!=0, _IRQL_requires_max_(APC_LEVEL))
_When_(((PoolType&0x1))==0, _IRQL_requires_max_(DISPATCH_LEVEL))
_When_(((PoolType&0x2))!=0,
    __drv_reportError("Must succeed pool allocations are forbidden. "
    "Allocation failures cause a system crash"))
_When_(((PoolType&(0x2|POOL_RAISE_IF_ALLOCATION_FAILURE)))==0,
    _Post_maybenull_ _Must_inspect_result_)
_When_(((PoolType&(0x2|POOL_RAISE_IF_ALLOCATION_FAILURE)))!=0,
    _Post_notnull_ )
_When_((PoolType&NonPagedPoolMustSucceed)!=0,
    __drv_reportError("Must succeed pool allocations are forbidden. "
                      "Allocation failures cause a system crash"))
_Post_writable_byte_size_(NumberOfBytes)
PVOID
DsmpAllocatePool(
    _In_ _Strict_type_match_ IN POOL_TYPE PoolType,
    _In_ IN SIZE_T NumberOfBytes,
    _In_ IN ULONG Tag
    )
/*+++

Routine Description :

    Allocates memory from the specified pool using the given tag.
    If the allocation is successful, the entire buffer will be zeroed.

Arguements:

    PoolType - Pool to allocate from (NonPaged, Paged, etc)
    NumberOfBytes - Size of the buffer to allocate
    Tag - Tag (DSM_TAG_XXX) to be used for this allocation.
          These tags are defined in msdsm.h

Return Value:

    Pointer to the buffer if allocation is successful
    NULL otherwise

--*/
{
    PVOID Block = NULL;

    #pragma warning(suppress: 28118) // False-positive; PoolType is simply passed through
    Block = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
    if (Block) {
        RtlZeroMemory(Block, NumberOfBytes);
    }


    return Block;
}


_Success_(return != NULL)
_Post_maybenull_
_Must_inspect_result_
__drv_allocatesMem(Mem)
_Post_writable_byte_size_(*BytesAllocated)
_When_(((PoolType&0x1))!=0, _IRQL_requires_max_(APC_LEVEL))
_When_(((PoolType&0x1))==0, _IRQL_requires_max_(DISPATCH_LEVEL))
_When_((PoolType&NonPagedPoolMustSucceed)!=0,
    __drv_reportError("Must succeed pool allocations are forbidden. "
                      "Allocation failures cause a system crash"))
PVOID
#pragma warning(suppress:28195) // Allocation is not guaranteed, caller needs to check return value
DsmpAllocateAlignedPool(
    _In_ IN POOL_TYPE PoolType,
    _In_ IN SIZE_T NumberOfBytes,
    _In_ IN ULONG AlignmentMask,
    _In_ IN ULONG Tag,
    _Out_ OUT SIZE_T *BytesAllocated
    )
/*+++

Routine Description :

    Allocates memory from the specified pool using the given tag and alignment requirement.
    If the allocation is successful, the entire buffer will be zeroed.

Arguements:

    PoolType - Pool to allocate from (NonPaged, Paged, etc)
    NumberOfBytes - Size of the buffer to allocate
    AlignmentMask - Alignment requirement specified by the device
    Tag - Tag (DSM_TAG_XXX) to be used for this allocation.
          These tags are defined in msdsm.h
    BytesAllocated - Returns the number of bytes allocated, if the routine was successful

Return Value:

    Pointer to the buffer if allocation is successful
    NULL otherwise

--*/
{
    PVOID Block = NULL;
    UINT_PTR align64 = (UINT_PTR)AlignmentMask;
    ULONG totalSize = (ULONG)NumberOfBytes;
    NTSTATUS status = STATUS_SUCCESS;

    if (BytesAllocated == NULL) {

        status = STATUS_INVALID_PARAMETER;
        goto __Exit;
    }

    *BytesAllocated = 0;

    if (AlignmentMask) {

        status = RtlULongAdd((ULONG)NumberOfBytes, AlignmentMask, &totalSize);
    }

    if (NT_SUCCESS(status)) {

	#pragma warning(suppress: 6014 28118) // Block isn't leaked, this function is marked as an allocator; PoolType is simply passed through
        Block = ExAllocatePoolWithTag(PoolType, totalSize, Tag);

        if (Block != NULL) {

            if (AlignmentMask) {

                Block = (PVOID)(((UINT_PTR)Block + align64) & ~align64);
            }
        } else {

            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

__Exit:

    if (NT_SUCCESS(status)) {

        RtlZeroMemory(Block, totalSize);
        *BytesAllocated = totalSize;
    }


    return Block;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
DsmpFreePool(
    _In_opt_ __drv_freesMem(Mem) IN PVOID Block
    )
/*+++

Routine Description :

    Frees the block passed in.

Arguements:

    Block - pointer to the memory to free.

Return Value:

    Nothing

--*/
{
    PVOID tempAddress = Block;


    if (Block) {

        ExFreePool(Block);
        Block = NULL;
    }


    return;
}


NTSTATUS
DsmpGetStatsGatheringChoice(
    _In_ IN PDSM_CONTEXT Context,
    _Out_ OUT PULONG StatsGatherChoice
    )
/*++

Routine Description:

    This routine is used to determine if the Admin wants statitics to be collected
    on every IO. It queries the the services key for the value under
    "msdsm\Parameters\DsmDisableStatistics"

Arguments:

    Context - The DSM Context value.
    StatsGatherChoice - Returns the choice of whether or not to gather statistics

Return Value:

    Status of the RtlQueryRegistryValues call.

--*/
{
    RTL_QUERY_REGISTRY_TABLE queryTable[2];
    WCHAR registryKeyName[56] = {0};
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (!StatsGatherChoice) {


        goto __Exit_DsmpGetStatsGatherChoice;
    }

    RtlZeroMemory(queryTable, sizeof(queryTable));

    //
    // Build the key value name that we want as the base of the query.
    //
    RtlStringCbPrintfW(registryKeyName,
                       sizeof(registryKeyName),
                       DSM_PARAMETER_PATH_W);

    //
    // The query table has two entries. One for the supporteddeviceList and
    // the second which is the 'NULL' terminator.
    //
    queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK;
    queryTable[0].Name = DSM_DISABLE_STATISTICS;
    queryTable[0].EntryContext = StatsGatherChoice;
    queryTable[0].DefaultType  = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;

    status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES,
                                    registryKeyName,
                                    queryTable,
                                    registryKeyName,
                                    NULL);

__Exit_DsmpGetStatsGatherChoice:


    return status;
}


NTSTATUS
DsmpSetStatsGatheringChoice(
    _In_ IN PDSM_CONTEXT Context,
    _In_ IN ULONG StatsGatherChoice
    )
/*++

Routine Description:

    This routine is used to set the value that indicates whether statistics will
    be gathered on every IO. It updates the services key for the value under
    "msdsm\Parameters\DsmDisableStatistics"

Arguments:

    Context - The DSM Context value.
    StatsGatherChoice - Value indicating whether to gather statistics (TRUE) or not (FALSE)

Return Value:

    Status of the RtlWriteRegistryValue call.

--*/
{
    WCHAR registryKeyName[56] = {0};
    NTSTATUS status = STATUS_SUCCESS;

 

    //
    // Build the key value name that we want as the base of the query.
    //
    RtlStringCbPrintfW(registryKeyName,
                       sizeof(registryKeyName),
                       DSM_PARAMETER_PATH_W);


    status = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES,
                                   registryKeyName,
                                   DSM_DISABLE_STATISTICS,
                                   REG_DWORD,
                                   &StatsGatherChoice,
                                   sizeof(ULONG));


    return status;
}



NTSTATUS
DsmpGetDeviceList(
    _In_ IN PDSM_CONTEXT Context
    )
/*++

Routine Description:

    This routine is used to build the supported device list by querying the services
    key for the values under "msdsm\Parameters\DsmSupportedDeviceList"

Arguments:

    Context - The DSM Context value. It contains storage for the multi_sz string that may
              be built.

Return Value:

    Status of the RtlQueryRegistryValues call.

--*/
{
    RTL_QUERY_REGISTRY_TABLE queryTable[2];
    WCHAR registryKeyName[56] = {0};
    UNICODE_STRING inquiryStrings;
    WCHAR defaultIDs[] = { L"\0" };
    NTSTATUS status;

    RtlZeroMemory(queryTable, sizeof(queryTable));
    RtlInitUnicodeString(&inquiryStrings, NULL);

    //
    // Build the key value name that we want as the base of the query.
    //
    RtlStringCbPrintfW(registryKeyName,
                       sizeof(registryKeyName),
                       DSM_PARAMETER_PATH_W);

    //
    // The query table has two entries. One for the supporteddeviceList and
    // the second which is the 'NULL' terminator.
    //
    // Indicate that there is NO call-back routine, and to give back the MULTI_SZ as
    // one blob, as opposed to individual unicode strings.
    //
    queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND | RTL_QUERY_REGISTRY_TYPECHECK;

    //
    // The value to query.
    //
    queryTable[0].Name = DSM_SUPPORTED_DEVICELIST_VALUE_NAME;

    //
    // Where to put the strings. Note that we need to use an empty unicode_string
    // for the query or else RtlQueryRegistryValues will only fill in enough
    // entries as specified by the size of the unicode string's buffer, which
    // is why we can't use Context->SupportedDevices directly in the call.
    //
    queryTable[0].EntryContext = &inquiryStrings;
    queryTable[0].DefaultType  = (REG_MULTI_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_MULTI_SZ;
    queryTable[0].DefaultData = defaultIDs;
    queryTable[0].DefaultLength = sizeof(defaultIDs);

    status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES,
                                    registryKeyName,
                                    queryTable,
                                    registryKeyName,
                                    NULL);

    //
    // If we successfully queried for the supported device list, we need to delete
    // our cached list and update it with this new one.
    //
    if (NT_SUCCESS(status)) {

        KIRQL oldIrql;
        PWCHAR tempBuffer = NULL;

        tempBuffer = DsmpAllocatePool(NonPagedPoolNx, inquiryStrings.MaximumLength, DSM_TAG_REG_VALUE_RELATED);

        //
        // This is a "best effort" operation. If we are unable to allocate a
        // buffer for the strings, we just continue using our old cached list.
        // We do NOT fall back to using inquiryStrings's buffer as we want to
        // be able to work with the supported devices list at raised IRQL.
        //
        if (tempBuffer) {

            RtlCopyMemory(tempBuffer, inquiryStrings.Buffer, inquiryStrings.Length);

            KeAcquireSpinLock(&Context->SupportedDevicesListLock, &oldIrql);
            DsmpFreePool(Context->SupportedDevices.Buffer);
            Context->SupportedDevices.Buffer = tempBuffer;
            Context->SupportedDevices.Length = inquiryStrings.Length;
            Context->SupportedDevices.MaximumLength = inquiryStrings.MaximumLength;
            KeReleaseSpinLock(&Context->SupportedDevicesListLock, oldIrql);

        } else {


            status =  STATUS_INSUFFICIENT_RESOURCES;
        }

        ExFreePool(inquiryStrings.Buffer);
    }


    return status;
}


_Success_(return==0)
NTSTATUS
DsmpGetStandardInquiryData(
    _In_ IN PDEVICE_OBJECT DeviceObject,
    _Out_ OUT PINQUIRYDATA InquiryData
    )
/*++

Routine Description:

    Helper routine to send an inquiry with EVPD cleared to get the standard inquiry data.

Arguments:

    DeviceObject - The port PDO to which the command should be sent.
    InquiryData - Pointer to inquiry data that will be returned to caller.

Return Value:

    STATUS_SUCCESS or failure NTSTATUS code.

--*/
{
    PSCSI_PASS_THROUGH_WITH_BUFFERS passThrough = NULL;
    PCDB cdb;
    IO_STATUS_BLOCK ioStatus;
    ULONG length;
    NTSTATUS status = STATUS_SUCCESS;
    PINQUIRYDATA inquiryData;
    PSENSE_DATA senseData;


    if (InquiryData == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto __Exit_DsmpGetStandardInquiryData;
    }

    //
    // Build a standard inquiry command.
    //
    length = sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS);

    passThrough = DsmpAllocatePool(NonPagedPoolNx,
                                   length,
                                   DSM_TAG_PASS_THRU);
    if (!passThrough) {


        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpGetStandardInquiryData;
    }

__Retry_Request:

    //
    // Build the cdb for SCSI-3 standard inquiry.
    //
    cdb = (PCDB)passThrough->ScsiPassThrough.Cdb;
    cdb->CDB6INQUIRY3.OperationCode = SCSIOP_INQUIRY;
    cdb->CDB6INQUIRY3.EnableVitalProductData = 0;
    cdb->CDB6INQUIRY3.AllocationLength = sizeof(INQUIRYDATA);

    passThrough->ScsiPassThrough.Length = sizeof(SCSI_PASS_THROUGH);
    passThrough->ScsiPassThrough.CdbLength = 6;
    passThrough->ScsiPassThrough.SenseInfoLength = SPTWB_SENSE_LENGTH;
    passThrough->ScsiPassThrough.DataIn = 1;
    passThrough->ScsiPassThrough.DataTransferLength = sizeof(INQUIRYDATA);
    passThrough->ScsiPassThrough.TimeOutValue = 20;
    passThrough->ScsiPassThrough.SenseInfoOffset = FIELD_OFFSET(SCSI_PASS_THROUGH_WITH_BUFFERS, SenseInfoBuffer);
    passThrough->ScsiPassThrough.DataBufferOffset = FIELD_OFFSET(SCSI_PASS_THROUGH_WITH_BUFFERS, DataBuffer);

    DsmSendDeviceIoControlSynchronous(IOCTL_SCSI_PASS_THROUGH,
                                      DeviceObject,
                                      passThrough,
                                      passThrough,
                                      length,
                                      length,
                                      FALSE,
                                      &ioStatus);

    status = ioStatus.Status;
    senseData = (PSENSE_DATA)(passThrough->SenseInfoBuffer);

	TracePrintEx("DsmInquire (DevObj %p): DsmpGetStandardInquiryData status: %x.\n", DeviceObject, status);

    if ((passThrough->ScsiPassThrough.ScsiStatus == SCSISTAT_GOOD) && (NT_SUCCESS(status))) {

        //
        // Get the returned data.
        //
        inquiryData = (PINQUIRYDATA)(passThrough->DataBuffer);

        RtlCopyMemory(InquiryData, inquiryData, sizeof(INQUIRYDATA));

    } else if ((passThrough->ScsiPassThrough.ScsiStatus == SCSISTAT_CHECK_CONDITION) &&
               (NT_SUCCESS(ioStatus.Status)) &&
               (DsmpShouldRetryPassThroughRequest(senseData, passThrough->ScsiPassThrough.SenseInfoLength))) {

        length = sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS);

        //
        // Retry the request
        //
        RtlZeroMemory(passThrough, length);
        goto __Retry_Request;

    } else {

        // Failed to get inquiry data
        // Here it is possible that status is success, but scsi status is not.
        // If so, set status to unsuccessful.
        if (NT_SUCCESS(status)){
            status = STATUS_UNSUCCESSFUL;
        }

    }

__Exit_DsmpGetStandardInquiryData:

    //
    // Free the passthrough + data buffer.
    //
    if (passThrough) {
        DsmpFreePool(passThrough);
    }


    return status;
}


BOOLEAN
DsmpCheckScsiCompliance(
    _In_ IN PDEVICE_OBJECT TargetObject,
    _In_ IN PINQUIRYDATA InquiryData,
    _In_ IN PSTORAGE_DEVICE_DESCRIPTOR Descriptor,
    _In_ IN PSTORAGE_DEVICE_ID_DESCRIPTOR DeviceIdList
    )
/*++

Routine Description:

    Helper routine to determine if the device is SPC-3 compliant.

Arguments:

    DeviceObject - The port PDO that we're determining compliance for.
    InquiryData - Pointer to its inquiry data.
    Descriptor - Pointer to its VPD page 0x80 data
    DeviceIdList - Pointer to its VPD page 0x83 data

Return Value:

    TRUE if compliant, else FALSE.

--*/
{
    BOOLEAN supported = FALSE /* TRUE */;
    UCHAR deviceType;
    UCHAR qualifier;

    UNREFERENCED_PARAMETER(DeviceIdList);
    UNREFERENCED_PARAMETER(Descriptor);


    deviceType = InquiryData->DeviceType & 0x1F;
    qualifier = (InquiryData->DeviceTypeQualifier >> 0x5) & 0x7;

    if ((deviceType | qualifier) == 0x7F) {

        supported = FALSE;
    }

	supported = TRUE;

    return supported;
}


BOOLEAN
DsmpDeviceSupported(
    _In_ IN PDSM_CONTEXT Context,
    _In_ IN PCSTR VendorId,
    _In_ IN PCSTR ProductId
    )
/*++

Routine Description:

    This routine determines whether the device is supported by traversing the SupportedDevice
    list and comparing to the VendorId/ProductId values passed in.

Arguments:

    Context   - Context value given to the multipath driver during registration.
    VendorId - Pointer to the inquiry data VendorId.
    ProductId - Pointer to the inquiry data ProductId.

Return Value:

    TRUE - If VendorId/ProductId is found.

--*/
{
    UNICODE_STRING deviceName;
    UNICODE_STRING productName;
    ANSI_STRING ansiVendor;
    ANSI_STRING ansiProduct;
    NTSTATUS status;
    BOOLEAN supported = FALSE;
    KIRQL oldIrql;
    UNICODE_STRING tempStrings;


    KeAcquireSpinLock(&Context->SupportedDevicesListLock, &oldIrql);

    RtlInitUnicodeString(&tempStrings, NULL);
    tempStrings.Buffer = DsmpAllocatePool(NonPagedPoolNx, Context->SupportedDevices.MaximumLength, DSM_TAG_REG_VALUE_RELATED);

    if (tempStrings.Buffer) {

        RtlCopyMemory(tempStrings.Buffer, Context->SupportedDevices.Buffer, Context->SupportedDevices.Length);
        tempStrings.Length = Context->SupportedDevices.Length;
        tempStrings.MaximumLength = Context->SupportedDevices.MaximumLength;

    } else {

        status = STATUS_INSUFFICIENT_RESOURCES;

        KeReleaseSpinLock(&Context->SupportedDevicesListLock, oldIrql);

        goto __Exit_DsmpDeviceSupported;
    }

    KeReleaseSpinLock(&Context->SupportedDevicesListLock, oldIrql);

    //
    // The SupportedDevice list was built in DriverEntry from the services key.
    //
    if (tempStrings.MaximumLength == 0) {

        //
        // List is empty.

        goto __Exit_DsmpDeviceSupported;
    }

    RtlInitUnicodeString(&productName, NULL);

    //
    // Convert the inquiry fields into ansi strings.
    //
    RtlInitAnsiString(&ansiVendor, VendorId);
    RtlInitAnsiString(&ansiProduct, ProductId);

    //
    // Allocate the deviceName buffer. Needs to be 8+16 plus NULL.
    // (productId length + vendorId length + NULL).
    //
    deviceName.MaximumLength = 25 * sizeof(WCHAR);
    deviceName.Buffer = DsmpAllocatePool(PagedPool, deviceName.MaximumLength, DSM_TAG_SUPPORTED_DEV);

    if (deviceName.Buffer) {

        //
        // Convert the vendorId to unicode.
        //
        status = RtlAnsiStringToUnicodeString(&deviceName, &ansiVendor, FALSE);
        if (NT_SUCCESS(status)) {

            //
            // Convert the productId to unicode.
            //
            status = RtlAnsiStringToUnicodeString(&productName, &ansiProduct, TRUE);

            if (NT_SUCCESS(status)) {

                //
                // 'cat' them.
                //
                status = RtlAppendUnicodeStringToString(&deviceName, &productName);

                if (NT_SUCCESS(status)) {

                    //
                    // Run the list of supported devices that was captured from the registry
                    // and see if this one is in the list.
                    //
                    supported = DsmpFindSupportedDevice(&deviceName,
                                                        &tempStrings);
                }
            } else {

            }
        } else {

        }

        DsmpFreePool(deviceName.Buffer);

    } else {

    }

__Exit_DsmpDeviceSupported:

    if (tempStrings.Buffer) {
        DsmpFreePool(tempStrings.Buffer);
    }

    return supported;
}


BOOLEAN
DsmpFindSupportedDevice(
    _In_ IN PUNICODE_STRING DeviceName,
    _In_ IN PUNICODE_STRING SupportedDevices
    )
/*++

Routine Description:

    This routine compares the two unicode strings for a match.

Arguments:

    DeviceName - String built from the current device's inquiry data.
    SupportedDevices - MULTI_SZ of devices that are supported.

Return Value:

    TRUE - If VendorId/ProductId is found.

--*/
{
    PWSTR devices = SupportedDevices->Buffer;
    ULONG bufferLengthLeft = SupportedDevices->MaximumLength / sizeof(WCHAR);
    UNICODE_STRING unicodeString;
    USHORT originalLength = DeviceName->Length;
    LONG compare;
    BOOLEAN supported = FALSE;
    WCHAR tempString[32];


    //
    // 'devices' is the current buffer in the MULTI_SZ built from
    // the registry.
    //
    while (devices[0]) {

        RtlZeroMemory(tempString, sizeof(tempString));

        if (!NT_SUCCESS(RtlStringCchCopyNW(tempString, sizeof(tempString) / sizeof(tempString[0]), devices, bufferLengthLeft))) {

            tempString[(sizeof(tempString) / sizeof(tempString)) - 1] = L'\0';
        }

        //
        // Make the current entry into a unicode string.
        //
        RtlInitUnicodeString(&unicodeString, tempString);

        //
        // Compare this one with the current device.
        // However, for storages that make up the product id on-the-fly, MPIO
        // allows for matching based just on substring (product-id-prefix so to
        // speak).
        //
        if (unicodeString.Length < DeviceName->Length) {
            DeviceName->Length = unicodeString.Length;
        }

        compare = RtlCompareUnicodeStrings(unicodeString.Buffer,
                                           unicodeString.Length / sizeof(WCHAR),
                                           DeviceName->Buffer,
                                           DeviceName->Length / sizeof(WCHAR),
                                           TRUE);

        DeviceName->Length = originalLength;

        if (compare == 0) {


            supported = TRUE;
            break;
        }

        //
        // Advance to next entry in the MULTI_SZ.
        //
        devices += (unicodeString.MaximumLength / sizeof(WCHAR));

        bufferLengthLeft -= (unicodeString.MaximumLength / sizeof(WCHAR));
    }

    return supported;
}

_Success_(return!=0)
PVOID
DsmpParseDeviceID(
    _In_ IN PSTORAGE_DEVICE_ID_DESCRIPTOR DeviceID,
    _In_ IN DSM_DEVID_TYPE DeviceIdType,
    _In_opt_ IN PULONG IdNumber,
    _Out_opt_ OUT PSTORAGE_IDENTIFIER_CODE_SET CodeSet,
    _In_ IN BOOLEAN Legacy
    )
/*++

Routine Description:

    This routine builds a serial number string based on the information
    in the VPD page 0x83 data if serial number is requested, else it
    returns the appropriate identifier requested.

    Caller must free the buffer.

Arguments:

    DeviceIdList - VPD Page 0x83 information.
    DeviceIdType - Type of identifier that the DeviceID is being parsed for
    IdNumber - If there are multiple identifiers of type DeviceIdType, this parameter
                   determines which among them to actually return.
                   IMPORTANT: This number is one-based (not zero-based).
    CodeSet - Of relevance only if the DeviceIdType is DSM_DEVID_SERIAL_NUMBER. This
                   returns the code set that was used when building the serial number.
    Legacy - Of relevance only if the DeviceIdType is DSM_DEVID_SERIAL_NUMBER. If the
                   code set of the identifier is StorageIdCodeSetBinary, this determines
                   whether to use the legacy method of binary to ascii conversion.

Return Value:

    Requested Device identifier.

--*/
{
    PSTORAGE_IDENTIFIER identifier;
    STORAGE_IDENTIFIER_CODE_SET codeSet = StorageIdCodeSetReserved; // Preload with a bogus value.
    STORAGE_IDENTIFIER_TYPE type = 0xF;
    STORAGE_ASSOCIATION_TYPE association = 0xF;
    ULONG numberIds;
    ULONG i;
    ULONG identifierSize = 0;
    PUCHAR bytes = NULL;
    PVOID buffer = NULL;
    BOOLEAN done = FALSE;
    ULONG idNumber = MAXULONG;
    ULONG matches = 0;


    if (IdNumber) {
        idNumber = *IdNumber;
    }

    //
    // Get the number of encapsulated identifiers.
    //
    numberIds = DeviceID->NumberOfIdentifiers;

    if (idNumber != MAXULONG && idNumber > numberIds) {
        goto __Exit_DsmpParseDeviceID;
    }

    //
    // Get a pointer to the first one.
    //
    identifier = (PSTORAGE_IDENTIFIER)(DeviceID->Identifiers);

    for (i = 0; i < numberIds && !done; i++) {

        switch (DeviceIdType) {

            case DSM_DEVID_SERIAL_NUMBER: {

                //
                // The way this works is that we will go through all the identifiers
                // Order of preference will be LUN-associated over Target-associated.
                // Further, upon same association, preference will be based on type as
                // follows: 0x8, 0x3, 0x2, 0x1, 0x0.
                // So an existing identifier will be discarded if a better one is found.
                // If two identifiers have the same type, we will prefer the one will
                // the larger length.
                //

                //
                // 1. Ensure that the association is for either the LUN or target. (If neither, ignore id).
                // 2. If association is with target, don't it consider if current candidate has assocation with LUN.
                // 3. If considering this identifier, order of preference is 8 > 3 > 2 > 1 > 0.
                // 4. If this id type is same as current candidate, consider it only if it is of greater length.
                //
                if (((identifier->Association == StorageIdAssocDevice) ||
                     (identifier->Association == 0x2 && association != StorageIdAssocDevice)) &&
                    ((type == identifier->Type && identifierSize < identifier->IdentifierSize) ||
                     (type != identifier->Type && DsmpIsPreferredDeviceId(type, identifier->Type)))) {

                    //
                    // Get a pointer to the id itself.
                    //
                    bytes = identifier->Identifier;

                    //
                    // The id's size.
                    //
                    identifierSize = identifier->IdentifierSize;

                    //
                    // Get the type, code set, and association.
                    //
                    type = identifier->Type;
                    codeSet = identifier->CodeSet;
                    association = identifier->Association;

                    matches++;
                }

                break;
            }

            case DSM_DEVID_RELATIVE_TARGET_PORT: {

                //
                // Ensure that the association is for the target port.
                //
                if (identifier->Association != StorageIdAssocPort) {

                    if ((i + 1) < numberIds) {
                        identifier = (PSTORAGE_IDENTIFIER)((PUCHAR)identifier + identifier->NextOffset);
                    }

                    continue;
                }

                if (identifier->Type == StorageIdTypePortRelative) {

                    //
                    // Get a pointer to the id itself.
                    //
                    bytes = identifier->Identifier;

                    //
                    // The id's size.
                    //
                    identifierSize = identifier->IdentifierSize;

                    type = identifier->Type;
                    codeSet = identifier->CodeSet;
                    association = identifier->Association;

                    matches++;
                }

                break;
            }

            case DSM_DEVID_TARGET_PORT_GROUP: {

                //
                // Ensure that the association is for the target port.
                //
                if (identifier->Association != StorageIdAssocPort) {

                    if ((i + 1) < numberIds) {
                        identifier = (PSTORAGE_IDENTIFIER)((PUCHAR)identifier + identifier->NextOffset);
                    }

                    continue;
                }

                if (identifier->Type == 0x5) {

                    //
                    // Get a pointer to the id itself.
                    //
                    bytes = identifier->Identifier;

                    //
                    // Move this by two bytes because first two bytes are reservered
                    //
                    bytes += sizeof(USHORT);

                    //
                    // The id's size. Reduce the size by 2 bytes (to account
                    // for the reservered bytes)
                    //
                    identifierSize = identifier->IdentifierSize - sizeof(USHORT);

                    type = identifier->Type;
                    codeSet = identifier->CodeSet;
                    association = identifier->Association;

                    matches++;
                }

                break;
            }

            default: break;
        }


        if (idNumber != MAXULONG && idNumber == matches) {
            done = TRUE;
        }

        //
        // Advance to the next identifier in the buffer.
        //
        if ((i + 1) < numberIds) {
            identifier = (PSTORAGE_IDENTIFIER)((PUCHAR)identifier + identifier->NextOffset);
        }
    }

    if (idNumber != MAXULONG && idNumber > matches) {
        goto __Exit_DsmpParseDeviceID;
    }

    if (DeviceIdType == DSM_DEVID_SERIAL_NUMBER) {

        if (type != StorageIdTypeScsiNameString &&
            type != StorageIdTypeFCPHName &&
            type != StorageIdTypeEUI64 &&
            type != StorageIdTypeVendorId &&
            type != StorageIdTypeVendorSpecific) {

            DSM_ASSERT(FALSE);
            bytes = NULL;
            identifierSize = 0;
            type = association = 0xF;
            codeSet = StorageIdCodeSetReserved;
        }


        if (!bytes) {
            goto __Exit_DsmpParseDeviceID;
        }

        if (codeSet == StorageIdCodeSetBinary) {

            //
            // Need to convert to ascii.
            //
            buffer = DsmpBinaryToAscii(bytes,
                                       identifierSize,
                                       &identifierSize,
                                       Legacy);

        } else {

            if (identifierSize) {
                //
                // Allocate a buffer that is the size of the data, plus one for NULL.
                //
                buffer = DsmpAllocatePool(NonPagedPoolNx, identifierSize + 1, DSM_TAG_DEV_ID);
                DSM_ASSERT(buffer);

                if (buffer) {

                    //
                    // Copy over the id.
                    //
                    RtlCopyMemory(buffer, bytes, identifierSize);
                }
            }
        }

        if (CodeSet) {
            *CodeSet = codeSet;
        }

    } else {

        if (identifierSize) {

            DSM_ASSERT((DeviceIdType == DSM_DEVID_RELATIVE_TARGET_PORT && identifierSize == sizeof(ULONG)) ||
                       (DeviceIdType == DSM_DEVID_TARGET_PORT_GROUP && identifierSize == sizeof(USHORT)));

            _Analysis_assume_((DeviceIdType == DSM_DEVID_RELATIVE_TARGET_PORT && identifierSize == sizeof(ULONG)) ||
                              (DeviceIdType == DSM_DEVID_TARGET_PORT_GROUP && identifierSize == sizeof(USHORT)));

            buffer = DsmpAllocatePool(NonPagedPoolNx, identifierSize, DSM_TAG_DEV_ID);

            if (buffer) {

                if (DeviceIdType == DSM_DEVID_RELATIVE_TARGET_PORT) {

                    GetUlongFrom4ByteArray(bytes, *((PULONG)buffer));

                } else if (DeviceIdType == DSM_DEVID_TARGET_PORT_GROUP) {

                    *((PUSHORT)buffer) = (bytes[0] << 8) | (bytes[1]);
                }
            }
        }
    }

__Exit_DsmpParseDeviceID:


    return buffer;
}


PUCHAR
DsmpBinaryToAscii(
    _In_reads_(Length) IN PUCHAR HexBuffer,
    _In_ IN ULONG Length,
    _Inout_ IN OUT PULONG UpdateLength,
    _In_ IN BOOLEAN Legacy
    )
/*++

Routine Description:

    This routine will convert HexBuffer into an ascii NULL-terminated string.

    Note: This routine will allocate memory for storing the ascii string. It is
          the responsibility of the caller to free this buffer.

Arguments:

    HexBuffer - Pointer to the binary data.
    Length - Length, in bytes, of HexBuffer.
    UpdateLength - Storage to place the actual length of the returned string.
    Legacy - Use the legacy method for the conversion.

Return Value:

    Serial Number string, or NULL if an error occurred.

--*/
{
    static UCHAR IntegerTable[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    ULONG i;
    ULONG j;
    ULONG actualLength;
    PUCHAR buffer = NULL;
    UCHAR highWord;
    UCHAR lowWord;


    if (Length == 0) {
        *UpdateLength = 0;
        goto __Exit_DsmpBinaryToAscii;
    }

    if (Legacy) {
        //
        // Do a pre-test on the buffer to determine the length actually needed.
        //
        for (i = 0, actualLength = 0; i < Length; i++) {

            if (HexBuffer[i] < 0x10) {
                actualLength++;
            } else {
                actualLength += 2;
            }
        }

        //
        // Add room for a terminating NULL.
        //
        actualLength++;
    } else {
        //
        // We need one character for each nibble, plus one for the terminating NULL.
        //
        actualLength = (Length * 2) + 1;
    }

    //
    // Allocate the buffer.
    //
    buffer = DsmpAllocatePool(NonPagedPoolNx,
                              actualLength,
                              DSM_TAG_BIN_TO_ASCII);
    if (!buffer) {
        *UpdateLength = 0;
        goto __Exit_DsmpBinaryToAscii;
    }

    for (i = 0, j = 0; i < Length && j < actualLength; i++) {

        if (Legacy && (HexBuffer[i] < 0x10)) {

            //
            // If legacy is mentioned and it's 0x0F or less,
            // just convert the entire byte.
            //
            buffer[j++] = IntegerTable[HexBuffer[i]];
        } else {

            //
            // Split out each nibble from the binary byte.
            //
            highWord = HexBuffer[i] >> 4;
            lowWord = HexBuffer[i] & 0x0F;

            //
            // Using the lookup table, convert and stuff into
            // the ascii buffer.
            //
            buffer[j++] = IntegerTable[highWord];
            buffer[j++] = IntegerTable[lowWord];
        }
    }

    //
    // Update the caller's length field.
    //
    *UpdateLength = actualLength;

__Exit_DsmpBinaryToAscii:


    return buffer;
}


PSTR
DsmpGetSerialNumber(
    _In_ IN PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    Helper routine to send an inquiry with EVPD set to get the serial number page.
    Used if the serial number is not embedded in the device descriptor (this device probably
    doesn't support VPD page 0x00).

    Note: This routine will allocate memory for storing the serial number. It is
          the responsibility of the caller to free this buffer.

Arguments:

    DeviceObject - The port PDO to which the command should be sent.

Return Value:

    The serial number (null-terminated string) or NULL if the call fails.

--*/
{
    PSCSI_PASS_THROUGH_WITH_BUFFERS passThrough = NULL;
    PVPD_SERIAL_NUMBER_PAGE serialPage;
    PCDB cdb;
    PSTR serialNumber = NULL;
    IO_STATUS_BLOCK ioStatus;
    ULONG length;


    //
    // Build an inquiry command with EVPD and pagecode of 0x80 (serial number).
    //
    length = sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS);

    passThrough = DsmpAllocatePool(NonPagedPoolNx,
                                   length,
                                   DSM_TAG_PASS_THRU);
    if (!passThrough) {

        goto __Exit_DsmpGetSerialNumber;
    }

    //
    // Build the cdb.
    //
    cdb = (PCDB)passThrough->ScsiPassThrough.Cdb;
    cdb->CDB6INQUIRY.OperationCode = SCSIOP_INQUIRY;
    cdb->CDB6INQUIRY.Reserved1 = 1;
    cdb->CDB6INQUIRY.PageCode = VPD_SERIAL_NUMBER;
    cdb->CDB6INQUIRY.AllocationLength = DSM_SERIAL_NUMBER_BUFFER_SIZE;

    passThrough->ScsiPassThrough.Length = sizeof(SCSI_PASS_THROUGH);
    passThrough->ScsiPassThrough.CdbLength = 6;
    passThrough->ScsiPassThrough.SenseInfoLength = SPTWB_SENSE_LENGTH;
    passThrough->ScsiPassThrough.DataIn = 1;
    passThrough->ScsiPassThrough.DataTransferLength = DSM_SERIAL_NUMBER_BUFFER_SIZE;
    passThrough->ScsiPassThrough.TimeOutValue = 20;
    passThrough->ScsiPassThrough.SenseInfoOffset = FIELD_OFFSET(SCSI_PASS_THROUGH_WITH_BUFFERS, SenseInfoBuffer);
    passThrough->ScsiPassThrough.DataBufferOffset = FIELD_OFFSET(SCSI_PASS_THROUGH_WITH_BUFFERS, DataBuffer);

    DsmSendDeviceIoControlSynchronous(IOCTL_SCSI_PASS_THROUGH,
                                      DeviceObject,
                                      passThrough,
                                      passThrough,
                                      length,
                                      length,
                                      FALSE,
                                      &ioStatus);
    if ((passThrough->ScsiPassThrough.ScsiStatus == SCSISTAT_GOOD) &&
        (NT_SUCCESS(ioStatus.Status))) {

        ULONG inx;

        //
        // Get the returned data.
        //
        serialPage = (PVPD_SERIAL_NUMBER_PAGE)(passThrough->DataBuffer);

        //
        // Allocate a buffer to hold just the serial number plus a null terminator
        //
        serialNumber = DsmpAllocatePool(NonPagedPoolNx,
                                        serialPage->PageLength + 1,
                                        DSM_TAG_SERIAL_NUM);
        if (serialNumber) {

            //
            // Copy it over.
            //
            RtlCopyMemory(serialNumber, serialPage->SerialNumber, serialPage->PageLength);

            //
            // Some devices return binary data for the serial number.
            // Convert to a more ascii-ish format so that other routines don't have a problem.
            //
            for (inx = 0; inx < serialPage->PageLength; inx++) {
                if (serialNumber[inx] == '\0') {
                    serialNumber[inx] = ' ';
                }
            }
        } else {

        }
    } else {

    }

__Exit_DsmpGetSerialNumber:

    //
    // Free the passthrough + data buffer.
    //
    if (passThrough) {

        DsmpFreePool(passThrough);
    }


    //
    // Return the sn.
    //
    return serialNumber;
}


NTSTATUS
DsmpDisableImplicitStateTransition(
    _In_ IN PDEVICE_OBJECT TargetDevice,
    _Out_ OUT PBOOLEAN DisableImplicit
    )
/*++

Routine Description:

    Send down request to disable implicit ALUA state transition.
    The function first sends down a mode sense to get the control extension mode
    sense data. It then clears the IALUAE bit and sends down a mode select.

Arguements:

    TargetDevice - Device object that will be target of this command.
    DisableImplicit - Flag returned to the caller to indicate whether or not
                      implicit transitions are disabled.

Return Value :

    STATUS_SUCCESS if the command succeeds.
    Appropriate NTSTATUS code on failure

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PSCSI_PASS_THROUGH_WITH_BUFFERS passThrough = NULL;
    PCDB cdb;
    IO_STATUS_BLOCK ioStatus;
    ULONG length;
    PSPC3_CONTROL_EXTENSION_MODE_PAGE controlExtensionPage = NULL;
    PSENSE_DATA senseData = NULL;
    BOOLEAN implicitDisabled = FALSE;


    //
    // First build the mode sense command to get the control extension parameters.
    //
    length = sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS);

    passThrough = DsmpAllocatePool(NonPagedPoolNx,
                                   length,
                                   DSM_TAG_PASS_THRU);
    if (!passThrough) {


        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpDisableImplicitStateTransition;
    }

__Retry_ModeSense:

    passThrough->ScsiPassThrough.Length = sizeof(SCSI_PASS_THROUGH);
    passThrough->ScsiPassThrough.CdbLength = 6;
    passThrough->ScsiPassThrough.SenseInfoLength = SPTWB_SENSE_LENGTH;
    passThrough->ScsiPassThrough.DataIn = 1;
    passThrough->ScsiPassThrough.DataTransferLength = sizeof(SPC3_CONTROL_EXTENSION_MODE_PAGE);
    passThrough->ScsiPassThrough.TimeOutValue = 20;
    passThrough->ScsiPassThrough.SenseInfoOffset = FIELD_OFFSET(SCSI_PASS_THROUGH_WITH_BUFFERS, SenseInfoBuffer);
    passThrough->ScsiPassThrough.DataBufferOffset = FIELD_OFFSET(SCSI_PASS_THROUGH_WITH_BUFFERS, DataBuffer);

    //
    // Build the cdb for mode sense.
    //
    cdb = (PCDB)passThrough->ScsiPassThrough.Cdb;
    cdb->MODE_SENSE.OperationCode = SCSIOP_MODE_SENSE;
    cdb->MODE_SENSE.Dbd = 1;
    cdb->MODE_SENSE.PageCode = 0xA;
    cdb->MODE_SENSE.SubPageCode = 0x01;
    cdb->MODE_SENSE.AllocationLength = sizeof(SPC3_CONTROL_EXTENSION_MODE_PAGE);

    DsmSendDeviceIoControlSynchronous(IOCTL_SCSI_PASS_THROUGH,
                                      TargetDevice,
                                      passThrough,
                                      passThrough,
                                      length,
                                      length,
                                      FALSE,
                                      &ioStatus);

    status = ioStatus.Status;
    senseData = (PSENSE_DATA)(passThrough->SenseInfoBuffer);

    if ((passThrough->ScsiPassThrough.ScsiStatus == SCSISTAT_GOOD) && (NT_SUCCESS(status))) {

        controlExtensionPage = (PSPC3_CONTROL_EXTENSION_MODE_PAGE)(passThrough->DataBuffer);

        if (controlExtensionPage->ImplicitALUAEnable) {

            controlExtensionPage->ImplicitALUAEnable = 0;

__Retry_ModeSelect:

            RtlZeroMemory(passThrough->SenseInfoBuffer, passThrough->ScsiPassThrough.SenseInfoLength);

            passThrough->ScsiPassThrough.DataIn = 0;

            //
            // Build the cdb for mode select.
            //
            RtlZeroMemory(cdb, 6);
            cdb->MODE_SELECT.OperationCode = SCSIOP_MODE_SELECT;
            cdb->MODE_SELECT.SPBit = 0;
            cdb->MODE_SELECT.PFBit = 1;
            cdb->MODE_SELECT.ParameterListLength = sizeof(SPC3_CONTROL_EXTENSION_MODE_PAGE);

            length = sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS);

            DsmSendDeviceIoControlSynchronous(IOCTL_SCSI_PASS_THROUGH,
                                              TargetDevice,
                                              passThrough,
                                              passThrough,
                                              length,
                                              length,
                                              FALSE,
                                              &ioStatus);

            status = ioStatus.Status;
            senseData = (PSENSE_DATA)(passThrough->SenseInfoBuffer);

            if ((passThrough->ScsiPassThrough.ScsiStatus == SCSISTAT_GOOD) && (NT_SUCCESS(status))) {

                implicitDisabled = TRUE;


            } else if ((passThrough->ScsiPassThrough.ScsiStatus == SCSISTAT_CHECK_CONDITION) &&
                       (NT_SUCCESS(status)) &&
                       (DsmpShouldRetryPassThroughRequest(senseData, passThrough->ScsiPassThrough.SenseInfoLength))) {

                //
                // Retry the request
                //
                goto __Retry_ModeSelect;

            } else {

            }
        } else {

            implicitDisabled = TRUE;

        }
    } else if ((passThrough->ScsiPassThrough.ScsiStatus == SCSISTAT_CHECK_CONDITION) &&
               (NT_SUCCESS(status)) &&
               (DsmpShouldRetryPassThroughRequest(senseData, passThrough->ScsiPassThrough.SenseInfoLength))) {

        length = sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS);

        //
        // Retry the request
        //
        RtlZeroMemory(passThrough, length);
        goto __Retry_ModeSense;

    } else {
    }

__Exit_DsmpDisableImplicitStateTransition:

    //
    // Free the passthrough + data buffer.
    //
    if (passThrough) {
        DsmpFreePool(passThrough);
    }

    //
    // Return whether IALUAE is set to 0.
    //
    if (DisableImplicit) {

        *DisableImplicit = implicitDisabled;
    }

    return status;
}


PWSTR
DsmpBuildHardwareId(
    _In_ IN PDSM_DEVICE_INFO DeviceInfo
    )
/*++

Routine Description:

    Construct a string concatinating VendorId with ProductId.

Arguements:

    DeviceInfo   - Device Extension

Return Value :

    NULL terminated hardware id if it was built successfully.
    NULL in case of failure.

--*/
{
    PSTORAGE_DEVICE_DESCRIPTOR deviceDescriptor;
    PWSTR hardwareId = NULL;
    SIZE_T vendorIDLength = 0;
    SIZE_T productIDLength = 0;
    PCSZ vendorIdOffset;
    PCSZ productIdOffset;
    SIZE_T sizeNeeded;
    NTSTATUS status = STATUS_SUCCESS;
    ANSI_STRING ansiString;
    UNICODE_STRING unicodeString;
    ULONG offset;

    deviceDescriptor = &(DeviceInfo->Descriptor);

    //
    // Save the vendorid and productid offset in Device Descriptor
    //
    offset = deviceDescriptor->ProductIdOffset;
    if ((offset != 0) && (offset != MAXULONG)) {

        productIDLength = (strlen(((PCHAR)deviceDescriptor) + offset) * sizeof(WCHAR)) + WNULL_SIZE;
    }

    offset = deviceDescriptor->VendorIdOffset;
    if ((offset != 0) && (offset != MAXULONG)) {

        vendorIDLength = (strlen(((PCHAR)deviceDescriptor) + offset) * sizeof(WCHAR)) + WNULL_SIZE;
    }

    if (!vendorIDLength || !productIDLength) {

        status = STATUS_UNSUCCESSFUL;

        goto __Exit_DsmpBuildHardwareId;
    }

    sizeNeeded = vendorIDLength + productIDLength;
    hardwareId = DsmpAllocatePool(NonPagedPoolNx, sizeNeeded, DSM_TAG_DEV_HARDWARE_ID);
    if (!hardwareId) {


        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpBuildHardwareId;
    }

    //
    // Build the NULL terminated hardwareId whose format is :
    //
    //        VendorIdProductId
    //
    vendorIdOffset = (PCSZ)((PUCHAR)deviceDescriptor + deviceDescriptor->VendorIdOffset);
    RtlInitAnsiString(&ansiString, vendorIdOffset);
    unicodeString.Length = 0;
    unicodeString.MaximumLength = (USHORT)vendorIDLength;
    unicodeString.Buffer = hardwareId;

    status = RtlAnsiStringToUnicodeString(&unicodeString,
                                          &ansiString,
                                          FALSE);
    if (!NT_SUCCESS(status)) {


        goto __Exit_DsmpBuildHardwareId;
    }

    productIdOffset = (PCSZ)((PUCHAR)deviceDescriptor + deviceDescriptor->ProductIdOffset);
    RtlInitAnsiString(&ansiString, productIdOffset);
    unicodeString.Length = 0;
    unicodeString.MaximumLength = (USHORT)productIDLength;
    unicodeString.Buffer = hardwareId + strlen(((PCHAR)deviceDescriptor) + offset);

    status = RtlAnsiStringToUnicodeString(&unicodeString,
                                          &ansiString,
                                          FALSE);
    if (!NT_SUCCESS(status)) {


        goto __Exit_DsmpBuildHardwareId;
    }



__Exit_DsmpBuildHardwareId:

    if (hardwareId && !NT_SUCCESS(status)) {
        DsmpFreePool(hardwareId);
        hardwareId = NULL;
    }


    return hardwareId;
}


PWSTR
DsmpBuildDeviceNameLegacyPage0x80(
    _In_ IN PDSM_DEVICE_INFO DeviceInfo
    )
/*++

Routine Description:

    Construct a string from VendorId, ProductId, and SerialNumber (page 0x80
    info) of the device.

Arguements:

    DeviceInfo - Device Extension

Return Value :

    STATUS_SUCCESS if the device name was built successfully.

    Appropriate NTSTATUS code on failure

--*/
{
    PSTORAGE_DEVICE_DESCRIPTOR deviceDescriptor;
    PWCHAR deviceName = NULL;
    PWCHAR tmpPtr;
    PWCHAR vendorID = NULL;
    PWCHAR productID = NULL;
    PWCHAR serialID = NULL;
    ANSI_STRING ansiString;
    UNICODE_STRING unicodeString;
    UNICODE_STRING unicodeDeviceName;
    SIZE_T vendorIDLength = 0;
    SIZE_T productIDLength = 0;
    SIZE_T serialIDLength = 0;
    ULONG offset;
    SIZE_T sizeNeeded;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    deviceDescriptor = &(DeviceInfo->Descriptor);

    //
    // Save the vendorid, productid, and serialnumber offset
    // in Device Descriptor
    //
    offset = deviceDescriptor->VendorIdOffset;
    if ((offset != 0) && (offset != MAXULONG)) {

        vendorIDLength = (strlen(((PCHAR)deviceDescriptor) + offset) * sizeof(WCHAR)) + WNULL_SIZE;
    }

    offset = deviceDescriptor->ProductIdOffset;
    if ((offset != 0) && (offset != MAXULONG)) {

        productIDLength = (strlen(((PCHAR)deviceDescriptor) + offset) * sizeof(WCHAR)) + WNULL_SIZE;
    }

    offset = deviceDescriptor->SerialNumberOffset;
    if ((offset != 0) && (offset != MAXULONG)) {

        serialIDLength = (strlen(((PCHAR)deviceDescriptor) + offset) * sizeof(WCHAR)) + WNULL_SIZE;
    }

    //
    // Allocate buffers to use to convert the IDs from ANSI to Unicode and
    // eventually build the device name.
    //
    if (vendorIDLength > 0) {
        vendorID = (PWCHAR)DsmpAllocatePool(NonPagedPoolNx, vendorIDLength, DSM_TAG_DEV_NAME);
        if (!vendorID) {



            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (productIDLength > 0) {
        productID = (PWCHAR)DsmpAllocatePool(NonPagedPoolNx, productIDLength, DSM_TAG_DEV_NAME);
        if (!productID) {


            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (serialIDLength > 0) {
        serialID = (PWCHAR)DsmpAllocatePool(NonPagedPoolNx, serialIDLength, DSM_TAG_DEV_NAME);
        if (!serialID) {


            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    sizeNeeded = vendorIDLength + productIDLength + serialIDLength;
    if (sizeNeeded > 0) {

        //
        // Account for the terminating NULL if serial id is empty.
        //

        sizeNeeded += (serialIDLength ? 0 : WNULL_SIZE);

        deviceName = (PWCHAR)DsmpAllocatePool(NonPagedPoolNx, sizeNeeded, DSM_TAG_DEV_NAME);
        if (!deviceName) {

            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {

        status = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status)) {
        goto __Exit_DsmpBuildDeviceNameLegacyPage0x80;
    }

    //
    // Build the NULL terminated device name whose format is :
    //
    //        VendorId_ProductId_SerialNumber
    //

    unicodeDeviceName.Length = 0;
    unicodeDeviceName.MaximumLength = (USHORT)sizeNeeded;
    unicodeDeviceName.Buffer = deviceName;

    if (vendorIDLength) {

        PCSZ vendorIdOffset;

        vendorIdOffset = (PCSZ)((PUCHAR)deviceDescriptor +
                         deviceDescriptor->VendorIdOffset);

        RtlInitAnsiString(&ansiString, vendorIdOffset);

        unicodeString.Length = 0;
        unicodeString.MaximumLength = (USHORT) vendorIDLength;
        unicodeString.Buffer = vendorID;

        status = RtlAnsiStringToUnicodeString(&unicodeString,
                                              &ansiString,
                                              FALSE);
        if (!NT_SUCCESS(status)) {

            goto __Exit_DsmpBuildDeviceNameLegacyPage0x80;
        }

        //
        // If there are spaces in the id, set NULL at the first space.
        //
        tmpPtr = wcschr(vendorID, L' ');
        if (tmpPtr != NULL) {
            *tmpPtr = WNULL;
        }

        status = RtlUnicodeStringCatString(&unicodeDeviceName, vendorID);

        if (!NT_SUCCESS(status)) {

            goto __Exit_DsmpBuildDeviceNameLegacyPage0x80;
        }

        RtlUnicodeStringCatString(&unicodeDeviceName, L"_");
    }

    if (productIDLength) {

        PCSZ productIdOffset;

        productIdOffset = (PCSZ)((PUCHAR)deviceDescriptor +
                          deviceDescriptor->ProductIdOffset);

        RtlInitAnsiString(&ansiString, productIdOffset);

        unicodeString.Length = 0;
        unicodeString.MaximumLength = (USHORT) productIDLength;
        unicodeString.Buffer = productID;

        status = RtlAnsiStringToUnicodeString(&unicodeString,
                                              &ansiString,
                                              FALSE);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpBuildDeviceNameLegacyPage0x80;
        }

        //
        // If there are spaces in the id, set NULL at the first space.
        //
        tmpPtr = wcschr(productID, L' ');
        if (tmpPtr != NULL) {
            *tmpPtr = WNULL;
        }

        status = RtlUnicodeStringCatString(&unicodeDeviceName, productID);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpBuildDeviceNameLegacyPage0x80;
        }

        RtlUnicodeStringCatString(&unicodeDeviceName, L"_");
    }

    //
    // Serial number
    //
    if (serialIDLength) {

        PCSZ serialNumberOffset;

        serialNumberOffset = (PCSZ)((PUCHAR)deviceDescriptor +
                              deviceDescriptor->SerialNumberOffset);

        RtlInitAnsiString(&ansiString, serialNumberOffset);

        unicodeString.Length = 0;
        unicodeString.MaximumLength = (USHORT) serialIDLength;
        unicodeString.Buffer = serialID;

        status = RtlAnsiStringToUnicodeString(&unicodeString,
                                              &ansiString,
                                              FALSE);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpBuildDeviceNameLegacyPage0x80;
        }

        //
        // If there are spaces in the id, set NULL at the first space.
        //
        tmpPtr = wcschr(serialID, L' ');
        if (tmpPtr != NULL) {
            *tmpPtr = WNULL;
        }

        status = RtlUnicodeStringCatString(&unicodeDeviceName, serialID);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpBuildDeviceNameLegacyPage0x80;
        }
    }

__Exit_DsmpBuildDeviceNameLegacyPage0x80:

    if (vendorID) {
        DsmpFreePool(vendorID);
    }

    if (productID) {
        DsmpFreePool(productID);
    }

    if (serialID) {
        DsmpFreePool(serialID);
    }

    if (deviceName && !NT_SUCCESS(status)) {
        DsmpFreePool(deviceName);
        deviceName = NULL;
    }


    return deviceName;
}



PWSTR
DsmpBuildDeviceName(
    _In_ IN PDSM_DEVICE_INFO DeviceInfo,
    _In_reads_(SerialNumberLength) IN PSTR SerialNumber,
    _In_ IN SIZE_T SerialNumberLength
    )
/*++

Routine Description:

    Construct a string from VendorId, ProductId, and SerialNumber (page 0x83
    identifiers) of the device.

Arguements:

    DeviceInfo   - Device Extension
    SerialNumber - Device serial number built from appropriate page 0x83 identifier
    SerialNumberLength - Length (in chars) of the passed in serial number buffer

Return Value :

    Device name if it was built successfully.
    NULL in case of failure.

--*/
{
    PSTORAGE_DEVICE_DESCRIPTOR deviceDescriptor;
    PWCHAR deviceName = NULL;
    PWCHAR tmpPtr;
    PWCHAR vendorID = NULL;
    PWCHAR productID = NULL;
    PWCHAR serialID = NULL;
    ANSI_STRING ansiString;
    UNICODE_STRING unicodeString;
    UNICODE_STRING unicodeDeviceName;
    SIZE_T vendorIDLength = 0;
    SIZE_T productIDLength = 0;
    SIZE_T serialIDLength = 0;
    ULONG offset;
    SIZE_T sizeNeeded;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();


    deviceDescriptor = &(DeviceInfo->Descriptor);

    //
    // Save the vendorid, productid, and serialnumber offset
    // in Device Descriptor
    //
    offset = deviceDescriptor->VendorIdOffset;
    if ((offset != 0) && (offset != MAXULONG)) {

        vendorIDLength = (strlen(((PCHAR)deviceDescriptor) + offset) * sizeof(WCHAR)) + WNULL_SIZE;
    }

    offset = deviceDescriptor->ProductIdOffset;
    if ((offset != 0) && (offset != -1)) {

        productIDLength = (strlen(((PCHAR)deviceDescriptor) + offset) * sizeof(WCHAR)) + WNULL_SIZE;
    }

    if (SerialNumber) {

        serialIDLength = (SerialNumberLength * sizeof(WCHAR)) + WNULL_SIZE;
    }

    //
    // Allocate buffers to use to convert the IDs from ANSI to Unicode and
    // eventually build the device name.
    //
    if (vendorIDLength > 0) {
        vendorID = (PWCHAR)DsmpAllocatePool(NonPagedPoolNx, vendorIDLength, DSM_TAG_DEV_NAME);
        if (!vendorID) {

            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (productIDLength > 0) {
        productID = (PWCHAR)DsmpAllocatePool(NonPagedPoolNx, productIDLength, DSM_TAG_DEV_NAME);
        if (!productID) {

            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (serialIDLength > 0) {
        serialID = (PWCHAR)DsmpAllocatePool(NonPagedPoolNx, serialIDLength, DSM_TAG_DEV_NAME);
        if (!serialID) {


            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    sizeNeeded = vendorIDLength + productIDLength + serialIDLength;
    if (sizeNeeded > 0) {

        //
        // Account for the terminating NULL if serial id is empty.
        //

        sizeNeeded += (serialIDLength ? 0 : WNULL_SIZE);

        deviceName = (PWCHAR)DsmpAllocatePool(NonPagedPoolNx, sizeNeeded, DSM_TAG_DEV_NAME);
        if (!deviceName) {

            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {

        status = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status)) {
        goto __Exit_DsmpBuildDeviceName;
    }

    //
    // Build the NULL terminated device name whose format is :
    //
    //        VendorId_ProductId_SerialNumber
    //

    unicodeDeviceName.Length = 0;
    unicodeDeviceName.MaximumLength = (USHORT)sizeNeeded;
    unicodeDeviceName.Buffer = deviceName;

    if (vendorIDLength) {

        PCSZ vendorIdOffset;

        vendorIdOffset = (PCSZ)((PUCHAR)deviceDescriptor +
                         deviceDescriptor->VendorIdOffset);

        RtlInitAnsiString(&ansiString, vendorIdOffset);

        unicodeString.Length = 0;
        unicodeString.MaximumLength = (USHORT) vendorIDLength;
        unicodeString.Buffer = vendorID;

        status = RtlAnsiStringToUnicodeString(&unicodeString,
                                              &ansiString,
                                              FALSE);
        if (!NT_SUCCESS(status)) {

            goto __Exit_DsmpBuildDeviceName;
        }

        //
        // If there are spaces in the id, set NULL at the first space.
        //
        tmpPtr = wcschr(vendorID, L' ');
        if (tmpPtr != NULL) {
            *tmpPtr = WNULL;
        }

        status = RtlUnicodeStringCatString(&unicodeDeviceName, vendorID);

        if (!NT_SUCCESS(status)) {



            goto __Exit_DsmpBuildDeviceName;
        }

        RtlUnicodeStringCatString(&unicodeDeviceName, L"_");
    }

    if (productIDLength) {

        PCSZ productIdOffset;

        productIdOffset = (PCSZ)((PUCHAR)deviceDescriptor +
                          deviceDescriptor->ProductIdOffset);

        RtlInitAnsiString(&ansiString, productIdOffset);

        unicodeString.Length = 0;
        unicodeString.MaximumLength = (USHORT) productIDLength;
        unicodeString.Buffer = productID;

        status = RtlAnsiStringToUnicodeString(&unicodeString,
                                              &ansiString,
                                              FALSE);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpBuildDeviceName;
        }

        //
        // If there are spaces in the id, set NULL at the first space.
        //
        tmpPtr = wcschr(productID, L' ');
        if (tmpPtr != NULL) {
            *tmpPtr = WNULL;
        }

        status = RtlUnicodeStringCatString(&unicodeDeviceName, productID);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpBuildDeviceName;
        }

        RtlUnicodeStringCatString(&unicodeDeviceName, L"_");
    }

    //
    // Serial number
    //
    if (serialIDLength) {

        PSTR serialNumberOffset;

        serialNumberOffset = SerialNumber;

        RtlInitAnsiString(&ansiString, serialNumberOffset);

        unicodeString.Length = 0;
        unicodeString.MaximumLength = (USHORT) serialIDLength;
        unicodeString.Buffer = serialID;

        status = RtlAnsiStringToUnicodeString(&unicodeString,
                                              &ansiString,
                                              FALSE);

        if (!NT_SUCCESS(status)) {

            goto __Exit_DsmpBuildDeviceName;
        }

        //
        // If there are spaces in the id, set NULL at the first space.
        //
        tmpPtr = wcschr(serialID, L' ');
        if (tmpPtr != NULL) {
            *tmpPtr = WNULL;
        }

        status = RtlUnicodeStringCatString(&unicodeDeviceName, serialID);

        if (!NT_SUCCESS(status)) {

            goto __Exit_DsmpBuildDeviceName;
        }
    }

__Exit_DsmpBuildDeviceName:

    if (vendorID) {
        DsmpFreePool(vendorID);
    }

    if (productID) {
        DsmpFreePool(productID);
    }

    if (serialID) {
        DsmpFreePool(serialID);
    }

    if (deviceName && !NT_SUCCESS(status)) {
        DsmpFreePool(deviceName);
        deviceName = NULL;
    }

    return deviceName;
}


NTSTATUS
DsmpApplyDeviceNameCorrection(
    _In_ IN PDSM_DEVICE_INFO DeviceInfo,
    _In_reads_(DeviceNameLegacyLen) PWSTR DeviceNameLegacy,
    _In_ IN SIZE_T DeviceNameLegacyLen,
    _In_reads_(DeviceNameLen) PWSTR DeviceName,
    _In_ IN SIZE_T DeviceNameLen
    )
/*++

Routine Description:

    If the registry has a key name built with a legacy device name, this
    function updates the key name with the current device name.

Arguements:

    DeviceInfo          - Device instance
    DeviceNameLegacy    - Device name built using legacy methods.
    DeviceNameLegacyLen - Number of chars (including NULL) of the DeviceNameLegacy buffer.
    DeviceName          - Device name built using current methods.
    DeviceNameLen       - Number of chars (including NULL) of the DeviceName buffer.

Return Value :

    STATUS_SUCCESS if the device's key was updated successfully.

    Appropriate NTSTATUS code on failure

--*/
{
    HANDLE lbSettingsKey = NULL;
    HANDLE deviceKeyLegacy = NULL;
    HANDLE deviceKey = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;
    UNICODE_STRING deviceNameLegacy;
    UNICODE_STRING deviceName;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceNameLen);
    UNREFERENCED_PARAMETER(DeviceNameLegacyLen);

    //
    // First open LoadBalanceSettings key under the service key.
    //
    status = DsmpOpenLoadBalanceSettingsKey(KEY_ALL_ACCESS, &lbSettingsKey);

    if (!NT_SUCCESS(status)) {


        goto __Exit_DsmpApplyDeviceNameCorrection;
    }

    RtlInitUnicodeString(&deviceNameLegacy, DeviceNameLegacy);

    InitializeObjectAttributes(&objectAttributes,
                               &deviceNameLegacy,
                               (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                               lbSettingsKey,
                               (PSECURITY_DESCRIPTOR) NULL);

    //
    // Open the old device key under DsmLoadBalanceSettings key.
    // The name of this key is the one built using legacy methods - either a
    // serial number from VPD page 0x80 or an aliased serial number from VPD
    // page 0x83.
    //
    status = ZwOpenKey(&deviceKeyLegacy,
                       KEY_ALL_ACCESS,
                       &objectAttributes);

    if (NT_SUCCESS(status)) {

        ULONG disposition;


        RtlInitUnicodeString(&deviceName, DeviceName);

        InitializeObjectAttributes(&objectAttributes,
                                   &deviceName,
                                   (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                   lbSettingsKey,
                                   (PSECURITY_DESCRIPTOR) NULL);

        //
        // Since the old name key exists, create one with the new name.
        //
        status = ZwCreateKey(&deviceKey,
                             KEY_ALL_ACCESS,
                             &objectAttributes,
                             0,
                             NULL,
                             REG_OPTION_NON_VOLATILE,
                             &disposition);

        if (NT_SUCCESS(status)) {

            //
            // The new key shouldn't exist if the old one does.
            // If it does, it indicates a error occured the previous time
            // this was tried, so just copy over the old subtree anyways now.
            //
            DSM_ASSERT(disposition == REG_CREATED_NEW_KEY);

            //
            // Copy over the entire subtree of the old key over to the new key.
            //
            status = DsmpRegCopyTree(deviceKeyLegacy, deviceKey);

            if (!NT_SUCCESS(status)) {


                goto __Exit_DsmpApplyDeviceNameCorrection;
            }

            //
            // Delete the old key name.
            //
            status = DsmpRegDeleteTree(deviceKeyLegacy);
            if (!NT_SUCCESS(status)) {

                goto __Exit_DsmpApplyDeviceNameCorrection;
            }

        } else {


            goto __Exit_DsmpApplyDeviceNameCorrection;
        }

    } else if (status == STATUS_INVALID_HANDLE ||
               status == STATUS_OBJECT_NAME_NOT_FOUND) {


        status = STATUS_SUCCESS;

    } else {
    }

__Exit_DsmpApplyDeviceNameCorrection:

    if (deviceKey) {
        ZwClose(deviceKey);
    }

    if (deviceKeyLegacy) {
        ZwClose(deviceKeyLegacy);
    }

    if (lbSettingsKey) {
        ZwClose(lbSettingsKey);
    }

    return status;
}


NTSTATUS
DsmpQueryDeviceLBPolicyFromRegistry(
    _In_ PDSM_DEVICE_INFO DeviceInfo,
    _In_ PWSTR RegistryKeyName,
    _Inout_ PDSM_LOAD_BALANCE_TYPE LoadBalanceType,
    _Inout_ PULONGLONG PreferredPath,
    _Inout_ PUCHAR ExplicitlySet
    )
/*++

Routine Description:

    Query the saved load balance policy and preferred path for this device from
    the registry.
    Also returns whether this setting was explicitly set via WMI call to SetLBPolicy,
    (as opposed to the settings being made based on defaults determined through the
    storage's ALUA capabilities).

Arguements:

    DeviceInfo - The instance of the LUN through a paricular path
    RegistryKeyName - DeviceName representing this LUN
    LoadBalanceType - Type of LB policy.
    PreferredPath - The preferred path for the device.
    ExplicitlySet - Flag reflecting if LB policy was explicitly set.

Return Value :

    STATUS_SUCCESS if we were able to successfully query the registry for the info.

    Appropriate NTSTATUS code on failure

--*/
{
    HANDLE lbSettingsKey = NULL;
    HANDLE deviceKey = NULL;
    UNICODE_STRING subKeyName;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;
    UNICODE_STRING keyValueName;
    ULONG length;
    struct _explicitSet {
        KEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
        UCHAR Data;
    } explicitSet;
    struct _preferredPath {
        KEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
        ULONGLONG Data;
    } preferredPath;


    //
    // Query the Load Balance settings for the given device from the registry.
    // First open LoadBalanceSettings key under the service key.
    //
    status = DsmpOpenLoadBalanceSettingsKey(KEY_ALL_ACCESS, &lbSettingsKey);

    if (!NT_SUCCESS(status)) {


        goto __Exit_DsmpQueryDeviceLBPolicyFromRegistry;
    }

    RtlInitUnicodeString(&subKeyName, RegistryKeyName);

    InitializeObjectAttributes(&objectAttributes,
                               &subKeyName,
                               (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                               lbSettingsKey,
                               (PSECURITY_DESCRIPTOR) NULL);

    //
    // Create or Open the device key under DsmLoadBalanceSettings key.
    // The name of this key is the one built in DsmpBuildDeviceName
    //
    status = ZwCreateKey(&deviceKey,
                         KEY_ALL_ACCESS,
                         &objectAttributes,
                         0,
                         NULL,
                         REG_OPTION_NON_VOLATILE,
                         NULL);

    if (NT_SUCCESS(status)) {

        RTL_QUERY_REGISTRY_TABLE queryTable[2];

        RtlZeroMemory(queryTable, sizeof(queryTable));

        queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT |
                              RTL_QUERY_REGISTRY_REQUIRED | 
                              RTL_QUERY_REGISTRY_TYPECHECK;
        queryTable[0].Name = DSM_LOAD_BALANCE_POLICY;
        queryTable[0].EntryContext = LoadBalanceType;
        queryTable[0].DefaultType  = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;

        status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE,
                                        deviceKey,
                                        queryTable,
                                        deviceKey,
                                        NULL);
        if (NT_SUCCESS(status)) {

        } else if (status == STATUS_OBJECT_NAME_NOT_FOUND) {

            //
            // The device key must have been newly created.
            // Set the default load balance policy for this device
            //

            status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE,
                                           deviceKey,
                                           DSM_LOAD_BALANCE_POLICY,
                                           REG_DWORD,
                                           LoadBalanceType,
                                           sizeof(ULONG));
            if (!NT_SUCCESS(status)) {


                goto __Exit_DsmpQueryDeviceLBPolicyFromRegistry;
            }
        }

        if (NT_SUCCESS(status)) {

            RtlInitUnicodeString(&keyValueName, DSM_POLICY_EXPLICITLY_SET);
            status = ZwQueryValueKey(deviceKey,
                                     &keyValueName,
                                     KeyValuePartialInformation,
                                     &explicitSet,
                                     sizeof(explicitSet),
                                     &length);

            if (NT_SUCCESS(status)) {

                NT_ASSERT(explicitSet.KeyValueInfo.DataLength == sizeof(UCHAR));

                *ExplicitlySet = *((UCHAR UNALIGNED *)&(explicitSet.KeyValueInfo.Data));

            } else if (status == STATUS_OBJECT_NAME_NOT_FOUND) {

                *ExplicitlySet = FALSE;

                //
                // The device key must have been newly created.
                // Set ExplicitlySet to 0 to indicate that the default was used.
                //
                status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE,
                                               deviceKey,
                                               DSM_POLICY_EXPLICITLY_SET,
                                               REG_BINARY,
                                               ExplicitlySet,
                                               sizeof(UCHAR));
                if (!NT_SUCCESS(status)) {
                }
            }

            if (NT_SUCCESS(status)) {

                RtlInitUnicodeString(&keyValueName, DSM_PREFERRED_PATH);
                status = ZwQueryValueKey(deviceKey,
                                         &keyValueName,
                                         KeyValuePartialInformation,
                                         &preferredPath,
                                         sizeof(preferredPath),
                                         &length);

                if (NT_SUCCESS(status)) {

                    NT_ASSERT(preferredPath.KeyValueInfo.DataLength == sizeof(ULONGLONG));

                    *PreferredPath = *((ULONGLONG UNALIGNED *)&(preferredPath.KeyValueInfo.Data));


                } else if (status == STATUS_OBJECT_NAME_NOT_FOUND) {

                    *PreferredPath = (ULONGLONG)((ULONG_PTR)MAXULONG);

                    //
                    // The device key must have been newly created.
                    // Set a bogus preferred path as default.
                    //
                    status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE,
                                                   deviceKey,
                                                   DSM_PREFERRED_PATH,
                                                   REG_BINARY,
                                                   PreferredPath,
                                                   sizeof(ULONGLONG));
                    if (!NT_SUCCESS(status)) {

                    }
                }
            }
        }

    } else {


        deviceKey = NULL;
    }

__Exit_DsmpQueryDeviceLBPolicyFromRegistry:

    if (deviceKey) {
        ZwClose(deviceKey);
    }

    if (lbSettingsKey) {
        ZwClose(lbSettingsKey);
    }


    return status;
}


NTSTATUS
DsmpQueryTargetLBPolicyFromRegistry(
    _In_ IN PDSM_DEVICE_INFO DeviceInfo,
    _Out_ OUT PDSM_LOAD_BALANCE_TYPE LoadBalanceType,
    _Out_ OUT PULONGLONG PreferredPath
    )
/*++

Routine Description:

    Query the load balance policy for the VID/PID of the passed in device from
    the registry if it has been set.

Arguements:

    DeviceInfo - Device's whose VID/PID we need to compare against.
    LoadBalanceType - Type of LB policy.
    PreferredPath - The preferred path for the device.

Return Value :

    STATUS_SUCCESS if we were able to successfully query the registry for the info.

    Appropriate NTSTATUS code on failure

--*/
{
    HANDLE targetsLBSettingKey = NULL;
    HANDLE targetKey = NULL;
    UNICODE_STRING subKeyName;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UNICODE_STRING keyValueName;
    ULONG length;
    struct _preferredPath {
        KEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
        ULONGLONG Data;
    } preferredPath;



    if (!LoadBalanceType || !PreferredPath) {

        goto __Exit_DsmpQueryTargetLBPolicyFromRegistry;
    }

    if (!DeviceInfo->Group->HardwareId) {

        status = STATUS_UNSUCCESSFUL;


        goto __Exit_DsmpQueryTargetLBPolicyFromRegistry;
    }

    //
    // Query the Load Balance settings for the given target from the registry.
    // First open TargetsLoadBalanceSetting key under the service key.
    //
    status = DsmpOpenTargetsLoadBalanceSettingKey(KEY_ALL_ACCESS, &targetsLBSettingKey);

    if (!NT_SUCCESS(status)) {


        goto __Exit_DsmpQueryTargetLBPolicyFromRegistry;
    }

    RtlInitUnicodeString(&subKeyName, DeviceInfo->Group->HardwareId);

    InitializeObjectAttributes(&objectAttributes,
                               &subKeyName,
                               (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                               targetsLBSettingKey,
                               (PSECURITY_DESCRIPTOR) NULL);

    //
    // Open the VID/PID key under DsmTargetsLoadBalanceSetting key.
    //
    status = ZwOpenKey(&targetKey, KEY_ALL_ACCESS, &objectAttributes);

    if (NT_SUCCESS(status)) {

        RTL_QUERY_REGISTRY_TABLE queryTable[2];

        RtlZeroMemory(queryTable, sizeof(queryTable));

        queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT |
                              RTL_QUERY_REGISTRY_REQUIRED | 
                              RTL_QUERY_REGISTRY_TYPECHECK;
        queryTable[0].Name = DSM_LOAD_BALANCE_POLICY;
        queryTable[0].EntryContext = LoadBalanceType;
        queryTable[0].DefaultType  = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;

        status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE,
                                        targetKey,
                                        queryTable,
                                        targetKey,
                                        NULL);
        if (NT_SUCCESS(status)) {

        } else {

        }

        if (NT_SUCCESS(status)) {

            RtlInitUnicodeString(&keyValueName, DSM_PREFERRED_PATH);
            status = ZwQueryValueKey(targetKey,
                                     &keyValueName,
                                     KeyValuePartialInformation,
                                     &preferredPath,
                                     sizeof(preferredPath),
                                     &length);

            if (NT_SUCCESS(status)) {

                NT_ASSERT(preferredPath.KeyValueInfo.DataLength == sizeof(ULONGLONG));

                *PreferredPath = *((ULONGLONG UNALIGNED *)&(preferredPath.KeyValueInfo.Data));

            } else {

            }
        }

    } else {


        targetKey = NULL;
    }

__Exit_DsmpQueryTargetLBPolicyFromRegistry:

    if (targetKey) {
        ZwClose(targetKey);
    }

    if (targetsLBSettingKey) {
        ZwClose(targetsLBSettingKey);
    }


    return status;
}


NTSTATUS
DsmpQueryDsmLBPolicyFromRegistry(
    _Out_ OUT PDSM_LOAD_BALANCE_TYPE LoadBalanceType,
    _Out_ OUT PULONGLONG PreferredPath
    )
/*++

Routine Description:

    Query the overall load balance policy for MSDSM controlled devices from
    the registry if it has been set.

Arguements:

    LoadBalanceType - Type of LB policy.
    PreferredPath - The preferred path for the device.

Return Value :

    STATUS_SUCCESS if we were able to successfully query the registry for the info.

    Appropriate NTSTATUS code on failure

--*/
{
    HANDLE parametersKey = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UNICODE_STRING keyValueName;
    RTL_QUERY_REGISTRY_TABLE queryTable[2];
    ULONG length;
    struct _preferredPath {
        KEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
        ULONGLONG Data;
    } preferredPath;


    if (!LoadBalanceType || !PreferredPath) {


        goto __Exit_DsmpQueryDsmLBPolicyFromRegistry;
    }

    //
    // Query the overall default Load Balance settings for MSDSM from the registry.
    // First open the Parameters key under the service key.
    //
    status = DsmpOpenDsmServicesParametersKey(KEY_ALL_ACCESS, &parametersKey);

    if (!NT_SUCCESS(status)) {


        goto __Exit_DsmpQueryDsmLBPolicyFromRegistry;
    }

    RtlZeroMemory(queryTable, sizeof(queryTable));

    queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT |
                          RTL_QUERY_REGISTRY_REQUIRED | 
                          RTL_QUERY_REGISTRY_TYPECHECK;
    queryTable[0].Name = DSM_LOAD_BALANCE_POLICY;
    queryTable[0].EntryContext = LoadBalanceType;
    queryTable[0].DefaultType  = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;

    status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE,
                                    parametersKey,
                                    queryTable,
                                    parametersKey,
                                    NULL);
    if (NT_SUCCESS(status)) {



    } else {


        goto __Exit_DsmpQueryDsmLBPolicyFromRegistry;
    }

    if (NT_SUCCESS(status)) {

        RtlInitUnicodeString(&keyValueName, DSM_PREFERRED_PATH);
        status = ZwQueryValueKey(parametersKey,
                                 &keyValueName,
                                 KeyValuePartialInformation,
                                 &preferredPath,
                                 sizeof(preferredPath),
                                 &length);

        if (NT_SUCCESS(status)) {

            NT_ASSERT(preferredPath.KeyValueInfo.DataLength == sizeof(ULONGLONG));

            *PreferredPath = *((ULONGLONG UNALIGNED *)&(preferredPath.KeyValueInfo.Data));



        } else {


        }
    }

__Exit_DsmpQueryDsmLBPolicyFromRegistry:

    if (parametersKey) {
        ZwClose(parametersKey);
    }


    return status;
}


NTSTATUS
DsmpSetDsmLBPolicyInRegistry(
    _In_ IN DSM_LOAD_BALANCE_TYPE LoadBalanceType,
    _In_ IN ULONGLONG PreferredPath
    )
/*++

Routine Description:

    Set the overall load balance policy for MSDSM controlled devices in
    the registry.
    Note: If the policy specified is 0, remove the currently set values
          for policy and preferred path.

Arguements:

    LoadBalanceType - Type of LB policy.
    PreferredPath - The preferred path for devices controlled by DSM.

Return Value :

    STATUS_SUCCESS if we were able to successfully set the info in the registry.

    Appropriate NTSTATUS code on failure

--*/
{
    HANDLE parametersKey = NULL;
    NTSTATUS status;
    UNICODE_STRING lbPolicyValueName;
    UNICODE_STRING preferredPathValueName;


    //
    // First open the Parameters key under the service key.
    //
    status = DsmpOpenDsmServicesParametersKey(KEY_ALL_ACCESS, &parametersKey);

    if (!NT_SUCCESS(status)) {

        goto __Exit_DsmpSetDsmLBPolicyInRegistry;
    }

    RtlInitUnicodeString(&lbPolicyValueName, DSM_LOAD_BALANCE_POLICY);
    RtlInitUnicodeString(&preferredPathValueName, DSM_PREFERRED_PATH);

    //
    // If the LB policy is specified as 0, we need to delete the values.
    //
    if (LoadBalanceType < DSM_LB_FAILOVER) {

        status = ZwDeleteValueKey(parametersKey, &preferredPathValueName);

        if (NT_SUCCESS(status) || status == STATUS_OBJECT_NAME_NOT_FOUND) {

            status = ZwDeleteValueKey(parametersKey, &lbPolicyValueName);
        }

        if (!NT_SUCCESS(status)) {
        }
    } else {

        status = ZwSetValueKey(parametersKey,
                               &lbPolicyValueName,
                               0,
                               REG_DWORD,
                               &LoadBalanceType,
                               sizeof(ULONG));

        if (!NT_SUCCESS(status)) {

            goto __Exit_DsmpSetDsmLBPolicyInRegistry;
        }

        status = ZwSetValueKey(parametersKey,
                               &preferredPathValueName,
                               0,
                               REG_BINARY,
                               &PreferredPath,
                               sizeof(ULONGLONG));

        if (!NT_SUCCESS(status)) {

        }
    }

__Exit_DsmpSetDsmLBPolicyInRegistry:

    if (parametersKey) {
        ZwClose(parametersKey);
    }


    return status;
}


NTSTATUS
DsmpSetVidPidLBPolicyInRegistry(
    _In_ IN PWSTR TargetHardwareId,
    _In_ IN DSM_LOAD_BALANCE_TYPE LoadBalanceType,
    _In_ IN ULONGLONG PreferredPath
    )
/*++

Routine Description:

    Set the default load balance policy for MSDSM controlled devices for
    a particular target VID/PID in the registry.
    Note: If the policy specified is 0, remove the subkey that matches
          the passed in TargetHardwareId.

Arguements:

    TargetHardwareId - The VID/PID for which a default LB policy is being set.
    LoadBalanceType - Type of LB policy.
    PreferredPath - The preferred path for devices controlled by DSM.

Return Value :

    STATUS_SUCCESS if we were able to successfully set the info in the registry.

    Appropriate NTSTATUS code on failure

--*/
{
    HANDLE targetsLBSettingKey = NULL;
    HANDLE targetSubKey = NULL;
    NTSTATUS status;
    UNICODE_STRING vidPidKeyName;
    UNICODE_STRING lbPolicyValueName;
    UNICODE_STRING preferredPathValueName;
    OBJECT_ATTRIBUTES objectAttributes;


    //
    // First open the DsmTargetsLoadBalanceSetting key under the service's parameters key.
    //
    status = DsmpOpenTargetsLoadBalanceSettingKey(KEY_ALL_ACCESS, &targetsLBSettingKey);

    if (!NT_SUCCESS(status)) {


        goto __Exit_DsmpSetVidPidLBPolicyInRegistry;
    }

    RtlInitUnicodeString(&vidPidKeyName, TargetHardwareId);
    InitializeObjectAttributes(&objectAttributes,
                               &vidPidKeyName,
                               (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                               targetsLBSettingKey,
                               (PSECURITY_DESCRIPTOR) NULL);

    //
    // If the LB policy is specified as 0, we need to delete the values.
    //
    if (LoadBalanceType < DSM_LB_FAILOVER) {

        //
        // Open the VID/PID key under DsmTargetsLoadBalanceSetting key.
        //
        status = ZwOpenKey(&targetSubKey, KEY_ALL_ACCESS, &objectAttributes);

        if (NT_SUCCESS(status)) {

            status = ZwDeleteKey(targetSubKey);
        }

        if (!NT_SUCCESS(status)) {

        }
    } else {

        RtlInitUnicodeString(&lbPolicyValueName, DSM_LOAD_BALANCE_POLICY);
        RtlInitUnicodeString(&preferredPathValueName, DSM_PREFERRED_PATH);

        status = ZwCreateKey(&targetSubKey,
                             KEY_ALL_ACCESS,
                             &objectAttributes,
                             0,
                             NULL,
                             REG_OPTION_NON_VOLATILE,
                             NULL);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpSetVidPidLBPolicyInRegistry;
        }

        status = ZwSetValueKey(targetSubKey,
                               &lbPolicyValueName,
                               0,
                               REG_DWORD,
                               &LoadBalanceType,
                               sizeof(ULONG));

        if (!NT_SUCCESS(status)) {

            goto __Exit_DsmpSetVidPidLBPolicyInRegistry;
        }

        status = ZwSetValueKey(targetSubKey,
                               &preferredPathValueName,
                               0,
                               REG_BINARY,
                               &PreferredPath,
                               sizeof(ULONGLONG));

        if (!NT_SUCCESS(status)) {

        }
    }

__Exit_DsmpSetVidPidLBPolicyInRegistry:

    if (targetSubKey) {
        ZwClose(targetSubKey);
    }

    if (targetsLBSettingKey) {
        ZwClose(targetsLBSettingKey);
    }


    return status;
}


NTSTATUS
DsmpOpenLoadBalanceSettingsKey(
    _In_ IN  ACCESS_MASK    AccessMask,
    _Out_ OUT PHANDLE LoadBalanceSettingsKey
    )
/*++

Routine Description:

    Open the device key in the registry.

    NOTE: It is the responsibility of the caller to close the returned handle.

Arguements:

    AccessMask - Requested access with which to open key
    LoadBalanceSettingsKey - handle of the key that is returned to the caller

Return Value :

    STATUS_SUCCESS if we were able to successfully open the registry key.

    Appropriate NTSTATUS code on failure

--*/
{
    HANDLE serviceKey = NULL;
    HANDLE parametersKey = NULL;
    PUNICODE_STRING registryPath = &(gDsmInitData.DsmWmiInfo.RegistryPath);
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING parametersKeyName;
    UNICODE_STRING subKeyName;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();


    *LoadBalanceSettingsKey = NULL;

    //
    // First check if registry path is available for msdsm.
    //
    if (!registryPath->Buffer) {


        goto __Exit_DsmpOpenLoadBalanceSettingsKey;
    }

    //
    // Open the service key first
    //
    InitializeObjectAttributes(&objectAttributes,
                               registryPath,
                               (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                               NULL,
                               NULL);

    status = ZwOpenKey(&serviceKey,
                       AccessMask,
                       &objectAttributes);
    if (NT_SUCCESS(status)) {

        //
        // Open Parameters key under the Service key
        //
        RtlInitUnicodeString(&parametersKeyName, DSM_SERVICE_PARAMETERS);

        RtlZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));

        InitializeObjectAttributes(&objectAttributes,
                                   &parametersKeyName,
                                   (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                   serviceKey,
                                   (PSECURITY_DESCRIPTOR) NULL);

        status = ZwOpenKey(&parametersKey,
                           AccessMask,
                           &objectAttributes);

        if (NT_SUCCESS(status)) {

            //
            // Open LoadBalanceSettings key under the Parameters key
            //
            RtlInitUnicodeString(&subKeyName, DSM_LOAD_BALANCE_SETTINGS);

            RtlZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));

            InitializeObjectAttributes(&objectAttributes,
                                       &subKeyName,
                                       (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                       parametersKey,
                                       (PSECURITY_DESCRIPTOR) NULL);

            status = ZwCreateKey(LoadBalanceSettingsKey,
                                 AccessMask,
                                 &objectAttributes,
                                 0,
                                 NULL,
                                 REG_OPTION_NON_VOLATILE,
                                 NULL);

            if (!NT_SUCCESS(status)) {

                *LoadBalanceSettingsKey = NULL;
            }

        } else {

        }

    } else {

    }

__Exit_DsmpOpenLoadBalanceSettingsKey:

    if (parametersKey) {
        ZwClose(parametersKey);
    }

    if (serviceKey) {
        ZwClose(serviceKey);
    }


    return status;
}


NTSTATUS
DsmpOpenTargetsLoadBalanceSettingKey(
    _In_ IN  ACCESS_MASK    AccessMask,
    _Out_ OUT PHANDLE TargetsLoadBalanceSettingKey
    )
/*++

Routine Description:

    Open the target key in the registry.

    NOTE: It is the responsibility of the caller to close the returned handle.

Arguements:

    AccessMask - Requested access with which to open key
    LoadBalanceSettingsKey - handle of the key that is returned to the caller

Return Value :

    STATUS_SUCCESS if we were able to successfully open the registry key.

    Appropriate NTSTATUS code on failure

--*/
{
    HANDLE serviceKey = NULL;
    HANDLE parametersKey = NULL;
    PUNICODE_STRING registryPath = &(gDsmInitData.DsmWmiInfo.RegistryPath);
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING parametersKeyName;
    UNICODE_STRING subKeyName;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();


    if (!TargetsLoadBalanceSettingKey) {


        status = STATUS_INVALID_PARAMETER;
        goto __Exit_DsmpOpenTargetsLoadBalanceSettingKey;
    }

    *TargetsLoadBalanceSettingKey = NULL;

    //
    // First check if registry path is available for msdsm.
    //
    if (!registryPath->Buffer) {


        goto __Exit_DsmpOpenTargetsLoadBalanceSettingKey;
    }

    //
    // Open the service key first
    //
    InitializeObjectAttributes(&objectAttributes,
                               registryPath,
                               (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                               NULL,
                               NULL);

    status = ZwOpenKey(&serviceKey,
                       AccessMask,
                       &objectAttributes);
    if (NT_SUCCESS(status)) {

        //
        // Open Parameters key under the Service key
        //
        RtlInitUnicodeString(&parametersKeyName, DSM_SERVICE_PARAMETERS);

        RtlZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));

        InitializeObjectAttributes(&objectAttributes,
                                   &parametersKeyName,
                                   (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                   serviceKey,
                                   (PSECURITY_DESCRIPTOR) NULL);

        status = ZwOpenKey(&parametersKey,
                           AccessMask,
                           &objectAttributes);

        if (NT_SUCCESS(status)) {

            //
            // Open LoadBalanceSettings key under the Parameters key
            //
            RtlInitUnicodeString(&subKeyName, DSM_TARGETS_LOAD_BALANCE_SETTING);

            RtlZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));

            InitializeObjectAttributes(&objectAttributes,
                                       &subKeyName,
                                       (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                       parametersKey,
                                       (PSECURITY_DESCRIPTOR) NULL);

            status = ZwCreateKey(TargetsLoadBalanceSettingKey,
                                 AccessMask,
                                 &objectAttributes,
                                 0,
                                 NULL,
                                 REG_OPTION_NON_VOLATILE,
                                 NULL);

            if (!NT_SUCCESS(status)) {


                *TargetsLoadBalanceSettingKey = NULL;
            }

        } else {

        }

    } else {

    }

__Exit_DsmpOpenTargetsLoadBalanceSettingKey:

    if (parametersKey) {
        ZwClose(parametersKey);
    }

    if (serviceKey) {
        ZwClose(serviceKey);
    }


    return status;
}


NTSTATUS
DsmpOpenDsmServicesParametersKey(
    _In_ IN  ACCESS_MASK AccessMask,
    _Out_ OUT PHANDLE ParametersKey
    )
/*++

Routine Description:

    Open the DSM's Parameters key in the registry.

    NOTE: It is the responsibility of the caller to close the returned handle.

Arguements:

    AccessMask - Requested access with which to open key
    ParametersKey - handle of the key that is returned to the caller

Return Value :

    STATUS_SUCCESS if we were able to successfully open the registry key.

    Appropriate NTSTATUS code on failure

--*/
{
    HANDLE serviceKey = NULL;
    PUNICODE_STRING registryPath = &(gDsmInitData.DsmWmiInfo.RegistryPath);
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING parametersKeyName;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();

    if (!ParametersKey) {


        status = STATUS_INVALID_PARAMETER;
        goto __Exit_DsmpOpenDsmServicesParametersKey;
    }

    *ParametersKey = NULL;

    //
    // First check if registry path is available for msdsm.
    //
    if (!registryPath->Buffer) {


        goto __Exit_DsmpOpenDsmServicesParametersKey;
    }

    //
    // Open the service key first
    //
    InitializeObjectAttributes(&objectAttributes,
                               registryPath,
                               (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                               NULL,
                               NULL);

    status = ZwOpenKey(&serviceKey,
                       AccessMask,
                       &objectAttributes);
    if (NT_SUCCESS(status)) {

        //
        // Open Parameters key under the Service key
        //
        RtlInitUnicodeString(&parametersKeyName, DSM_SERVICE_PARAMETERS);

        RtlZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));

        InitializeObjectAttributes(&objectAttributes,
                                   &parametersKeyName,
                                   (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                   serviceKey,
                                   (PSECURITY_DESCRIPTOR) NULL);

        status = ZwOpenKey(ParametersKey,
                           AccessMask,
                           &objectAttributes);

        if (!NT_SUCCESS(status)) {

            *ParametersKey = NULL;
        }

    } else {
    }

__Exit_DsmpOpenDsmServicesParametersKey:

    if (serviceKey) {
        ZwClose(serviceKey);
    }

    return status;
}

NTSTATUS
DsmpReportTargetPortGroupsSyncCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);


    KeSetEvent(Irp->UserEvent, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

_Success_(return==0)
NTSTATUS
DsmpReportTargetPortGroups(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Outptr_result_buffer_maybenull_(*TargetPortGroupsInfoLength) PUCHAR *TargetPortGroupsInfo,
    _Out_ PULONG TargetPortGroupsInfoLength
    )
/*++

Routine Description:

    Helper routine to send down ReportTargetPortGroups request synchronously.
    Used if device supports ALUA.

    Note: This routine will allocate memory for the TPG info. It is the
    responsibility of the caller to free this buffer, but only if the function
    returns STATUS_SUCCESS.

Arguments:

    DeviceObject - The port PDO to which the command should be sent.
    TargetPortGroupsInfo - buffer containing the returned data.
    TargetPortGroupsInfoLength - size of the returned buffer.

Return Value:

    STATUS_SUCCESS or appropriate failure code.

--*/
{
    PSPC3_CDB_REPORT_TARGET_PORT_GROUPS cdb;
    NTSTATUS status = STATUS_SUCCESS;
    PIRP irp = NULL;
    PMDL mdl = NULL;
    PSCSI_REQUEST_BLOCK srb = NULL;
    PSENSE_DATA_EX senseInfoBuffer = NULL;
    UCHAR senseInfoBufferLength = 0;
    KEVENT completionEvent;
    ULONG targetPortGroupsInfoLength = 0;
    PUCHAR targetPortGroupsInfo = NULL;
    PIO_STACK_LOCATION irpStack = NULL;

    if (TargetPortGroupsInfoLength == NULL ||
        TargetPortGroupsInfo == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto __Exit_DsmpReportTargetPortGroups;
    }

    *TargetPortGroupsInfoLength = 0;
    *TargetPortGroupsInfo = NULL;

    senseInfoBuffer = (PSENSE_DATA_EX)DsmpAllocatePool(NonPagedPoolNx,
                                                       SENSE_BUFFER_SIZE_EX,
                                                       DSM_TAG_SCSI_SENSE_INFO);
    if (senseInfoBuffer != NULL) {

        senseInfoBufferLength = SENSE_BUFFER_SIZE_EX;

        srb = (PSCSI_REQUEST_BLOCK)DsmpAllocatePool(NonPagedPoolNx,
                                                    sizeof(SCSI_REQUEST_BLOCK),
                                                    DSM_TAG_SCSI_REQUEST_BLOCK);
        if (srb != NULL) {

            SrbSetSenseInfoBufferLength(srb, senseInfoBufferLength);
            SrbSetSenseInfoBuffer(srb, senseInfoBuffer);

            //
            // Take care of worst case scenario, which is:
            // 1. 4-byte header (for allocation length)
            // 2. 32 8-byte descriptors (for TPGs)
            // 3. Each descriptor containing 32 4-byte identifiers (for TPs in each TPG)
            //
            targetPortGroupsInfoLength = SPC3_TARGET_PORT_GROUPS_HEADER_SIZE +
                                         (DSM_MAX_PATHS * (sizeof(SPC3_REPORT_TARGET_PORT_GROUP_DESCRIPTOR) +
                                                           DSM_MAX_PATHS * sizeof(ULONG)));

            targetPortGroupsInfo = (PUCHAR)DsmpAllocatePool(NonPagedPoolNx,
                                                            targetPortGroupsInfoLength,
                                                            DSM_TAG_TARGET_PORT_GROUPS);

            if (targetPortGroupsInfo == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto __Exit_DsmpReportTargetPortGroups;
            }

        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto __Exit_DsmpReportTargetPortGroups;
        }

    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpReportTargetPortGroups;
    }

    irp = IoAllocateIrp(DeviceObject->StackSize + 1, FALSE);
    if (irp == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpReportTargetPortGroups;
    }

    mdl = IoAllocateMdl(targetPortGroupsInfo,
                        targetPortGroupsInfoLength,
                        FALSE,
                        FALSE,
                        irp);

    if (mdl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpReportTargetPortGroups;
    }

    MmBuildMdlForNonPagedPool(mdl);

__Retry_DsmpReportTargetPortGroups:

    irp->MdlAddress = mdl;

    //
    // Set up SRB for execute scsi request. Save SRB address in next stack
    // for the port driver.
    //
    irpStack = IoGetNextIrpStackLocation(irp);
    irpStack->MajorFunction = IRP_MJ_SCSI;
    irpStack->MinorFunction = IRP_MN_SCSI_CLASS;
    irpStack->Parameters.Scsi.Srb = (PSCSI_REQUEST_BLOCK)srb;
    irpStack->DeviceObject = DeviceObject;

    //
    // Set the completion event and the completion routine.
    //
    KeInitializeEvent(&completionEvent, NotificationEvent, FALSE);
    irp->UserEvent = &completionEvent;
    IoSetCompletionRoutine(irp,
                           DsmpReportTargetPortGroupsSyncCompletion,
                           srb,
                           TRUE,
                           TRUE,
                           TRUE);

    srb->Function = SRB_FUNCTION_EXECUTE_SCSI;
    srb->Length = sizeof(SCSI_REQUEST_BLOCK);

    SrbSetCdbLength(srb, sizeof(SPC3_CDB_REPORT_TARGET_PORT_GROUPS));
    cdb = (PSPC3_CDB_REPORT_TARGET_PORT_GROUPS)SrbGetCdb(srb);
    cdb->OperationCode = SPC3_SCSIOP_REPORT_TARGET_PORT_GROUPS;
    cdb->ServiceAction = SPC3_SERVICE_ACTION_TARGET_PORT_GROUPS;
    REVERSE_BYTES(&(cdb->AllocationLength), &targetPortGroupsInfoLength);

    SrbSetTimeOutValue(srb, SPC3_REPORT_TARGET_PORT_GROUPS_TIMEOUT);
    SrbSetDataTransferLength(srb, targetPortGroupsInfoLength);
    SrbSetDataBuffer(srb, targetPortGroupsInfo);
    srb->SrbStatus = 0;
    SrbSetScsiStatus(srb, 0);
    SrbSetNextSrb(srb, NULL);
    SrbSetSrbFlags(srb, SRB_FLAGS_DONT_START_NEXT_PACKET | SRB_FLAGS_QUEUE_ACTION_ENABLE |
                        SRB_FLAGS_DATA_IN | SRB_FLAGS_DISABLE_SYNCH_TRANSFER |
                        SRB_FLAGS_BYPASS_FROZEN_QUEUE | SRB_FLAGS_NO_QUEUE_FREEZE);
    SrbSetQueueAction(srb, SRB_HEAD_OF_QUEUE_TAG_REQUEST);
    SrbSetOriginalRequest(srb, irp);

    ObReferenceObject(DeviceObject);

    //
    // Finally, send the IRP down and wait for its completion.
    //
    status = IoCallDriver(DeviceObject, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&completionEvent,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        status = irp->IoStatus.Status;
    }

    ObDereferenceObject(DeviceObject);

    if ((status == STATUS_BUFFER_OVERFLOW) ||
        (NT_SUCCESS(status) && (SrbGetScsiStatus(srb) == SCSISTAT_GOOD))) {

        //
        // The first 4 bytes of the returned data are the Returned Data Length
        // field of the RTPG header.
        //
        ULONG returnedDataLength = 0;
        REVERSE_BYTES(&returnedDataLength, targetPortGroupsInfo);

        status = STATUS_SUCCESS;
        if (returnedDataLength > SrbGetDataTransferLength(srb)) {

            status = STATUS_BUFFER_OVERFLOW;
        }
    }

    if (NT_SUCCESS(status) && SrbGetScsiStatus(srb) == SCSISTAT_GOOD) {

        //
        // RTPG was successful so return the TPG info to the caller.
        //

        //
        // The first 4 bytes of the returned data are the Returned Data Length
        // field of the RTPG header.  We need to return this value plus the header size.
        //
        ULONG returnedDataLength = 0;
        REVERSE_BYTES(&returnedDataLength, targetPortGroupsInfo);
        *TargetPortGroupsInfoLength = SPC3_TARGET_PORT_GROUPS_HEADER_SIZE + returnedDataLength;

        *TargetPortGroupsInfo = targetPortGroupsInfo;

    } else if (SrbGetScsiStatus(srb) == SCSISTAT_CHECK_CONDITION) {

        if (DsmpShouldRetryTPGRequest(senseInfoBuffer, senseInfoBufferLength)) {


            IoReuseIrp(irp, STATUS_SUCCESS);

            RtlZeroMemory(senseInfoBuffer, senseInfoBufferLength);

            goto __Retry_DsmpReportTargetPortGroups;
        }

        if (DsmpIsDeviceRemoved(senseInfoBuffer, senseInfoBufferLength)) {


            //
            // Sense key was illegal request. SPC 6.25 says response to TPG should follow Test Unit Ready responses
            //
            status = STATUS_NO_SUCH_DEVICE;

        }

        // RTPG was unsuccessful
        // Here it is possible that status is success, but scsi status is not.
        // and there was no RTPG retry. If so, set status to unsuccessful.
        if (NT_SUCCESS(status)) {
            status = STATUS_UNSUCCESSFUL;
        }

        //
        // TPG resulted HW to respond with Check Condition but Sense Key indicates it is not for retry or illegal request
        //
    } else {

        // RTPG was unsuccessful
        // Here it is possible that status is success, but scsi status is not.
        // If so, set status to unsuccessful.
        if (NT_SUCCESS(status)) {
            status = STATUS_UNSUCCESSFUL;
        }

    }

__Exit_DsmpReportTargetPortGroups:

    //
    // The port driver may have allocated its own sense buffer so we need to
    // make sure we free that here.
    //
    if (srb != NULL &&
        SrbGetSrbFlags(srb) & SRB_FLAGS_PORT_DRIVER_ALLOCSENSE &&
        SrbGetSrbFlags(srb) & SRB_FLAGS_FREE_SENSE_BUFFER &&
        SrbGetSenseInfoBuffer(srb) != NULL) {
        DsmpFreePool(SrbGetSenseInfoBuffer(srb));
    }

    if (senseInfoBuffer) {
        DsmpFreePool(senseInfoBuffer);
    }

    if (srb) {
        DsmpFreePool(srb);
    }

    if (irp) {
        if (irp->MdlAddress) {
            IoFreeMdl(irp->MdlAddress);
        }
        IoFreeIrp(irp);
    }

    if (!NT_SUCCESS(status) && targetPortGroupsInfo) {
        DsmpFreePool(targetPortGroupsInfo);
        *TargetPortGroupsInfoLength = 0;
        *TargetPortGroupsInfo = NULL;
    }


    return status;
}

NTSTATUS
DsmpReportTargetPortGroupsAsync(
    _In_ IN PDSM_DEVICE_INFO DeviceInfo,
    _In_ IN PIO_COMPLETION_ROUTINE CompletionRoutine,
    _Inout_ __drv_aliasesMem IN PDSM_TPG_COMPLETION_CONTEXT CompletionContext,
    _In_ IN ULONG TargetPortGroupsInfoLength,
    _Inout_ __drv_aliasesMem IN OUT PUCHAR TargetPortGroupsInfo
    )
/*++

Routine Description:

    Helper routine to send down ReportTargetPortGroups request asynchronously.
    Used if device supports ALUA.

    NOTE: Caller needs to free Irp, system buffer, and passThrough buffer.

Arguments:

    DeviceInfo - The deviceInfo whose corresponding port PDO the command should be sent to.
    CompletionRoutine - completion routine passed in by the caller.
    CompletionContext - context to be passed to be completion routine.
    TargetPortGroupsInfoLength - size of the returned buffer.
    TargetPortGroupsInfo - preallocated (by caller) buffer that'll contain the returned data.

Return Value:

    STATUS_SUCCESS or appropriate failure code.

--*/
{
    PDSM_TPG_COMPLETION_CONTEXT tpgCompletionContext = CompletionContext;
    PSCSI_REQUEST_BLOCK srb = NULL;
    PSPC3_CDB_REPORT_TARGET_PORT_GROUPS cdb;
    NTSTATUS status;
    PIRP irp = NULL;
    PIO_STACK_LOCATION irpStack;
    PMDL mdl = NULL;

    srb = tpgCompletionContext->Srb;

    SrbZeroSrb(srb);

    //
    // Allocate an irp.
    //
    irp = IoAllocateIrp(DeviceInfo->TargetObject->StackSize + 1, FALSE);
    if (!irp) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpReportTargetPortGroupsAsync;
    }

    mdl = IoAllocateMdl(TargetPortGroupsInfo,
                        TargetPortGroupsInfoLength,
                        FALSE,
                        FALSE,
                        irp);
    if (!mdl) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpReportTargetPortGroupsAsync;
    }

    MmBuildMdlForNonPagedPool(irp->MdlAddress);

    //
    // It is possible that if an implicit access state transition took place,
    // each I_T nexus will return UA for asymmetric access state changed. So
    // set the number of retries to be one more than the total number of paths.
    // Worst case scenario is the it is sent down each path once (assuming every
    // is a different I_T nexus) and then one more for a retry one one of the
    // paths.
    //
    tpgCompletionContext->NumberRetries = DeviceInfo->Group->NumberDevices + 1;

    //
    // Set-up the completion routine.
    //
    IoSetCompletionRoutine(irp,
                           CompletionRoutine,
                           (PVOID)CompletionContext,
                           TRUE,
                           TRUE,
                           TRUE);

    //
    // Get the recipient's irpstack location.
    //
    irpStack = IoGetNextIrpStackLocation(irp);

    irpStack->Parameters.Scsi.Srb = srb;
    irpStack->DeviceObject = DeviceInfo->TargetObject;

    //
    // Set the major function code to IRP_MJ_SCSI.
    //
    irpStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;

    //
    // Set the minor function, or many requests will get kicked by by port.
    //
    irpStack->MinorFunction = IRP_MN_SCSI_CLASS;

    srb->Function = SRB_FUNCTION_EXECUTE_SCSI;
    srb->Length = sizeof(SCSI_REQUEST_BLOCK);

    SrbSetCdbLength(srb, sizeof(SPC3_CDB_REPORT_TARGET_PORT_GROUPS));
    cdb = (PSPC3_CDB_REPORT_TARGET_PORT_GROUPS)SrbGetCdb(srb);
    cdb->OperationCode = SPC3_SCSIOP_REPORT_TARGET_PORT_GROUPS;
    cdb->ServiceAction = SPC3_SERVICE_ACTION_TARGET_PORT_GROUPS;
    Get4ByteArrayFromUlong(TargetPortGroupsInfoLength, cdb->AllocationLength);

    SrbSetTimeOutValue(srb, SPC3_REPORT_TARGET_PORT_GROUPS_TIMEOUT);
    SrbSetSenseInfoBuffer(srb, tpgCompletionContext->SenseInfoBuffer);
    SrbSetSenseInfoBufferLength(srb, tpgCompletionContext->SenseInfoBufferLength);
    SrbSetDataTransferLength(srb, TargetPortGroupsInfoLength);
    SrbSetDataBuffer(srb, TargetPortGroupsInfo);
    srb->SrbStatus = 0;
    SrbSetScsiStatus(srb, 0);
    SrbSetNextSrb(srb, NULL);
    SrbSetSrbFlags(srb, SRB_FLAGS_DONT_START_NEXT_PACKET | SRB_FLAGS_QUEUE_ACTION_ENABLE |
                        SRB_FLAGS_DATA_IN | SRB_FLAGS_DISABLE_SYNCH_TRANSFER |
                        SRB_FLAGS_BYPASS_FROZEN_QUEUE | SRB_FLAGS_NO_QUEUE_FREEZE);
    SrbSetQueueAction(srb, SRB_HEAD_OF_QUEUE_TAG_REQUEST);
    SrbSetOriginalRequest(srb, irp);

    irp->UserBuffer = TargetPortGroupsInfo;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();

    //
    // Send the IRP asynchronously
    //
    DsmSendRequestEx(((PDSM_CONTEXT)(DeviceInfo->DsmContext))->MPIOContext,
                     DeviceInfo->TargetObject,
                     irp,
                     (PVOID)DeviceInfo,
                     DSM_CALL_COMPLETION_ON_MPIO_ERROR);

    //
    // We know that the completion routine will always be called.
    //
    status = STATUS_PENDING;

__Exit_DsmpReportTargetPortGroupsAsync:

    if (status != STATUS_PENDING) {

        //
        // This indicates Irp was never sent down to stack (completion routine was never called).
        // We need to clean up.
        //
        if (irp) {

            if (irp->MdlAddress) {
                IoFreeMdl(irp->MdlAddress);
            }

            IoFreeIrp(irp);
        }
    }

    return status;
}


NTSTATUS
DsmpQueryLBPolicyForDevice(
    _In_ IN PWSTR RegistryKeyName,
    _In_ IN  ULONGLONG PathId,
    _In_ IN DSM_LOAD_BALANCE_TYPE LoadBalanceType,
    _Out_ OUT PULONG PrimaryPath,
    _Out_ OUT PULONG OptimizedPath,
    _Out_ OUT PULONG PathWeight
    )
/*++

Routine Description:

    This routine opens the device's registry subkey, builds the path subkey from
    the passed in PathId, then queries that subkey for the value of PrimaryPath,
    OptimizedPath and PathWeight.

Arguments:

    RegistryKeyName - The device's registry subkey name.
    PathId - The pathId for this instance of the device.
    LoadBalanceType - The current load balance policy.
    PrimaryPath - Output of the queried PrimaryPath value.
    OptimizedPath - Output of the queried OptimizedPath value.
    PathWeight - Output of the queried PathWeight value.

Return Value:

    STATUS_SUCCESS or appropriate failure code.

--*/
{
    HANDLE lbSettingsKey = NULL;
    HANDLE deviceKey = NULL;
    HANDLE dsmPathKey = NULL;
    UNICODE_STRING subKeyName;
    WCHAR dsmPathName[128] = {0};
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;
    NTSTATUS pathWeightQueryStatus = STATUS_SUCCESS;

    PAGED_CODE();

    //
    // Query PrimaryPath and PathWeight for the given path.
    // These values are stored under DsmPath#Suffix key for
    // this path. If this key doesn't exist create it and
    // create PrimaryPath and PathWeight values - use the
    // values passed in PrimaryPath and PathWeight in this case.
    //
    status = DsmpOpenLoadBalanceSettingsKey(KEY_ALL_ACCESS, &lbSettingsKey);
    if (!NT_SUCCESS(status)) {

        goto __Exit_DsmpQueryLBPolicyForDevice;
    }

    RtlInitUnicodeString(&subKeyName, RegistryKeyName);

    InitializeObjectAttributes(&objectAttributes,
                               &subKeyName,
                               (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                               lbSettingsKey,
                               (PSECURITY_DESCRIPTOR) NULL);

    status = ZwOpenKey(&deviceKey, KEY_ALL_ACCESS, &objectAttributes);
    if (NT_SUCCESS(status)) {

        //
        // Create or open DsmPath#Suffix key for this path
        //
        DsmpGetDSMPathKeyName(PathId, dsmPathName, 128);


        RtlInitUnicodeString(&subKeyName, dsmPathName);

        RtlZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));

        InitializeObjectAttributes(&objectAttributes,
                                   &subKeyName,
                                   (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                   deviceKey,
                                   (PSECURITY_DESCRIPTOR) NULL);

        status = ZwCreateKey(&dsmPathKey,
                             KEY_ALL_ACCESS,
                             &objectAttributes,
                             0,
                             NULL,
                             REG_OPTION_NON_VOLATILE,
                             NULL);

        if (NT_SUCCESS(status)) {

            RTL_QUERY_REGISTRY_TABLE queryTable[2];

            //
            // Query the Path Weight value.
            //

            RtlZeroMemory(queryTable, sizeof(queryTable));

            queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT |
                                  RTL_QUERY_REGISTRY_REQUIRED | 
                                  RTL_QUERY_REGISTRY_TYPECHECK;
            queryTable[0].Name = DSM_PATH_WEIGHT;
            queryTable[0].EntryContext = PathWeight;
            queryTable[0].DefaultType  = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;

            pathWeightQueryStatus = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE,
                                                           dsmPathKey,
                                                           queryTable,
                                                           dsmPathKey,
                                                           NULL);

            if (!NT_SUCCESS(pathWeightQueryStatus)) {
            }

            //
            // Query the Primary Path value.
            //

            RtlZeroMemory(queryTable, sizeof(queryTable));

            queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT |
                                    RTL_QUERY_REGISTRY_REQUIRED | 
                                    RTL_QUERY_REGISTRY_TYPECHECK;
            queryTable[0].Name = DSM_PRIMARY_PATH;
            queryTable[0].EntryContext = PrimaryPath;
            queryTable[0].DefaultType  = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;

            status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE,
                                            dsmPathKey,
                                            queryTable,
                                            dsmPathKey,
                                            NULL);
            if (NT_SUCCESS(status)) {

                //
                // Query the Optimized Path value.
                //

                RtlZeroMemory(queryTable, sizeof(queryTable));

                queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT |
                                        RTL_QUERY_REGISTRY_REQUIRED | 
                                        RTL_QUERY_REGISTRY_TYPECHECK;
                queryTable[0].Name = DSM_OPTIMIZED_PATH;
                queryTable[0].EntryContext = OptimizedPath;
                queryTable[0].DefaultType  = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;

                status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE,
                                                dsmPathKey,
                                                queryTable,
                                                dsmPathKey,
                                                NULL);
                if (!NT_SUCCESS(status)) {
                }
            } else {

            }

        } else {

        }

    } else {

    }

    if (NT_SUCCESS(status)) {

    }

__Exit_DsmpQueryLBPolicyForDevice:

    if (dsmPathKey) {
        ZwClose(dsmPathKey);
    }

    if (deviceKey) {
        ZwClose(deviceKey);
    }

    if (lbSettingsKey) {
        ZwClose(lbSettingsKey);
    }

    //
    // If the load balance policy is Weighted Paths and we failed to read in
    // the path weight value, we need to return the failure status from the
    // path weight value query.
    //
    if (LoadBalanceType == DSM_LB_WEIGHTED_PATHS && !NT_SUCCESS(pathWeightQueryStatus)) {
        status = pathWeightQueryStatus;
    }


    return status;
}


VOID
DsmpGetDSMPathKeyName(
    _In_ ULONGLONG DSMPathId,
    _Out_writes_(DsmPathKeyNameSize) PWCHAR DsmPathKeyName,
    _In_ ULONG  DsmPathKeyNameSize
    )
/*++

Routine Description:

    This routine builds the string that corresponds to the device's Path subkey
    name in the registry.

Arguments:

    DSMPathId - The pathId of this instance of the device.
    DsmPathKeyName - Output buffer in which the subkey name for path is returned.
    DsmPathKeyNameSize - size  of the output buffer in WCHARs.

Return Value:

    STATUS_SUCCESS or appropriate failure code.

--*/
{
    PWCHAR pathPtr;
    SIZE_T wcharsLeft;
    SIZE_T size;


    //
    // This routine will build a name for a given DSM Path.
    // The name is of the format DsmPath#Suffix, where Suffix
    // is derived from the PathId
    //
    pathPtr = DsmPathKeyName;

    wcharsLeft = DsmPathKeyNameSize;

    size = wcslen(DSM_PATH);

    if (size < wcharsLeft) {

        //
        // First copy the string DsmPath#
        //
        if (NT_SUCCESS(RtlStringCchCopyNW(pathPtr, wcharsLeft, DSM_PATH, wcslen(DSM_PATH)))) {

            wcharsLeft -= size;
            pathPtr += size;

            if (wcharsLeft > 2) {

                RtlStringCchCatW(pathPtr, wcharsLeft, L"#");
                wcharsLeft--;
                pathPtr++;

                //
                // Each nibble in the path id would need 1 WCHAR
                // upon conversion to WCHAR string. So we'll need
                // 2 WCHARs for each byte. Include the NULL char also
                //
                size = (sizeof(PVOID) + 1) * 2;
                if (size <= wcharsLeft) {

                    PVOID pathId;
                    PUCHAR pathIdPtr;
                    ULONG inx;
                    UCHAR tmpChar;

                    //
                    // Convert the ULONGLONG path id to a string and
                    // append that to DsmPath#
                    //
                    pathId = (PVOID) DSMPathId;

                    pathIdPtr = (PUCHAR) &pathId;

                    for (inx = 0; inx < sizeof(PVOID); inx++) {

                        tmpChar = (*pathIdPtr & 0xF0) >> 4;
                        *pathPtr++ = DsmpGetAsciiForBinary(tmpChar);

                        tmpChar = (*pathIdPtr & 0x0F);
                        *pathPtr++ = DsmpGetAsciiForBinary(tmpChar);

                        pathIdPtr++;
                    }

                    *pathPtr = WNULL;
                }
            }
        }
    }


    return;
}


UCHAR
DsmpGetAsciiForBinary(
    _In_ UCHAR BinaryChar
    )
/*++

Routine Description:

    This routine converts the passed in binary value into ASCII equivalent.

Arguments:

    BinaryChar - The binary value that needs to be converted.

Return Value:

    Corresponding ASCII value.

--*/
{
    UCHAR outChar = 0;


    //
    // Convert a binary nibble into an ASCII character.
    //
    if ((BinaryChar >= 0) && (BinaryChar <= 9)) {
        outChar = BinaryChar + '0';
    } else {
        outChar = BinaryChar + 'A' - 10;
    }


    return outChar;
}


NTSTATUS
DsmpGetDeviceIdList(
    _In_ IN PDEVICE_OBJECT DeviceObject,
    _Out_ OUT PSTORAGE_DESCRIPTOR_HEADER *Descriptor
    )
/*++

Routine Description:

    This routine will perform a query for the StorageDeviceIdProperty and will
    allocate a non-paged buffer to store the data in.
    IMPORTANT: It is the responsibility of the caller to ensure that this buffer is freed.

Arguments:

    DeviceObject - the device to query
    Descriptor - a location to store a pointer to the buffer we allocate

Return Value:

    status.

--*/
{
    STORAGE_PROPERTY_QUERY query;
    PIO_STATUS_BLOCK ioStatus = NULL;
    PSTORAGE_DESCRIPTOR_HEADER descriptor = NULL;
    ULONG length;
    NTSTATUS status = STATUS_UNSUCCESSFUL;


    if (!DeviceObject) {

        status = STATUS_INVALID_PARAMETER;
        goto __Exit_DsmpGetDeviceIdList;
    }

    //
    // Poison the passed in descriptor.
    //
    *Descriptor = NULL;

    //
    // Setup the query buffer.
    //
    query.PropertyId = StorageDeviceIdProperty;
    query.QueryType = PropertyStandardQuery;
    query.AdditionalParameters[0] = 0;

    ioStatus = DsmpAllocatePool(NonPagedPoolNx, sizeof(IO_STATUS_BLOCK), DSM_TAG_IO_STATUS_BLOCK);

    if (!ioStatus) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpGetDeviceIdList;
    }

    ioStatus->Status = 0;
    ioStatus->Information = 0;

    //
    // On the first call, just need to get the length of the descriptor.
    //
    descriptor = (PVOID)&query;
    DsmSendDeviceIoControlSynchronous(IOCTL_STORAGE_QUERY_PROPERTY,
                                      DeviceObject,
                                      &query,
                                      &query,
                                      sizeof(STORAGE_PROPERTY_QUERY),
                                      sizeof(STORAGE_DESCRIPTOR_HEADER),
                                      FALSE,
                                      ioStatus);

    status = ioStatus->Status;

    if(!NT_SUCCESS(status)) {

        descriptor = NULL;

        goto __Exit_DsmpGetDeviceIdList;
    }

    NT_ASSERT(descriptor->Size);
    if (descriptor->Size == 0) {
        status = STATUS_UNSUCCESSFUL;
        goto __Exit_DsmpGetDeviceIdList;
    }

    //
    // This time we know how much data there is so we can
    // allocate a buffer of the correct size
    //
    length = descriptor->Size;

    descriptor = DsmpAllocatePool(NonPagedPoolNx, length, DSM_TAG_DEVICE_ID_LIST);

    if(!descriptor) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpGetDeviceIdList;
    }

    //
    // setup the query again.
    //
    query.PropertyId = StorageDeviceIdProperty;
    query.QueryType = PropertyStandardQuery;
    query.AdditionalParameters[0] = 0;

    //
    // copy the input to the new outputbuffer
    //
    RtlCopyMemory(descriptor,
                  &query,
                  sizeof(STORAGE_PROPERTY_QUERY));

    DsmSendDeviceIoControlSynchronous(IOCTL_STORAGE_QUERY_PROPERTY,
                                      DeviceObject,
                                      descriptor,
                                      descriptor,
                                      sizeof(STORAGE_PROPERTY_QUERY),
                                      length,
                                      0,
                                      ioStatus);

    status = ioStatus->Status;

    if(!NT_SUCCESS(status)) {

        goto __Exit_DsmpGetDeviceIdList;
    }

__Exit_DsmpGetDeviceIdList:

    if (ioStatus) {
        DsmpFreePool(ioStatus);
    }

    if (!NT_SUCCESS(status)) {

        if (descriptor) {
            DsmpFreePool(descriptor);
        }

    } else {
        *Descriptor = descriptor;
    }

    return status;
}


NTSTATUS
DsmpSetTargetPortGroups(
    _In_ IN PDEVICE_OBJECT DeviceObject,
    _In_reads_bytes_(TargetPortGroupsInfoLength) IN PUCHAR TargetPortGroupsInfo,
    _In_ IN ULONG TargetPortGroupsInfoLength
    )
/*++

Routine Description:

    Helper routine to send down SetTargetPortGroups request.

Arguments:

    DeviceObject - The port PDO to which the command should be sent.
    TargetPortGroupsInfo - buffer containing the TPG data.
    TargetPortGroupsInfoLength - size of the TPG buffer.

Return Value:

    STATUS_SUCCESS or appropriate failure code.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER passThrough;
    PSPC3_CDB_SET_TARGET_PORT_GROUPS cdb;
    IO_STATUS_BLOCK ioStatus;
    ULONG alignmentMask = DeviceObject->AlignmentRequirement;
    PUCHAR dataBuffer = NULL;
    SIZE_T allocatedLength = 0;

    NT_ASSERT(TargetPortGroupsInfoLength && TargetPortGroupsInfo);

    //
    // Build request.
    //
    RtlZeroMemory(&passThrough, sizeof(passThrough));

    dataBuffer = DsmpAllocateAlignedPool(NonPagedPoolNx,
                                         TargetPortGroupsInfoLength,
                                         alignmentMask,
                                         DSM_TAG_PASS_THRU,
                                         &allocatedLength);
    if (!dataBuffer) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpSetTargetPortGroups;
    }

__Retry_Request:

    //
    // Build the cdb.
    //
    cdb = (PSPC3_CDB_SET_TARGET_PORT_GROUPS)passThrough.ScsiPassThroughDirect.Cdb;

    cdb->OperationCode = SPC3_SCSIOP_SET_TARGET_PORT_GROUPS;
    cdb->ServiceAction = SPC3_SERVICE_ACTION_TARGET_PORT_GROUPS;
    Get4ByteArrayFromUlong(TargetPortGroupsInfoLength, cdb->ParameterListLength);

    passThrough.ScsiPassThroughDirect.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    passThrough.ScsiPassThroughDirect.CdbLength = 12;
    passThrough.ScsiPassThroughDirect.SenseInfoLength = SPTWB_SENSE_LENGTH;
    passThrough.ScsiPassThroughDirect.DataIn = 0;
    passThrough.ScsiPassThroughDirect.DataTransferLength = TargetPortGroupsInfoLength;
    passThrough.ScsiPassThroughDirect.TimeOutValue = 20;
    passThrough.ScsiPassThroughDirect.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, SenseInfoBuffer);
    passThrough.ScsiPassThroughDirect.DataBuffer = dataBuffer;
    RtlCopyMemory(dataBuffer,
                  TargetPortGroupsInfo,
                  TargetPortGroupsInfoLength);

    DsmSendDeviceIoControlSynchronous(IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                      DeviceObject,
                                      &passThrough,
                                      &passThrough,
                                      sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
                                      sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
                                      FALSE,
                                      &ioStatus);

    if ((passThrough.ScsiPassThroughDirect.ScsiStatus == SCSISTAT_GOOD) &&
        (NT_SUCCESS(ioStatus.Status))) {

        status = STATUS_SUCCESS;

    } else if (NT_SUCCESS(ioStatus.Status) &&
               passThrough.ScsiPassThroughDirect.ScsiStatus == SCSISTAT_CHECK_CONDITION &&
               DsmpShouldRetryTPGRequest((PSENSE_DATA)&passThrough.SenseInfoBuffer, passThrough.ScsiPassThroughDirect.SenseInfoLength)) {

        //
        // Retry the request
        //
        RtlZeroMemory(dataBuffer, TargetPortGroupsInfoLength);
        goto __Retry_Request;

    } else {

        status = ioStatus.Status;
    }

__Exit_DsmpSetTargetPortGroups:

    //
    // Free the passthrough + data buffer.
    //
    if (dataBuffer) {
        DsmpFreePool(dataBuffer);
    }

    return status;
}


NTSTATUS
DsmpSetTargetPortGroupsAsync(
    _In_ IN PDSM_DEVICE_INFO DeviceInfo,
    _In_ IN PIO_COMPLETION_ROUTINE CompletionRoutine,
    _In_ __drv_aliasesMem IN PDSM_TPG_COMPLETION_CONTEXT CompletionContext,
    _In_ IN ULONG TargetPortGroupsInfoLength,
    _In_ __drv_aliasesMem IN PUCHAR TargetPortGroupsInfo
    )
/*++

Routine Description:

    Helper routine to send down SetTargetPortGroups request asynchronously.

    IMPORTANT: Caller needs to free the IRP and allocated system buffer.

Arguments:

    DeviceInfo - The deviceInfo whose corresponding port PDO the command should be sent to.
    CompletionRoutine - completion routine provided by the caller.
    CompletionContext - context passed into the completion routine.
    TargetPortGroupsInfoLength - size of the TPG buffer.
    TargetPortGroupsInfo - buffer containing the TPG data.

Return Value:

    STATUS_SUCCESS or appropriate failure code.

--*/
{
    PDSM_TPG_COMPLETION_CONTEXT tpgCompletionContext = CompletionContext;
    PSCSI_REQUEST_BLOCK srb;
    PSPC3_CDB_SET_TARGET_PORT_GROUPS cdb;
    NTSTATUS status;
    PIRP irp = NULL;
    PIO_STACK_LOCATION irpStack;
    PMDL mdl = NULL;

    srb = tpgCompletionContext->Srb;

    SrbZeroSrb(srb);

    //
    // Allocate an irp.
    //
    irp = IoAllocateIrp(DeviceInfo->TargetObject->StackSize + 1, FALSE);
    if (!irp) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpSetTargetPortGroupsAsync;
    }

    mdl = IoAllocateMdl(TargetPortGroupsInfo,
                        TargetPortGroupsInfoLength,
                        FALSE,
                        FALSE,
                        irp);
    if (!mdl) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpSetTargetPortGroupsAsync;
    }

    MmBuildMdlForNonPagedPool(irp->MdlAddress);

    //
    // It is possible that an implicit state transition may have occurred which
    // will cause every I_T nexus to return an UA (for asymmetric access state
    // changed). So set the number of retries to number of paths (worst case of
    // every path being a separate I_T nexus) plus one for a retry down one of
    // paths.
    //
    tpgCompletionContext->NumberRetries = DeviceInfo->Group->NumberDevices + 1;

    //
    // Set-up the completion routine.
    //
    IoSetCompletionRoutine(irp,
                           CompletionRoutine,
                           (PVOID)CompletionContext,
                           TRUE,
                           TRUE,
                           TRUE);

    //
    // Get the recipient's irpstack location.
    //
    irpStack = IoGetNextIrpStackLocation(irp);

    irpStack->Parameters.Scsi.Srb = srb;
    irpStack->DeviceObject = DeviceInfo->TargetObject;

    //
    // Set the major function code to IRP_MJ_SCSI.
    //
    irpStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;

    //
    // Set the minor function, or many requests will get kicked by by port.
    //
    irpStack->MinorFunction = IRP_MN_SCSI_CLASS;

    srb->Function = SRB_FUNCTION_EXECUTE_SCSI;
    srb->Length = sizeof(SCSI_REQUEST_BLOCK);

    SrbSetCdbLength(srb, sizeof(SPC3_CDB_SET_TARGET_PORT_GROUPS));
    cdb = (PSPC3_CDB_SET_TARGET_PORT_GROUPS)SrbGetCdb(srb);
    cdb->OperationCode = SPC3_SCSIOP_SET_TARGET_PORT_GROUPS;
    cdb->ServiceAction = SPC3_SERVICE_ACTION_TARGET_PORT_GROUPS;
    Get4ByteArrayFromUlong(TargetPortGroupsInfoLength, cdb->ParameterListLength);

    SrbSetTimeOutValue(srb, SPC3_SET_TARGET_PORT_GROUPS_TIMEOUT);
    SrbSetSenseInfoBuffer(srb, tpgCompletionContext->SenseInfoBuffer);
    SrbSetSenseInfoBufferLength(srb, tpgCompletionContext->SenseInfoBufferLength);
    SrbSetDataTransferLength(srb, TargetPortGroupsInfoLength);
    SrbSetDataBuffer(srb, TargetPortGroupsInfo);
    srb->SrbStatus = 0;
    SrbSetScsiStatus(srb, 0);
    SrbSetNextSrb(srb, NULL);
    SrbSetSrbFlags(srb, SRB_FLAGS_DONT_START_NEXT_PACKET | SRB_FLAGS_QUEUE_ACTION_ENABLE |
                     SRB_FLAGS_DATA_OUT | SRB_FLAGS_DISABLE_SYNCH_TRANSFER |
                     SRB_FLAGS_BYPASS_FROZEN_QUEUE | SRB_FLAGS_NO_QUEUE_FREEZE);
    SrbSetQueueAction(srb, SRB_HEAD_OF_QUEUE_TAG_REQUEST);
    SrbSetOriginalRequest(srb, irp);

    irp->UserBuffer = TargetPortGroupsInfo;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();

    //
    // Send the IRP asynchronously
    //
    DsmSendRequestEx(((PDSM_CONTEXT)(DeviceInfo->DsmContext))->MPIOContext,
                     DeviceInfo->TargetObject,
                     irp,
                     DeviceInfo,
                     DSM_CALL_COMPLETION_ON_MPIO_ERROR);

    //
    // We know that the completion routine will always be called.
    //
    status = STATUS_PENDING;


__Exit_DsmpSetTargetPortGroupsAsync:

    if (status != STATUS_PENDING) {

        //
        // This indicates Irp was never sent down to stack (completion routine was never called).
        // We need to clean up.
        //
        if (irp) {

            if (irp->MdlAddress) {
                IoFreeMdl(irp->MdlAddress);
            }

            IoFreeIrp(irp);
        }
    }

    return status;
}


PDSM_LOAD_BALANCE_POLICY_SETTINGS
DsmpCopyLoadBalancePolicies(
    _In_ IN PDSM_GROUP_ENTRY GroupEntry,
    _In_ IN ULONG DsmWmiVersion,
    _In_ IN PVOID SupportedLBPolicies
    )
/*+++

Routine Description:

    This routine copies the LB Policies that needs to be persisted in registry.
    This is done because registry routines can be called at PASSIVE IRQL only.
    So a spinlock cannot be held while accessing registry. So hold a spinlock,
    save the values in a temp buffer, release spinlock, and save data to registry
    from the temp buffer.

    NOTE: This routine MUST be called with DSM_CONTEXT lock held.

Arguements:

    GroupEntry - Group entry
    DsmWmiVersion - version of the MPIO_DSM_Path class to use
    SupportedLBPolicies - LB policy for the group

 Return Value:

    Pointer to  LOAD_BALANCE_POLICY_SETTINGS if successful. Else, NULL
--*/
{
    PDSM_LOAD_BALANCE_POLICY_SETTINGS lbSettings = NULL;
    ULONG sizeNeeded;
    ULONG inx;


    if (((PDSM_Load_Balance_Policy_V2)SupportedLBPolicies)->DSMPathCount == 0) {

        goto __Exit_DsmpCopyLoadBalancePolicies;
    }

    sizeNeeded = sizeof(DSM_LOAD_BALANCE_POLICY_SETTINGS) +
                 ((((PDSM_Load_Balance_Policy_V2)SupportedLBPolicies)->DSMPathCount - 1) * sizeof(MPIO_DSM_Path_V2));;

    lbSettings = DsmpAllocatePool(NonPagedPoolNx,
                                  sizeNeeded,
                                  DSM_TAG_LB_POLICY);

    if (!lbSettings) {
        goto __Exit_DsmpCopyLoadBalancePolicies;
    }

    //
    // Copy the registry key name used to store the LB policies.
    //
    RtlStringCchCopyNW(lbSettings->RegistryKeyName,
                       sizeof(lbSettings->RegistryKeyName) / sizeof(lbSettings->RegistryKeyName[0]),
                       GroupEntry->RegistryKeyName,
                       ((sizeof(lbSettings->RegistryKeyName) - sizeof(WCHAR))/sizeof(WCHAR)));

    //
    // Copy the Load Balance settings for this group
    //
    lbSettings->LoadBalancePolicy = ((PDSM_Load_Balance_Policy_V2)SupportedLBPolicies)->LoadBalancePolicy;

    lbSettings->PathCount = ((PDSM_Load_Balance_Policy_V2)SupportedLBPolicies)->DSMPathCount;

    for (inx = 0; inx < ((PDSM_Load_Balance_Policy_V2)SupportedLBPolicies)->DSMPathCount; inx++) {

        if (DsmWmiVersion == DSM_WMI_VERSION_1) {

            RtlCopyMemory(&(lbSettings->DsmPath[inx]),
                          &(((PDSM_Load_Balance_Policy)SupportedLBPolicies)->DSM_Paths[inx]),
                          sizeof(MPIO_DSM_Path));

            //
            // DSM_WMI_VERSION_1 supports only active and standby states
            //
            (lbSettings->DsmPath[inx]).OptimizedPath = TRUE;

        } else {

            RtlCopyMemory(&(lbSettings->DsmPath[inx]),
                          &(((PDSM_Load_Balance_Policy_V2)SupportedLBPolicies)->DSM_Paths[inx]),
                          sizeof(MPIO_DSM_Path_V2));
        }
    }

__Exit_DsmpCopyLoadBalancePolicies:

    return lbSettings;
}


NTSTATUS
DsmpPersistLBSettings(
    _In_ IN PDSM_LOAD_BALANCE_POLICY_SETTINGS LoadBalanceSettings
    )
/*+++

Routine Description:

    This routine will save the Load Balance settings from LoadBalanceSettings
    to registry.

    NOTE: This routine MUST be called at PASSIVE IRQL

    The format of the registry tree is :

      Services\MSDSM\LoadBalanceSettings ->

               DeviceName -> LoadBalancePolicy REG_DWORD  <LB Value>

                  DsmPath#Suffix -> PrimaryPath     REG_DWORD <Value>
                                    OptimizedPath   REG_DWORD <Value>
                                    PathWeight      REG_DWORD <Value>

      The device name is the one built in DsmpBuildDeviceName

      The Suffix in DsmPath#Suffix is built from the PathId. It is built in
      the routine DsmpGetDSMPathKeyName.

Arguements:

     LoadBalanceSettings - Load Balance settings to be persisted in registry

Return Value:

    STATUS_SUCCESS if the data could be successfully stored in the registry
    Appropriate NT Status code on failure.
--*/
{
    PMPIO_DSM_Path_V2 dsmPath;
    HANDLE lbSettingsKey = NULL;
    HANDLE deviceKey = NULL;
    HANDLE dsmPathKey = NULL;
    UNICODE_STRING subKeyName;
    WCHAR dsmPathName[128];
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;
    ULONG inx;
    PMPIO_DSM_Path_V2 preferredPath = NULL;

    //
    // First open LoadBalanceSettings key under the Service key
    //
    status = DsmpOpenLoadBalanceSettingsKey(KEY_ALL_ACCESS, &lbSettingsKey);
    if (!NT_SUCCESS(status)) {
        goto __Exit_DsmpPersistLBSettings;
    }

    //
    // Now open the key under which the LB settings for the given device is stored
    //
    RtlInitUnicodeString(&subKeyName, LoadBalanceSettings->RegistryKeyName);

    InitializeObjectAttributes(&objectAttributes,
                               &subKeyName,
                               (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                               lbSettingsKey,
                               (PSECURITY_DESCRIPTOR) NULL);

    status = ZwOpenKey(&deviceKey, KEY_ALL_ACCESS, &objectAttributes);

    if (NT_SUCCESS(status)) {

        //
        // Remove all LB policy information as we are going to rewrite it.
        // We do this in case there is stale information about a path that
        // no longer exists
        //
        status = DsmpRegDeleteTree(deviceKey);

        if (NT_SUCCESS(status)) {

        } else {


        }

        ZwClose(deviceKey);
        deviceKey = NULL;

    }

    status = ZwCreateKey(&deviceKey,
                         KEY_ALL_ACCESS,
                         &objectAttributes,
                         0,
                         NULL,
                         REG_OPTION_NON_VOLATILE,
                         NULL);

    if (NT_SUCCESS(status)) {

        PDSM_DEVICE_INFO devInfo;

        for (inx = 0; inx < LoadBalanceSettings->PathCount; inx++) {

            dsmPath = &(LoadBalanceSettings->DsmPath[inx]);

            if (dsmPath->DsmPathId == 0) {

                continue;
            }

            RtlZeroMemory(dsmPathName, sizeof(dsmPathName));

            //
            // Get the sub key name under which the LB settings for
            // the given path is stored.
            //
            DsmpGetDSMPathKeyName(dsmPath->DsmPathId, dsmPathName, 128);


            RtlInitUnicodeString(&subKeyName, dsmPathName);

            RtlZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));

            InitializeObjectAttributes(&objectAttributes,
                                       &subKeyName,
                                       (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                       deviceKey,
                                       (PSECURITY_DESCRIPTOR) NULL);

            status = ZwCreateKey(&dsmPathKey,
                                 KEY_ALL_ACCESS,
                                 &objectAttributes,
                                 0,
                                 NULL,
                                 REG_OPTION_NON_VOLATILE,
                                 NULL);

            if (NT_SUCCESS(status)) {

                if (dsmPath->PreferredPath) {

                    preferredPath = dsmPath;
                }

                devInfo = (PDSM_DEVICE_INFO)dsmPath->Reserved;

                //
                // Save PrimaryPath, PathWeight and OptimizedPath values for this path
                //
                if (devInfo->DesiredState != DSM_DEV_UNDETERMINED) {

                    status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE,
                                                   dsmPathKey,
                                                   DSM_PRIMARY_PATH,
                                                   REG_DWORD,
                                                   &(dsmPath->PrimaryPath),
                                                   sizeof(ULONG));

                    if (NT_SUCCESS(status)) {

                        status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE,
                                                       dsmPathKey,
                                                       DSM_OPTIMIZED_PATH,
                                                       REG_DWORD,
                                                       &(dsmPath->OptimizedPath),
                                                       sizeof(ULONG));

                        if (!NT_SUCCESS(status)) {

 
                        }
                    } else {

                    }
                }

                if (NT_SUCCESS(status)) {

                    if (LoadBalanceSettings->LoadBalancePolicy == DSM_LB_WEIGHTED_PATHS) {

                        status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE,
                                                       dsmPathKey,
                                                       DSM_PATH_WEIGHT,
                                                       REG_DWORD,
                                                       &(dsmPath->PathWeight),
                                                       sizeof(ULONG));

                        if (!NT_SUCCESS(status)) {

                        }
                    }
                }

                ZwClose(dsmPathKey);
                dsmPathKey = NULL;
            } else {
            }

            if (!NT_SUCCESS(status)) {
                break;
            }
        }

        if (NT_SUCCESS(status)) {

            //
            // Save the new Load Balance Policy value,
            //
            status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE,
                                           deviceKey,
                                           DSM_LOAD_BALANCE_POLICY,
                                           REG_DWORD,
                                           &(LoadBalanceSettings->LoadBalancePolicy),
                                           sizeof(ULONG));
            if (NT_SUCCESS(status)) {

                UCHAR explicitlySet = TRUE;

                //
                // Write out that the policy has been explicitly set
                //
                status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE,
                                               deviceKey,
                                               DSM_POLICY_EXPLICITLY_SET,
                                               REG_BINARY,
                                               &explicitlySet,
                                               sizeof(UCHAR));

                if (NT_SUCCESS(status)) {

                    //
                    // If FailOver-Only policy, set the PreferredPath, if specified
                    //
                    if (preferredPath) {

                        status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE,
                                                       deviceKey,
                                                       DSM_PREFERRED_PATH,
                                                       REG_BINARY,
                                                       &(preferredPath->DsmPathId),
                                                       sizeof(ULONGLONG));
                    }
                } else {

                }
            } else {

            }
        }
    }

__Exit_DsmpPersistLBSettings:

    if (dsmPathKey) {
        ZwClose(dsmPathKey);
    }

    if (deviceKey) {
        ZwClose(deviceKey);
    }

    if (lbSettingsKey) {
        ZwClose(lbSettingsKey);
    }

    return status;
}


NTSTATUS
DsmpSetDeviceALUAState(
    _In_ IN PDSM_CONTEXT DsmContext,
    _In_ IN PDSM_DEVICE_INFO DeviceInfo,
    _In_ IN DSM_DEVICE_STATE DevState
    )
/*++

Routine Description:

    Helper routine to build the STPG info and send it down to modify the passed in
    devInfo's state.

Arguments:

    DsmContext - DSM context.
    DeviceInfo - DevInfo whose state needs to be changed.
    DevState - New state to be set.

Return Value:

    STATUS_SUCCESS or appropriate failure code.

--*/
{
    PUCHAR targetPortGroupsInfo = NULL;
    ULONG targetPortGroupsInfoLength;
    PSPC3_SET_TARGET_PORT_GROUP_DESCRIPTOR tpgDescriptor = NULL;
    NTSTATUS status;

    //
    // Send down SetTPG to set the appropriate access state
    // (The TPG block will contain the header and a SetTPG descriptor).
    //
    targetPortGroupsInfoLength = SPC3_TARGET_PORT_GROUPS_HEADER_SIZE +
                                 sizeof(SPC3_SET_TARGET_PORT_GROUP_DESCRIPTOR);

    targetPortGroupsInfo = DsmpAllocatePool(NonPagedPoolNx,
                                            targetPortGroupsInfoLength,
                                            DSM_TAG_TARGET_PORT_GROUPS);

    if (targetPortGroupsInfo) {

        tpgDescriptor = (PSPC3_SET_TARGET_PORT_GROUP_DESCRIPTOR)(targetPortGroupsInfo + SPC3_TARGET_PORT_GROUPS_HEADER_SIZE);
        tpgDescriptor->AsymmetricAccessState = DevState;
        REVERSE_BYTES_SHORT(&tpgDescriptor->TPG_Identifier, &DeviceInfo->TargetPortGroup->Identifier);

        status = DsmpSetTargetPortGroups(DeviceInfo->TargetObject,
                                         targetPortGroupsInfo,
                                         targetPortGroupsInfoLength);

        if (NT_SUCCESS(status)) {

            //
            // An explicit transition may cause changes to some other TPGs.
            // So we need to query for the states of all the TPGs and update
            // our internal list and its elements.
            //
            status = DsmpGetDeviceALUAState(DsmContext,
                                            DeviceInfo,
                                            NULL);

        } else {

        }

    } else {

        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    if (targetPortGroupsInfo) {
        DsmpFreePool(targetPortGroupsInfo);
    }


    return status;
}


NTSTATUS
DsmpAdjustDeviceStatesALUA(
    _In_ IN PDSM_GROUP_ENTRY Group,
    _In_opt_ IN PDSM_DEVICE_INFO PreferredActiveDeviceInfo,
    _In_ IN ULONG SpecialHandlingFlag
    )
/*++

Routine Description:

    Helper routine to build the adjust every device state in the group taking
    the following into consideration:
    1. PreferredActiveDeviceInfo
    2. DeviceInfo's TPG state
    3. Preferred Path
    4. LB Policy

Arguments:

    Group - Pseudo-LUN whose path states need to be adjusted.
    PreferredActiveDeviceInfo - DevInfo whose state needs to preferrably made
                                A/O, if possible. This parameter is optional.

    SpecialHandlingFlag - Flags to indicate any special handling requirement

Return Value:

    STATUS_SUCCESS or appropriate failure code.

--*/
{
    ULONG index;
    PDSM_DEVICE_INFO deviceInfo;
    PDSM_DEVICE_INFO activeDevice = NULL;
    DSM_DEVICE_STATE devState;
    NTSTATUS status = STATUS_SUCCESS;


    //
    // Ensure that:
    // 1. All devices match their ALUA state.
    // 2. For RRWS, if a device's desired state is non-A/O, but ALUA state is A/O, mask it.
    // 3. For FOO there must be only one A/O device. Preferably the preferred path.
    //
    for (index = 0; index < DSM_MAX_PATHS; index++) {

        deviceInfo = Group->DeviceList[index];

        if (deviceInfo) {

            devState = deviceInfo->State;

            if (!DsmpIsDeviceFailedState(deviceInfo->State) &&
                DsmpIsDeviceInitialized(deviceInfo) &&
                DsmpIsDeviceUsable(deviceInfo) &&
                DsmpIsDeviceUsablePR(deviceInfo)) {


                deviceInfo->PreviousState = deviceInfo->State;
                deviceInfo->State = deviceInfo->ALUAState;


                if (deviceInfo->ALUAState == DSM_DEV_ACTIVE_OPTIMIZED) {

                    //
                    // In FOO and RRWS, we need to mask states.
                    //
                    switch (Group->LoadBalanceType) {
                        case DSM_LB_FAILOVER: {

                            //
                            // Cache the first available devInfo that is in A/O
                            //
                            if (!activeDevice) {

                                activeDevice = deviceInfo;


                                break;
                            }

                            //
                            // Check if this deviceInfo is the preferred path. If yes,
                            // mask the active device's state and make this the new
                            // active device.
                            //
                            if (Group->PreferredPath == (ULONGLONG)((ULONG_PTR)deviceInfo->FailGroup->PathId)) {

                                activeDevice->PreviousState = activeDevice->State;
                                activeDevice->State = (activeDevice->DesiredState == DSM_DEV_UNDETERMINED ||
                                                       activeDevice->DesiredState == DSM_DEV_ACTIVE_OPTIMIZED) ? DSM_DEV_ACTIVE_UNOPTIMIZED : activeDevice->DesiredState;


                                activeDevice = deviceInfo;


                                break;
                            }

                            //
                            // If active device's desired state is not A/O but this
                            // deviceInfo's is, then mask the active device's state
                            // and make this one the new active device.
                            //
                            if (activeDevice->DesiredState != DSM_DEV_ACTIVE_OPTIMIZED &&
                                activeDevice->DesiredState != DSM_DEV_UNDETERMINED) {

                                //
                                // The exception though is if the current active device
                                // is the preferred path
                                //
                                if (Group->PreferredPath == (ULONGLONG)((ULONG_PTR)activeDevice->FailGroup->PathId)) {

                                    deviceInfo->PreviousState = deviceInfo->State;
                                    deviceInfo->State = (deviceInfo->DesiredState == DSM_DEV_UNDETERMINED ||
                                                         deviceInfo->DesiredState == DSM_DEV_ACTIVE_OPTIMIZED) ? DSM_DEV_ACTIVE_UNOPTIMIZED : deviceInfo->DesiredState;

                                } else {

                                    //
                                    // If this is the devInfo that is preferred to be A/O, make it such
                                    //
                                    if (PreferredActiveDeviceInfo &&
                                        PreferredActiveDeviceInfo == deviceInfo) {

                                        activeDevice->PreviousState = activeDevice->State;
                                        activeDevice->State = activeDevice->DesiredState;

                                        activeDevice = deviceInfo;

                                    } else {

                                        //
                                        // Check if this devInfo desires to be in A/O, since the currently
                                        // active one doesn't want to be.
                                        //
                                        if (deviceInfo->DesiredState != DSM_DEV_ACTIVE_OPTIMIZED &&
                                            deviceInfo->DesiredState != DSM_DEV_UNDETERMINED) {

                                            //
                                            // This deviceInfo's desire is also not to be in A/O,
                                            // so just leave the current one active.
                                            //
                                            if (devState == DSM_DEV_ACTIVE_OPTIMIZED) {

                                                //
                                                // Exception is if we're processing the device whose state before
                                                // RTPG was sent was already A/O, it is best to leave this device
                                                // in A/O state.
                                                //

                                                activeDevice->PreviousState = activeDevice->State;
                                                activeDevice->State = (activeDevice->DesiredState == DSM_DEV_UNDETERMINED ||
                                                                       activeDevice->DesiredState == DSM_DEV_ACTIVE_OPTIMIZED) ? DSM_DEV_ACTIVE_UNOPTIMIZED : activeDevice->DesiredState;


                                                activeDevice = deviceInfo;

                                            } else {

                                                //
                                                // This device wasn't in A/O state before, so just leave
                                                // the currently selected active device as is.
                                                //
                                                deviceInfo->PreviousState = deviceInfo->State;
                                                deviceInfo->State = deviceInfo->DesiredState;

                                            }
                                        } else {

                                            //
                                            // Current devInfo wants (or doesn't) mind being in
                                            // A/O, whereas the current active device doesn't, so
                                            // mask the active device and make this devInfo the
                                            // active device.
                                            //
                                            activeDevice->PreviousState = activeDevice->State;
                                            activeDevice->State = activeDevice->DesiredState;


                                            activeDevice = deviceInfo;

 
                                        }
                                    }
                                }
                            } else {

                                //
                                // The single overriding factor is always the preferred path.
                                // Everything else is secondary, so first check if the currently
                                // active device can even be overridden by another one.
                                //
                                if (Group->PreferredPath != (ULONGLONG)((ULONG_PTR)activeDevice->FailGroup->PathId)) {

                                    //
                                    // It can't be overridden, so we're done.
                                    //
                                    deviceInfo->PreviousState = deviceInfo->State;
                                    deviceInfo->State = (deviceInfo->DesiredState == DSM_DEV_UNDETERMINED ||
                                                         deviceInfo->DesiredState == DSM_DEV_ACTIVE_OPTIMIZED) ? DSM_DEV_ACTIVE_UNOPTIMIZED : deviceInfo->DesiredState;

  
                                } else {

                                    //
                                    // Active device's desired state is A/O but it isn't the preferred
                                    // path. Check if this devInfo is preferred as A/O.
                                    //
                                    if (PreferredActiveDeviceInfo &&
                                        PreferredActiveDeviceInfo == deviceInfo) {

                                        activeDevice->PreviousState = activeDevice->State;
                                        activeDevice->State = (activeDevice->DesiredState == DSM_DEV_UNDETERMINED ||
                                                               activeDevice->DesiredState == DSM_DEV_ACTIVE_OPTIMIZED) ? DSM_DEV_ACTIVE_UNOPTIMIZED : activeDevice->DesiredState;


                                        activeDevice = deviceInfo;


                                    } else {

                                        //
                                        // Active device's desired state is A/O but it isn't the
                                        // preferred path. Check if this devInfo's desired state
                                        // is also A/O. If yes, we'll need to make certain decisions.
                                        //
                                        if (deviceInfo->DesiredState != DSM_DEV_ACTIVE_OPTIMIZED &&
                                            deviceInfo->DesiredState != DSM_DEV_UNDETERMINED) {

                                            //
                                            // Since this device doesn't desire to be in
                                            // A/O and we already have an active device, just
                                            // mask its state.
                                            //
                                            deviceInfo->PreviousState = deviceInfo->State;
                                            deviceInfo->State = deviceInfo->DesiredState;


                                        } else {

                                            //
                                            // Active device is in A/O and this device desires to be in
                                            // A/O too. Make this the new active device only if its state
                                            // before the RTPG was already A/O.
                                            //
                                            if (devState == DSM_DEV_ACTIVE_OPTIMIZED) {

                                                activeDevice->PreviousState = activeDevice->State;
                                                activeDevice->State = (activeDevice->DesiredState == DSM_DEV_UNDETERMINED ||
                                                                       activeDevice->DesiredState == DSM_DEV_ACTIVE_OPTIMIZED) ? DSM_DEV_ACTIVE_UNOPTIMIZED : activeDevice->DesiredState;



                                                activeDevice = deviceInfo;


                                            } else {

                                                //
                                                // Just leave the currently active one alone.
                                                //
                                                deviceInfo->PreviousState = deviceInfo->State;
                                                deviceInfo->State = (deviceInfo->DesiredState == DSM_DEV_UNDETERMINED ||
                                                                     deviceInfo->DesiredState == DSM_DEV_ACTIVE_OPTIMIZED) ? DSM_DEV_ACTIVE_UNOPTIMIZED : deviceInfo->DesiredState;

                                            }
                                        }
                                    }
                                }
                            }
                            break;
                        }

                        case DSM_LB_ROUND_ROBIN_WITH_SUBSET: {

                            //
                            // At least one path needs to be in A/O state, so
                            // cache the first available devInfo that is in A/O
                            //
                            if (!activeDevice) {

                                activeDevice = deviceInfo;


                                break;
                            }

                            //
                            // Check if this device is preferred to be in A/O
                            //
                            if (PreferredActiveDeviceInfo &&
                                PreferredActiveDeviceInfo == deviceInfo) {

                                //
                                // If the currently active device, doesn't desire to be in
                                // A/O state, mask its state.
                                //
                                if (activeDevice->DesiredState != DSM_DEV_ACTIVE_OPTIMIZED &&
                                    activeDevice->DesiredState != DSM_DEV_UNDETERMINED) {

                                    activeDevice->PreviousState = activeDevice->State;
                                    activeDevice->State = activeDevice->DesiredState;


                                }

                                activeDevice = deviceInfo;

                            } else {

                                //
                                // If this device's desired state is specified and not A/O,
                                // mask its path state.
                                //
                                if (deviceInfo->DesiredState != DSM_DEV_ACTIVE_OPTIMIZED &&
                                    deviceInfo->DesiredState != DSM_DEV_UNDETERMINED) {

                                    deviceInfo->PreviousState = deviceInfo->State;
                                    deviceInfo->State = deviceInfo->DesiredState;


                                } else {

                                    //
                                    // Since this devInfo desires to be in A/O, we are assured
                                    // of at least one path in A/O. So check to see if the
                                    // currently active device doesn't desire to be in A/O.
                                    //
                                    if (activeDevice->DesiredState != DSM_DEV_ACTIVE_OPTIMIZED &&
                                        activeDevice->DesiredState != DSM_DEV_UNDETERMINED) {

                                        activeDevice->PreviousState = activeDevice->State;
                                        activeDevice->State = activeDevice->DesiredState;



                                        activeDevice = deviceInfo;

                                    }
                                }
                            }

                            break;
                        }

                        default: {

                            //
                            // For RR, LQD and WP, paths must be in the same
                            // state as their corresponding TPG. Preferably
                            // all should be A/O.
                            //
                            if (deviceInfo->State != DSM_DEV_ACTIVE_OPTIMIZED) {
                                DSM_ASSERT(deviceInfo->State == deviceInfo->ALUAState);
                            }

                            break;
                        }
                    }
                }
            }
        }
    }

    //
    // There may have been a change to the device states.
    // DsmpGetPath() will pick these changes for RR, RRWS and LQD.
    // However, it won't for FOO and WP, so update PTBU if needed.
    //
    if (Group->LoadBalanceType == DSM_LB_FAILOVER ||
        Group->LoadBalanceType == DSM_LB_WEIGHTED_PATHS) {

        deviceInfo = DsmpGetActivePathToBeUsed(Group, FALSE, SpecialHandlingFlag);

        if (deviceInfo) {

            InterlockedExchangePointer(&(Group->PathToBeUsed), deviceInfo->FailGroup);
        }
    }



    return status;
}


PDSM_WORKITEM
DsmpAllocateWorkItem(
    _In_ IN PDEVICE_OBJECT DeviceObject,
    _In_ IN PVOID Context
    )
/*++

Routine Description:

    Allocates a work item to handle reservation failover.

Arguments:

    DeviceObject - Target device.
    Context - Workitem context

Return Value:

    Allocated workitem or NULL (if low memory).

--*/
{
    PDSM_WORKITEM dsmWorkItem = NULL;


    dsmWorkItem = DsmpAllocatePool(NonPagedPoolNx,
                                   sizeof(DSM_WORKITEM),
                                   DSM_TAG_WORKITEM);
    if (dsmWorkItem != NULL) {

        dsmWorkItem->WorkItem = IoAllocateWorkItem(DeviceObject);
        if (dsmWorkItem->WorkItem != NULL) {

            dsmWorkItem->Context = Context;
        } else {

            DsmpFreePool(dsmWorkItem);
            dsmWorkItem = NULL;
        }
    }


    return dsmWorkItem;
}


VOID
DsmpFreeWorkItem(
    _In_ IN PDSM_WORKITEM DsmWorkItem
    )
{
    PVOID temp = DsmWorkItem;


    if (DsmWorkItem != NULL) {

        if (DsmWorkItem->WorkItem != NULL) {
            IoFreeWorkItem(DsmWorkItem->WorkItem);
        }

        DsmpFreePool(DsmWorkItem);
    }

    return;
}


VOID
DsmpFreeZombieGroupList(
    _In_ IN PDSM_FAILOVER_GROUP FailGroup
    )
{
     PLIST_ENTRY zombieEntry = NULL;


     while (!IsListEmpty(&FailGroup->ZombieGroupList)) {

         zombieEntry = RemoveHeadList(&FailGroup->ZombieGroupList);

         if (zombieEntry) {

             DsmpFreePool(zombieEntry);
         }
     }

}


NTSTATUS
DsmpGetDeviceALUAState(
    _In_ IN PDSM_CONTEXT DsmContext,
    _In_ IN PDSM_DEVICE_INFO DeviceInfo,
    _In_opt_ IN PDSM_DEVICE_STATE DevState
    )
/*++

Routine Description:

    Helper routine to build the RTPG info and send it down to retrieve the
    devInfo's current state.

Arguments:

    DsmContext - DSM context.
    DeviceInfo - DevInfo whose state needs to be changed.
    DevState   - Current state of passed in DeviceInfo.

Return Value:

    STATUS_SUCCESS or appropriate failure code.

--*/
{
    PUCHAR targetPortGroupsInfo = NULL;
    ULONG targetPortGroupsInfoLength = 0;
    PDSM_TARGET_PORT_GROUP_ENTRY targetPortGroup = NULL;
    KIRQL irql;
    NTSTATUS status;
    ULONG index;



    status = DsmpReportTargetPortGroups(DeviceInfo->TargetObject,
                                        &targetPortGroupsInfo,
                                        &targetPortGroupsInfoLength);


    if (NT_SUCCESS(status) && targetPortGroupsInfo != NULL) {

        irql = ExAcquireSpinLockExclusive(&(DsmContext->DsmContextLock));

        status = DsmpParseTargetPortGroupsInformation(DsmContext,
                                                      DeviceInfo->Group,
                                                      targetPortGroupsInfo,
                                                      targetPortGroupsInfoLength);

        for (index = 0; index < DSM_MAX_PATHS; index++) {

            targetPortGroup = DeviceInfo->Group->TargetPortGroupList[index];

            if (targetPortGroup) {

                DsmpUpdateTargetPortGroupDevicesStates(targetPortGroup, targetPortGroup->AsymmetricAccessState);
            }
        }

        ExReleaseSpinLockExclusive(&(DsmContext->DsmContextLock), irql);

        if (DevState) {

            *DevState = DeviceInfo->State;
        }

    } else {

    }

    if (targetPortGroupsInfo) {

        DsmpFreePool(targetPortGroupsInfo);
    }


    return status;
}


NTSTATUS
DsmpRegCopyTree(
    _In_ IN HANDLE SourceKey,
    _In_ IN HANDLE DestKey
    )
/*++

Routine Description:

    Copies a reg subtree from source key to destination key.
    This routine will first copy over all the key's values, and then
    copy the subkeys, each time recursively handling the subkey's
    values and its subtree.

Arguments:

    SourceKey - Handle to the root of the subtree to copy over.
    DestKey   - Handle to the root of the new tree.

Return Value:

    STATUS_SUCCESS upon successfully coping over the tree.
    Appropriate NT error code in case of failure.

--*/
{
    ULONG numValues = 0;
    ULONG numSubKeys = 0;
    ULONG lengthOfValueName = 0;
    ULONG lengthOfValueData = 0;
    ULONG lengthOfKeyName = 0;
    LPWSTR valueBuf = NULL;
    BYTE *valueDataBuf = NULL;
    ULONG valueDataType;
    ULONG titleIndex;
    HANDLE srcSubKey = NULL;
    HANDLE destSubKey = NULL;
    LPWSTR subKey = NULL;
    NTSTATUS status;
    PKEY_FULL_INFORMATION keyFullInfo = NULL;
    ULONG length = sizeof(KEY_FULL_INFORMATION);
    ULONG index = 0;
    PKEY_VALUE_FULL_INFORMATION keyValueFullInfo = NULL;
    PKEY_BASIC_INFORMATION keyBasicInfo = NULL;
    OBJECT_ATTRIBUTES objectAttributes;


    if (!SourceKey || !DestKey) {

        status = STATUS_INVALID_PARAMETER;
        goto __Exit_DsmpRegCopyTree;
    }

    //
    // Query the source key for information about number of subkeys, number of values, etc.
    //
    do {
        if (keyFullInfo) {

            DsmpFreePool(keyFullInfo);
        }

        keyFullInfo = DsmpAllocatePool(NonPagedPoolNxCacheAligned, length, DSM_TAG_REG_KEY_RELATED);

        if (!keyFullInfo) {


            status = STATUS_INSUFFICIENT_RESOURCES;
            goto __Exit_DsmpRegCopyTree;
        }

        status = ZwQueryKey(SourceKey,
                            KeyFullInformation,
                            keyFullInfo,
                            length,
                            &length);

    } while (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW);

    if (!NT_SUCCESS(status)) {


        goto __Exit_DsmpRegCopyTree;
    }

    numSubKeys = keyFullInfo->SubKeys;
    numValues = keyFullInfo->Values;
    lengthOfKeyName = keyFullInfo->MaxNameLen + sizeof(WCHAR);
    lengthOfValueName = keyFullInfo->MaxValueNameLen + sizeof(WCHAR);
    lengthOfValueData = keyFullInfo->MaxValueDataLen + sizeof(WCHAR);

    //
    // Allocate a buffer for the name of the value
    //
    valueBuf = DsmpAllocatePool(NonPagedPoolNxCacheAligned,
                                lengthOfValueName,
                                DSM_TAG_REG_KEY_RELATED);
    if (!valueBuf) {


        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpRegCopyTree;
    }

    //
    // Allocate a buffer for the value data
    //
    valueDataBuf = DsmpAllocatePool(NonPagedPoolNxCacheAligned,
                                    lengthOfValueData,
                                    DSM_TAG_REG_KEY_RELATED);

    if (!valueDataBuf) {


        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpRegCopyTree;
    }

    //
    // First enumerate all of the values
    //
    status = STATUS_SUCCESS;
    for (index = 0; index < numValues && NT_SUCCESS(status); index++) {

        UNICODE_STRING valueName;

        length = sizeof(KEY_VALUE_FULL_INFORMATION);

        do {

            if (keyValueFullInfo) {

                DsmpFreePool(keyValueFullInfo);
            }

            keyValueFullInfo = DsmpAllocatePool(NonPagedPoolNxCacheAligned, length, DSM_TAG_REG_KEY_RELATED);

            if (!keyValueFullInfo) {


                status = STATUS_INSUFFICIENT_RESOURCES;
                goto __Exit_DsmpRegCopyTree;
            }

            //
            // Get the information of the index'th value
            //
            status = ZwEnumerateValueKey(SourceKey,
                                         index,
                                         KeyValueFullInformation,
                                         keyValueFullInfo,
                                         length,
                                         &length);

        } while (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpRegCopyTree;
        }

        //
        // Capture the data type, data value, and value name.
        //
        titleIndex = keyValueFullInfo->TitleIndex;
        valueDataType = keyValueFullInfo->Type;

        RtlZeroMemory(valueDataBuf, lengthOfValueData);
        RtlCopyMemory(valueDataBuf,
                      (PUCHAR)keyValueFullInfo + keyValueFullInfo->DataOffset,
                      keyValueFullInfo->DataLength);

        RtlZeroMemory(valueBuf, lengthOfValueName);
        RtlStringCbCopyNW(valueBuf, lengthOfValueName, keyValueFullInfo->Name, keyValueFullInfo->NameLength);
        RtlInitUnicodeString(&valueName, valueBuf);

        //
        // Copy the value over to the new key
        //
        status = ZwSetValueKey(DestKey,
                               &valueName,
                               titleIndex,
                               valueDataType,
                               valueDataBuf,
                               keyValueFullInfo->DataLength);
    }

    if (!NT_SUCCESS(status)) {

        goto __Exit_DsmpRegCopyTree;
    }

    //
    // Allocate buffer for subkey name
    //
    subKey = DsmpAllocatePool(NonPagedPoolNxCacheAligned,
                              lengthOfKeyName,
                              DSM_TAG_REG_KEY_RELATED);

    if(!subKey) {



        status = STATUS_INSUFFICIENT_RESOURCES;
        goto __Exit_DsmpRegCopyTree;
    }

    //
    // Now Enumerate all of the subkeys
    //
    length = sizeof(KEY_BASIC_INFORMATION);
    for(index = 0; index < numSubKeys && NT_SUCCESS(status); index++) {

        UNICODE_STRING subKeyName;

        do {
            if (keyBasicInfo) {

                DsmpFreePool(keyBasicInfo);
            }

            keyBasicInfo = DsmpAllocatePool(NonPagedPoolNxCacheAligned,
                                            length,
                                            DSM_TAG_REG_KEY_RELATED);

            if (!keyBasicInfo) {


                status = STATUS_INSUFFICIENT_RESOURCES;
                goto __Exit_DsmpRegCopyTree;
            }

            //
            // Enumerate the index'th subkey
            //
            status = ZwEnumerateKey(SourceKey,
                                    index,
                                    KeyBasicInformation,
                                    keyBasicInfo,
                                    length,
                                    &length);

        } while (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpRegCopyTree;
        }

        RtlZeroMemory(subKey, lengthOfKeyName);
        RtlStringCbCopyNW(subKey, lengthOfKeyName, keyBasicInfo->Name, keyBasicInfo->NameLength);
        RtlInitUnicodeString(&subKeyName, subKey);

        //
        // Open a handle to the the subkey on the old device.
        //
        InitializeObjectAttributes(&objectAttributes,
                                   &subKeyName,
                                   (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                   SourceKey,
                                   (PSECURITY_DESCRIPTOR) NULL);

        if (srcSubKey) {
            ZwClose(srcSubKey);
            srcSubKey = NULL;
        }

        status = ZwOpenKey(&srcSubKey,
                           KEY_ALL_ACCESS,
                           &objectAttributes);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpRegCopyTree;
        }

        InitializeObjectAttributes(&objectAttributes,
                                   &subKeyName,
                                   (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                   DestKey,
                                   (PSECURITY_DESCRIPTOR) NULL);

        if (destSubKey) {
            ZwClose(destSubKey);
            destSubKey = NULL;
        }

        //
        // Create the subkey on the new device.
        //
        status = ZwCreateKey(&destSubKey,
                             KEY_ALL_ACCESS,
                             &objectAttributes,
                             0,
                             NULL,
                             REG_OPTION_NON_VOLATILE,
                             NULL);

        if (!NT_SUCCESS(status)) {


            goto __Exit_DsmpRegCopyTree;
        }

        //
        // That's it. We've got everything we need (ie. handles to the two new
        // subtrees' roots. Call recursively.
        //
        status = DsmpRegCopyTree(srcSubKey, destSubKey);
    }

__Exit_DsmpRegCopyTree:

    if (keyFullInfo) {
        DsmpFreePool(keyFullInfo);
    }

    if (valueBuf) {
        DsmpFreePool(valueBuf);
    }

    if (valueDataBuf) {
        DsmpFreePool(valueDataBuf);
    }

    if (keyValueFullInfo) {
        DsmpFreePool(keyValueFullInfo);
    }

    if (subKey) {
        DsmpFreePool(subKey);
    }

    if (keyBasicInfo) {
        DsmpFreePool(keyBasicInfo);
    }

    if (srcSubKey) {
        ZwClose(srcSubKey);
    }

    if (destSubKey) {
        ZwClose(destSubKey);
    }


    return status;
}


NTSTATUS
DsmpRegDeleteTree(
    _In_ IN HANDLE KeyRoot
    )
/*++
Routine Description:

    This routine is a recursive worker that enumerates the subkeys
    of a given key, applies itself to each one, then deletes itself.

Arguments:

    KeyRoot - Supplies a handle to the root of subtree to be deleted.

Return Value:

    STATUS_SUCCESS - upon successful deletion of subtree.
    Appropriate NT error code upon failure.

--*/
{
    NTSTATUS status;
    PKEY_FULL_INFORMATION keyFullInfo = NULL;
    ULONG length = sizeof(KEY_FULL_INFORMATION);
    ULONG numSubKeys;
    ULONG lengthOfKeyName;
    LPWSTR subKey = NULL;
    PKEY_BASIC_INFORMATION keyBasicInfo = NULL;
    ULONG index = 0;
    HANDLE srcSubKey = NULL;
    OBJECT_ATTRIBUTES objectAttributes;


    if (!KeyRoot) {

        status = STATUS_INVALID_PARAMETER;
        goto __Exit_DsmpRegDeleteTree;
    }

    //
    // Query the source key for information about number of subkeys and max
    // length needed for subkey name.
    //
    do {
        if (keyFullInfo) {

            DsmpFreePool(keyFullInfo);
        }

        keyFullInfo = DsmpAllocatePool(NonPagedPoolNxCacheAligned, length, DSM_TAG_REG_KEY_RELATED);

        if (!keyFullInfo) {


            status = STATUS_INSUFFICIENT_RESOURCES;
            goto __Exit_DsmpRegDeleteTree;
        }

        status = ZwQueryKey(KeyRoot,
                            KeyFullInformation,
                            keyFullInfo,
                            length,
                            &length);

    } while (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW);

    if (!NT_SUCCESS(status)) {

        goto __Exit_DsmpRegDeleteTree;
    }

    numSubKeys = keyFullInfo->SubKeys;
    lengthOfKeyName = keyFullInfo->MaxNameLen + sizeof(WCHAR);

    if (numSubKeys) {

        //
        // Allocate buffer for subkey name
        //
        subKey = DsmpAllocatePool(NonPagedPoolNxCacheAligned,
                                  lengthOfKeyName,
                                  DSM_TAG_REG_KEY_RELATED);

        if(!subKey) {

            status = STATUS_INSUFFICIENT_RESOURCES;
            goto __Exit_DsmpRegDeleteTree;
        }

        //
        // Now Enumerate all of the subkeys
        //
        index = numSubKeys - 1;
        length = sizeof(KEY_BASIC_INFORMATION);
        do {

            UNICODE_STRING subKeyName;

            do {
                if (keyBasicInfo) {

                    DsmpFreePool(keyBasicInfo);
                }

                keyBasicInfo = DsmpAllocatePool(NonPagedPoolNxCacheAligned,
                                                length,
                                                DSM_TAG_REG_KEY_RELATED);

                if (!keyBasicInfo) {

                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto __Exit_DsmpRegDeleteTree;
                }

                //
                // Enumerate the index'th subkey
                //
                status = ZwEnumerateKey(KeyRoot,
                                        index,
                                        KeyBasicInformation,
                                        keyBasicInfo,
                                        length,
                                        &length);

            } while (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW);

            if (NT_SUCCESS(status)) {

                RtlZeroMemory(subKey, lengthOfKeyName);
                RtlStringCbCopyNW(subKey, lengthOfKeyName, keyBasicInfo->Name, keyBasicInfo->NameLength);
                RtlInitUnicodeString(&subKeyName, subKey);

                //
                // Open a handle to the the current root's subkey.
                //
                InitializeObjectAttributes(&objectAttributes,
                                           &subKeyName,
                                           (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
                                           KeyRoot,
                                           (PSECURITY_DESCRIPTOR) NULL);

                status = ZwOpenKey(&srcSubKey,
                                   KEY_ALL_ACCESS,
                                   &objectAttributes);

                if (!NT_SUCCESS(status)) {


                    goto __Exit_DsmpRegDeleteTree;
                }

                //
                // Delete this key's subtree (recursively).
                //
                status = DsmpRegDeleteTree(srcSubKey);

                ZwClose(srcSubKey);
                srcSubKey = NULL;
            }

            index--;

        } while (status != STATUS_NO_MORE_ENTRIES && (LONG)index >= 0);

        if (status == STATUS_NO_MORE_ENTRIES) {

            status = STATUS_SUCCESS;
        }
    }

    ZwDeleteKey(KeyRoot);

__Exit_DsmpRegDeleteTree:

    if (srcSubKey) {
        ZwClose(srcSubKey);
    }

    if (keyFullInfo) {
        DsmpFreePool(keyFullInfo);
    }

    if (subKey) {
        DsmpFreePool(subKey);
    }

    if (keyBasicInfo) {
        DsmpFreePool(keyBasicInfo);
    }


    return status;
}


#if defined (_WIN64)
VOID
DsmpPassThroughPathTranslate32To64(
    _In_ IN PMPIO_PASS_THROUGH_PATH32 MpioPassThroughPath32,
    _Inout_ IN OUT PMPIO_PASS_THROUGH_PATH MpioPassThroughPath64
    )
/*++

Routine Description:

    On WIN64, the SCSI_PASS_THROUGH field of the MPIO_PASS_THROUGH_PATH structure
    sent down by a 32-bit application must be marshaled into a 64-bit version
    of the structure.  This function performs that marshaling.

Arguments:

    MpioPassThroughPath32 - Supplies a pointer to a 32-bit MPIO_PASS_THROUGH_PATH
                            struct.

    MpioPassThroughPath64 - Supplies a pointer to a 64-bit MPIO_PASS_THROUGH_PATH
                            structure, into which we'll copy the marshaled
                            32-bit data.

Return Value:

    None.

--*/
{
    //
    // Copy the first set of fields out of the 32-bit structure.  These
    // fields all line up between the 32 & 64 bit versions.
    //
    // Note that we do NOT adjust the length in the SrbControl.  This is to
    // allow the calling routine to compare the length of the actual
    // control area against the offsets embedded within.  If we adjusted the
    // length then requests with the sense area backed against the control
    // area would be rejected because the 64-bit control area is 4 bytes
    // longer.
    //
    RtlCopyMemory(MpioPassThroughPath64,
                  MpioPassThroughPath32,
                  FIELD_OFFSET(SCSI_PASS_THROUGH, DataBufferOffset));

    //
    // Copy over the CDB.
    //
    RtlCopyMemory(MpioPassThroughPath64->PassThrough.Cdb,
                  MpioPassThroughPath32->PassThrough.Cdb,
                  16 * sizeof(UCHAR)
                  );

    //
    // Copy over the rest of the fields of the structure.
    //
    MpioPassThroughPath64->Version = MpioPassThroughPath32->Version;
    MpioPassThroughPath64->Length = MpioPassThroughPath32->Length;
    MpioPassThroughPath64->Flags = MpioPassThroughPath32->Flags;
    MpioPassThroughPath64->PortNumber = MpioPassThroughPath32->PortNumber;
    MpioPassThroughPath64->MpioPathId = MpioPassThroughPath32->MpioPathId;

    //
    // Copy the fields that follow the ULONG_PTR.
    //
    MpioPassThroughPath64->PassThrough.DataBufferOffset = (ULONG_PTR)MpioPassThroughPath32->PassThrough.DataBufferOffset;
    MpioPassThroughPath64->PassThrough.SenseInfoOffset = MpioPassThroughPath32->PassThrough.SenseInfoOffset;

    return;
}


VOID
DsmpPassThroughPathTranslate64To32(
    _In_ IN PMPIO_PASS_THROUGH_PATH MpioPassThroughPath64,
    _Inout_ IN OUT PMPIO_PASS_THROUGH_PATH32 MpioPassThroughPath32
    )
/*++

Routine Description:

    On WIN64, the SCSI_PASS_THROUGH field of MPIO_PASS_THROUGH_PATH structure
    sent down by a 32-bit application must be marshaled into a 64-bit version
    of the structure.  This function marshals a 64-bit version of the structure
    back into a 32-bit version.

Arguments:

    MpioPassThroughPath64 - Supplies a pointer to a 64-bit MPIO_PASS_THROUGH_PATH
                            struct.

    MpioPassThroughPath32 - Supplies the address of a pointer to a 32-bit
                            MPIO_PASS_THROUGH_PATH structure, into which we'll
                            copy the marshaled 64-bit data.

Return Value:

    None.

--*/
{
    //
    // Copy back the fields through the data offsets.
    //
    RtlCopyMemory(MpioPassThroughPath32,
                  MpioPassThroughPath64,
                  FIELD_OFFSET(SCSI_PASS_THROUGH, DataBufferOffset));


    //
    // Copy over the CDB.
    //
    RtlCopyMemory(MpioPassThroughPath32->PassThrough.Cdb,
                  MpioPassThroughPath64->PassThrough.Cdb,
                  16 * sizeof(UCHAR)
                  );

    //
    // Copy over the rest of the fields of the structure.
    //
    MpioPassThroughPath32->Version = MpioPassThroughPath64->Version;
    MpioPassThroughPath32->Length = MpioPassThroughPath64->Length;
    MpioPassThroughPath32->Flags = MpioPassThroughPath64->Flags;
    MpioPassThroughPath32->PortNumber = MpioPassThroughPath64->PortNumber;
    MpioPassThroughPath32->MpioPathId = MpioPassThroughPath64->MpioPathId;

    return;
}
#endif


NTSTATUS
DsmpGetMaxPRRetryTime(
    _In_ IN PDSM_CONTEXT Context,
    _Out_ OUT PULONG RetryTime
    )
/*++

Routine Description:

    This routine is used to get the max time period for which a PR request failing
    with a retry-able unit attention should be retried before failing back to MSCS.
    The value is determined by querying the value found at
    "msdsm\Parameters\DsmMaximumStateTransitionTime"

Arguments:

    Context - The DSM Context value.
    RetryTime - The output parameter that will receive the value to be used.

Return Value:

    Status of the RtlQueryRegistryValues call.

--*/
{
    RTL_QUERY_REGISTRY_TABLE queryTable[2];
    WCHAR registryKeyName[56] = {0};
    NTSTATUS status;


    NT_ASSERT(RetryTime);
    *RetryTime = DSM_MAX_PR_UNIT_ATTENTION_RETRY_TIME;

    RtlZeroMemory(queryTable, sizeof(queryTable));

    //
    // Build the key value name that we want as the base of the query.
    //
    RtlStringCbPrintfW(registryKeyName,
                       sizeof(registryKeyName),
                       DSM_PARAMETER_PATH_W);

    //
    // The query table has two entries. One for the state transition time and
    // the second which is the 'NULL' terminator.
    //
    queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK;
    queryTable[0].Name = DSM_MAX_STATE_TRANSITION_TIME_VALUE_NAME;
    queryTable[0].EntryContext = RetryTime;
    queryTable[0].DefaultType  = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;

    status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES,
                                    registryKeyName,
                                    queryTable,
                                    registryKeyName,
                                    NULL);


    return status;
}


NTSTATUS
DsmpQueryCacheInformationFromRegistry(
    _In_ IN PDSM_CONTEXT DsmContext,
    _Out_ OUT PBOOLEAN UseCacheForLeastBlocks,
    _Out_ OUT PULONGLONG CacheSizeForLeastBlocks
    )
/*++

Routine Description:

    This routine is used to get the information about whether sequential IO
    should use the same path when employing Least Blocks policy.
    It also queries the size of cache set by the administrator.
    The value is determined by querying the value found at
    "msdsm\Parameters\DsmUseCacheForLeastBlocks" and
    "msdsm\Parameters\DsmCacheSizeForLeastBlocks"

Arguments:

    Context - The DSM Context value.
    UseCacheForLeastBlocks - Returns the flag that indicates whether or not to
                                use same path for sequential IO when LB policy
                                is Least Blocks.
    CacheSizeForLeastBlocks - Returns the size of the cache (in bytes) set by
                                the Admin to indicate the amount of sequential
                                data that should be use the same path when LB
                                policy is Least Blocks.

Return Value:

    Status of the RtlQueryRegistryValues call.

--*/
{
    RTL_QUERY_REGISTRY_TABLE queryTable[2] = {0};
    WCHAR registryKeyName[56] = {0};
    HANDLE parametersKey = NULL;
    UNICODE_STRING keyValueName;
    NTSTATUS status;
    struct _cacheSizeForLeastBlocks {
        KEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
        ULONGLONG Data;
    } cacheSizeForLeastBlocks;
    ULONG length = 0;
    BOOLEAN useCacheForLeastBlocksDefault = FALSE;


    NT_ASSERT(UseCacheForLeastBlocks);
    NT_ASSERT(CacheSizeForLeastBlocks);

    RtlZeroMemory(queryTable, sizeof(queryTable));

    //
    // Build the key value name that we want as the base of the query.
    //
    RtlStringCbPrintfW(registryKeyName,
                       sizeof(registryKeyName),
                       DSM_PARAMETER_PATH_W);

    //
    // The query table has two entries. One for whether to use cache, and
    // and the second which is the 'NULL' terminator.
    //
    queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK;
    queryTable[0].Name = DSM_USE_CACHE_FOR_LEAST_BLOCKS;
    queryTable[0].EntryContext = UseCacheForLeastBlocks;
    queryTable[0].DefaultType  = (REG_BINARY << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_BINARY;
    queryTable[0].DefaultLength = sizeof(BOOLEAN);
    queryTable[0].DefaultData = &useCacheForLeastBlocksDefault;

    status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES,
                                    registryKeyName,
                                    queryTable,
                                    registryKeyName,
                                    NULL);

    if (NT_SUCCESS(status)) {

        status = DsmpOpenDsmServicesParametersKey(KEY_QUERY_VALUE, &parametersKey);

        if (NT_SUCCESS(status)) {

            RtlInitUnicodeString(&keyValueName, DSM_CACHE_SIZE_FOR_LEAST_BLOCKS);

            status = ZwQueryValueKey(parametersKey,
                                     &keyValueName,
                                     KeyValuePartialInformation,
                                     &cacheSizeForLeastBlocks,
                                     sizeof(cacheSizeForLeastBlocks),
                                     &length);

            if (NT_SUCCESS(status)) {

                NT_ASSERT(cacheSizeForLeastBlocks.KeyValueInfo.DataLength == sizeof(ULONGLONG));
                *CacheSizeForLeastBlocks = *((ULONGLONG UNALIGNED *)&(cacheSizeForLeastBlocks.KeyValueInfo.Data));
            }
        }

        if (parametersKey) {
            ZwClose(parametersKey);
        }
    }

    return status;
}

BOOLEAN
DsmpConvertSharedSpinLockToExclusive(
    _Inout_ _Requires_lock_held_(*_Curr_) PEX_SPIN_LOCK SpinLock
    )
/*++

Routine Description:

    This routine is a wrapper around ExTryConvertSharedSpinLockExclusive() that
    guarantees the given EX_SPIN_LOCK will be acquired in Exclusive mode once
    this function returns.

    It's possible the lock may be released and re-acquired within this function
    so the caller should be very careful about the use of this function.

    N.B. The caller MUST have acquired the given lock in Shared mode before
    calling this function.

Arguments:

    SpinLock - The EX_SPIN_LOCK to convert from Shared to Exclusive mode.

Return Value:

    Status of the ExTryConvertSharedSpinLockExclusive() call.  This function
    will always return with the lock acquired in Exclusive mode.  The FALSE is
    returned, then the lock had to be released and re-acquired.

--*/
{
    BOOLEAN converted = FALSE;

    converted = (BOOLEAN)ExTryConvertSharedSpinLockExclusive(SpinLock);

    //
    // If the conversion attempt failed, then we should release the lock from
    // Shared mode and try to pick it back up in Exclusive mode to guarantee
    // this function will always return with the lock in Exclusive mode.
    //
    if (converted == FALSE) {
        ExReleaseSpinLockSharedFromDpcLevel(SpinLock);
        ExAcquireSpinLockExclusiveAtDpcLevel(SpinLock);
    }

    return converted;
}

CHAR  hex_asc[] = "0123456789abcdef";
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]

INT32 hex_dump_to_buffer(PVOID buf, INT32 len, INT32 rowsize, INT32 groupsize,
	PCHAR linebuf, INT32 linebuflen, BOOLEAN ascii)
{
	const PUINT8 ptr = (PUINT8)buf;
	INT32 ngroups = 0;;
	UINT8 ch;
	INT32 j, lx = 0;
	INT32 ascii_column = 0;
	INT32 ret = 0;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	if (len > rowsize)		/* limit to one line at a time */
		len = rowsize;

	if ((len % groupsize) != 0)	/* no mixed size output */
		groupsize = 1;

	ngroups = len / groupsize;
	ascii_column = rowsize * 2 + rowsize / groupsize + 1;

	if (!linebuflen)
		goto overflow1;

	if (!len)
		goto nil;

	if (groupsize == 8) {
		PUINT64 ptr8 = (PUINT64)buf;

		for (j = 0; j < ngroups; j++) {
			ret = RtlStringCbPrintfA(linebuf + lx, linebuflen - lx,
				"%s%16.16llx", j ? " " : "",
				(PUINT64)(ptr8 + j));
			if (ret >= linebuflen - lx)
				goto overflow1;
			lx += ret;
		}

	}
	else if (groupsize == 4) {
		PUINT32 ptr4 = (PUINT32)buf;

		for (j = 0; j < ngroups; j++) {
			ret = RtlStringCbPrintfA(linebuf + lx, linebuflen - lx,
				"%s%8.8x", j ? " " : "",
				(PUINT32)(ptr4 + j));
			if (ret >= linebuflen - lx)
				goto overflow1;
			lx += ret;
		}
	}
	else if (groupsize == 2) {
		PUINT16 ptr2 = (PUINT16)buf;

		for (j = 0; j < ngroups; j++) {
			ret = RtlStringCbPrintfA(linebuf + lx, linebuflen - lx,
				"%s%4.4x", j ? " " : "",
				(PUINT16)(ptr2 + j));
			if (ret >= linebuflen - lx)
				goto overflow1;
			lx += ret;
		}
	}
	else {
		for (j = 0; j < len; j++) {
			if (linebuflen < lx + 2)
				goto overflow2;
			ch = ptr[j];
			linebuf[lx++] = hex_asc_hi(ch);
			if (linebuflen < lx + 2)
				goto overflow2;
			linebuf[lx++] = hex_asc_lo(ch);
			if (linebuflen < lx + 2)
				goto overflow2;
			linebuf[lx++] = ' ';
		}
		if (j)
			lx--;
	}
	if (!ascii)
		goto nil;

	while (lx < ascii_column) {
		if (linebuflen < lx + 2)
			goto overflow2;
		linebuf[lx++] = ' ';
	}
	for (j = 0; j < len; j++) {
		if (linebuflen < lx + 2)
			goto overflow2;
		ch = ptr[j];
		linebuf[lx++] = ch;
	}
nil:
	linebuf[lx] = '\0';
	return lx;
overflow2:
	linebuf[lx++] = '\0';
overflow1:

	return ascii ? ascii_column + len : (groupsize * 2 + 1) * ngroups - 1;
}

void TracePrintHexDump(PVOID pBuffer, INT32 BufferLen)
{
	PUINT8 ptr = (PUINT8)pBuffer;
	INT32 i, linelen, remaining = BufferLen;
	CHAR linebuf[32 * 3 + 2 + 32 + 1];
	INT32 rowsize = 32;
	INT32 groupsize = 1;
	BOOLEAN ascii = TRUE;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < BufferLen; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer((PVOID)(ptr + i), linelen, rowsize, groupsize,
			linebuf, (INT32)sizeof(linebuf), ascii);

		TracePrintEx("%08x: %s\n", i, linebuf);
	}
}

