#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#define CBC 1
#define AES256 1
#include "aes.h"

#define FILE_BUFFER_SIZE 4096  // Размер буфера для файловых операций
#define AES_BLOCK_SIZE 16       // Размер блока AES (128 бит)

// Теги пула памяти для отслеживания выделений
#define MY_CONTEXT_TAG 'xtCM'          // Контекст операции записи
#define MY_BUFFER_TAG  'fuBM'          // Буфер для модифицированной записи
#define MY_READ_TEMP_BUFFER_TAG 'buRT' // Временный буфер для чтения

// Статический ключ AES-256 (32 байта)
// В производственной системе ключ должен быть защищен и управляться отдельно

const uint8_t aes_key[32] = {
    0x22, 0x4e, 0x11, 0x28, 0x32, 0xb5, 0xca, 0xc1,
    0x90, 0x70, 0xb1, 0xff, 0x59, 0xcd, 0x84, 0xdc,
    0x3b, 0x39, 0x0a, 0x36, 0x39, 0x3a, 0x90, 0xc4,
    0xcc, 0xfe, 0x15, 0x08, 0x82, 0x93, 0x12, 0xec
};

// Вектор инициализации для AES-CBC (16 байт)

const uint8_t aes_iv[16] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02
};



#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

// Структура контекста для передачи данных между pre-op и post-op WRITE
typedef struct _MY_WRITE_CONTEXT {
    PVOID NewBuffer;       // Указатель на выделенный нами буфер
    PMDL  NewMdl;          // Указатель на созданный нами MDL (если MdlAddress использовался)
    PMDL  OriginalMdl;     // Исходный MDL (для восстановления указателя в Data, если потребуется)
    // Хотя обычно Filter Manager сам корректно обрабатывает замену MDL
    PVOID OriginalWriteBuffer; // Исходный WriteBuffer (если он использовался)
    ULONG OriginalLength;    // Исходная длина данных
    ULONG NewLength;         // Новая длина данных после шифрования
    BOOLEAN MdlChanged;      // Флаг, указывающий, был ли заменен MDL
} MY_WRITE_CONTEXT, * PMY_WRITE_CONTEXT;

/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
PtInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
PtInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
PtInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
PtUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
PtInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
PtOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
PtDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

// Функции для шифрования и дешифрования буфера 
VOID EncryptBuffer(uint8_t* buffer, SIZE_T* length);
VOID DecryptBuffer(uint8_t* buffer, SIZE_T* length);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#pragma alloc_text(PAGE, PtInstanceQueryTeardown)
#pragma alloc_text(PAGE, PtInstanceSetup)
#pragma alloc_text(PAGE, PtInstanceTeardownStart)
#pragma alloc_text(PAGE, PtInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CLOSE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_READ,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_EA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_EA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SHUTDOWN,
      0,
      PtPreOperationNoPostOperationPassThrough,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CLEANUP,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_SECURITY,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_SECURITY,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_QUOTA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_QUOTA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_PNP,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_MDL_READ,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    PtUnload,                           //  MiniFilterUnload

    PtInstanceSetup,                    //  InstanceSetup
    PtInstanceQueryTeardown,            //  InstanceQueryTeardown
    PtInstanceTeardownStart,            //  InstanceTeardownStart
    PtInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
PtInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )

{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
PtInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
PtInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceTeardownStart: Entered\n") );
}


VOID
PtInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {


        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
PtUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}

VOID EncryptBuffer(uint8_t* buffer, SIZE_T* length) {
    SIZE_T originalLen = *length;
    SIZE_T padLen = AES_BLOCK_SIZE - (originalLen % AES_BLOCK_SIZE);
    if (padLen == 0 && originalLen == 0) { // Если исходная длина 0, паддинг будет равен блоку
        padLen = AES_BLOCK_SIZE;
    }
    else if (padLen == AES_BLOCK_SIZE && originalLen > 0) { // Если кратно, добавляем полный блок паддинга
        // Это стандарт PKCS#7 - если данные уже выровнены, добавляется полный блок паддинга
    }
    else if (originalLen % AES_BLOCK_SIZE == 0 && originalLen > 0) {
        padLen = AES_BLOCK_SIZE;
    }


    SIZE_T totalLen = originalLen + padLen;

    // Добавляем паддинг PKCS#7
    for (SIZE_T i = 0; i < padLen; ++i) {
        buffer[originalLen + i] = (uint8_t)padLen;
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, aes_iv); // Инициализируем контекст AES с ключом и вектором инициализации
    AES_CBC_encrypt_buffer(&ctx, buffer, (uint32_t)totalLen);    
    *length = totalLen;

    DbgPrint("EncryptBuffer: Original len: %lu, Padded len: %lu, Total encrypted len: %lu, Pad byte: 0x%x\n",
        (ULONG)originalLen, (ULONG)padLen, (ULONG)totalLen, (uint8_t)padLen);
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);

        if (NT_SUCCESS(status)) {
            
            status = FltParseFileNameInformation(nameInfo);
            if (NT_SUCCESS(status)) {

                // Проверяем, соответствует ли расширение файла требуемому
                const UNICODE_STRING required_extension = RTL_CONSTANT_STRING(L"testlabext");
                if (RtlEqualUnicodeString(&required_extension, &(nameInfo->Extension), FALSE)) {
                    DbgPrint("Lab2: PRE-WRITE - Extension '.testlabext' matched!\n");

                    PMY_WRITE_CONTEXT context = NULL;
                    PVOID originalDataBuffer = NULL;
                    ULONG originalLength = Data->Iopb->Parameters.Write.Length;
                    PMDL originalMdl = Data->Iopb->Parameters.Write.MdlAddress;
                    PVOID newAllocatedBuffer = NULL;
                    PMDL newMdl = NULL;
                    LARGE_INTEGER originalOffset = Data->Iopb->Parameters.Write.ByteOffset;

                    // Если длина записи равна 0, проверяем флаги IRP для предупреждения
                    if (originalLength == 0 && !(Data->Iopb->IrpFlags & IRP_PAGING_IO) && !(Data->Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO)) {
                        DbgPrint("Lab2: PRE-WRITE - Matched file with 0 length write at offset %I64d. Current Flags: 0x%x. Consider if modification is intended.\n", originalOffset.QuadPart, Data->Iopb->IrpFlags);

                    }


                    if (originalMdl) {
                        originalDataBuffer = MmGetSystemAddressForMdlSafe(originalMdl, NormalPagePriority);
                        DbgPrint("Lab2: PRE-WRITE - MDL path. originalDataBuffer: 0x%p\n", originalDataBuffer);
                    }
                    else {
                        originalDataBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
                        DbgPrint("Lab2: PRE-WRITE - WriteBuffer path. originalDataBuffer: 0x%p\n", originalDataBuffer);
                    }

                    // Проверяем, что originalDataBuffer не NULL для нулевой длины
                    if (!originalDataBuffer && originalLength > 0) {
                        DbgPrint("Lab2: PRE-WRITE - ERROR: Failed to get original data buffer pointer for non-zero length write (%lu bytes).\n", originalLength);
                    }
                    else {      // Вычисляем новый размер с учетом паддинга
                        SIZE_T padLen = AES_BLOCK_SIZE - (originalLength % AES_BLOCK_SIZE);
                        if (padLen == AES_BLOCK_SIZE && originalLength > 0) {
                            // Если длина данных кратна блоку AES, добавляем полный блок паддинга
                            padLen = AES_BLOCK_SIZE;
                        }
                        else if (originalLength == 0) {
                            // Для нулевой длины данных добавляем полный блок паддинга
                            padLen = AES_BLOCK_SIZE;
                        }
                        ULONG newLength = originalLength + (ULONG)padLen;

                        context = ExAllocatePoolZero(NonPagedPool, sizeof(MY_WRITE_CONTEXT), MY_CONTEXT_TAG);
                        if (!context) {
                            DbgPrint("Lab2: PRE-WRITE - ERROR: Failed to allocate MY_WRITE_CONTEXT.\n");
                        }
                        else {
                            newAllocatedBuffer = ExAllocatePoolZero(NonPagedPool, newLength, MY_BUFFER_TAG);
                            if (!newAllocatedBuffer) {
                                DbgPrint("Lab2: PRE-WRITE - ERROR: Failed to allocate new buffer (size %lu).\n", newLength);
                                ExFreePoolWithTag(context, MY_CONTEXT_TAG);
                                context = NULL;
                            }
                            else {
                                NTSTATUS copyStatus = STATUS_SUCCESS;
                                try {
                                    // Копируем исходные данные в новый буфер
                                    if (originalLength > 0 && originalDataBuffer) {
                                        RtlCopyMemory(newAllocatedBuffer, originalDataBuffer, originalLength);
                                    }
                                      // Шифруем новый буфер с добавлением паддинга
                                    SIZE_T encryptedLength = originalLength;
                                    EncryptBuffer((uint8_t*)newAllocatedBuffer, &encryptedLength);
                                    
                                    DbgPrint("Lab2: PRE-WRITE - Data encrypted. OrigLen: %lu -> EncryptedLen: %lu at 0x%p\n",
                                        originalLength, (ULONG)encryptedLength, newAllocatedBuffer);

                                } except(EXCEPTION_EXECUTE_HANDLER) {
                                    copyStatus = GetExceptionCode();
                                    DbgPrint("Lab2: PRE-WRITE - ERROR: Exception 0x%x during encryption.\n", copyStatus);
                                    ExFreePoolWithTag(newAllocatedBuffer, MY_BUFFER_TAG); newAllocatedBuffer = NULL;
                                    ExFreePoolWithTag(context, MY_CONTEXT_TAG); context = NULL;
                                }                                if (NT_SUCCESS(copyStatus) && context) {
                                    context->OriginalLength = originalLength;
                                    context->NewBuffer = newAllocatedBuffer;
                                    context->NewLength = newLength;

                                    if (originalMdl) {
                                        newMdl = IoAllocateMdl(newAllocatedBuffer, newLength, FALSE, FALSE, NULL);
                                        if (!newMdl) {
                                            DbgPrint("Lab2: PRE-WRITE - ERROR: Failed to allocate new MDL.\n");
                                            ExFreePoolWithTag(newAllocatedBuffer, MY_BUFFER_TAG); newAllocatedBuffer = NULL;
                                            ExFreePoolWithTag(context, MY_CONTEXT_TAG); context = NULL;
                                        }
                                        else {
                                            NTSTATUS lockStatus = STATUS_SUCCESS;
                                            try {
                                                MmProbeAndLockPages(newMdl, KernelMode, IoWriteAccess);
                                            } except(EXCEPTION_EXECUTE_HANDLER) {
                                                lockStatus = GetExceptionCode();
                                                DbgPrint("Lab2: PRE-WRITE - ERROR: Exception 0x%x MmProbeAndLockPages.\n", lockStatus);
                                                IoFreeMdl(newMdl); newMdl = NULL;
                                                ExFreePoolWithTag(newAllocatedBuffer, MY_BUFFER_TAG); newAllocatedBuffer = NULL;
                                                ExFreePoolWithTag(context, MY_CONTEXT_TAG); context = NULL;
                                            }
                                            if (NT_SUCCESS(lockStatus) && context) {
                                                Data->Iopb->Parameters.Write.MdlAddress = newMdl;
                                                context->MdlChanged = TRUE;
                                                context->OriginalMdl = originalMdl;
                                                context->NewMdl = newMdl;
                                            }
                                        }
                                    }
                                    else { // Если MDL не использовался, просто обновляем WriteBuffer
                                        Data->Iopb->Parameters.Write.WriteBuffer = newAllocatedBuffer;
                                        context->MdlChanged = FALSE;
                                        context->OriginalWriteBuffer = originalDataBuffer;
                                        context->NewMdl = NULL;
                                    }

                                    if (context) { 
                                        Data->Iopb->Parameters.Write.Length = newLength;
                                        *CompletionContext = context;
                                         
                                        // Указываем, что данные в Data изменены
                                        FltSetCallbackDataDirty(Data);
                                        DbgPrint("Lab2: PRE-WRITE - Encryption successful for write at Offset: %I64d. OrigLen: %lu -> EncryptedLen: %lu. CompletionContext SET.\n",
                                            originalOffset.QuadPart, originalLength, newLength);
                                    }
                                }
                            }
                        }
                    }
                }
            } // FltParseFileNameInformation OK

            if (nameInfo) {
                FltReleaseFileNameInformation(nameInfo); // Очищаем имя файла
            }
        } // FltGetFileNameInformation OK
    } // IRP_MJ_WRITE

    if (PtDoRequestOperationStatus(Data)) {
        status = FltRequestOperationStatusCallback(Data,
            PtOperationStatusCallback,
            (PVOID)(++OperationStatusCtx));
        if (!NT_SUCCESS(status)) {
            PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                ("PassThrough!PtPreOperationPassThrough: FltRequestOperationStatusCallback Failed, status=%08x\n",
                    status));
        }
    }
    return returnStatus;
}


VOID
PtOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("PassThrough!PtOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}

VOID DecryptBuffer(uint8_t* buffer, SIZE_T* length) {
    if (*length == 0 || (*length % AES_BLOCK_SIZE != 0)) {
        DbgPrint("DecryptBuffer: Invalid length for decryption: %lu\n", (ULONG)*length);
        // Возможно, стоит вернуть ошибку или не изменять длину
        return;
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, aes_iv); // Аналогично EncryptBuffer, IV должен соответствовать использованному при шифровании.
    AES_CBC_decrypt_buffer(&ctx, buffer, (uint32_t)(*length));

    // Удаляем паддинг PKCS#7
    // Важно: Проверять корректность значения паддинга
    uint8_t padLen = buffer[*length - 1];
    if (padLen > 0 && padLen <= AES_BLOCK_SIZE) {
        // Дополнительная проверка: все байты паддинга должны быть равны padLen
        BOOLEAN padding_ok = TRUE;
        for (SIZE_T i = 0; i < padLen; ++i) {
            if (buffer[*length - 1 - i] != padLen) {
                padding_ok = FALSE;
                break;
            }
        }        if (padding_ok) {
            // Очищаем область паддинга нулями перед уменьшением длины
            SIZE_T originalLength = *length;
            *length -= padLen;
            // Заполняем область паддинга нулями для предотвращения "мусорных" символов
            RtlZeroMemory(buffer + *length, padLen);
            DbgPrint("DecryptBuffer: Decrypted. Original encrypted len: %lu, PadLen: %u, Final len: %lu\n",
                (ULONG)originalLength, padLen, (ULONG)*length);
        }
        else {
            DbgPrint("DecryptBuffer: Invalid PKCS#7 padding detected.\n");
            // Ошибка паддинга. В реальном приложении это критическая ошибка.
            // Здесь мы можем просто не менять длину, чтобы не повредить данные дальше.
        }
    }
    else {
        DbgPrint("DecryptBuffer: Invalid pad length value: %u. Original length: %lu\n", padLen, (ULONG)*length);
        // Некорректное значение паддинга.
    }
}


FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{   UNREFERENCED_PARAMETER(FltObjects); 
    UNREFERENCED_PARAMETER(Flags);    
    
    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("PassThrough!PtPostOperationPassThrough: Entered. IRP_MJ_FUNCTION: 0x%x\n", Data->Iopb->MajorFunction));

    // Обработка контекста от PRE-WRITE
    if (Data->Iopb->MajorFunction == IRP_MJ_WRITE && CompletionContext != NULL) {
        PMY_WRITE_CONTEXT context = (PMY_WRITE_CONTEXT)CompletionContext;
        DbgPrint("Lab2: POST-WRITE - Cleaning up context for modified write. Status: 0x%x\n", Data->IoStatus.Status);

        if (context->MdlChanged && context->NewMdl) {
            MmUnlockPages(context->NewMdl); // Разблокируем страницы
            IoFreeMdl(context->NewMdl);     // Освобождаем MDL
            DbgPrint("Lab2: POST-WRITE - NewMdl unlocked and freed.\n");
        }
        // OriginalMdl и OriginalWriteBuffer были только для информации, мы не владеем ими.

        if (context->NewBuffer) {
            ExFreePoolWithTag(context->NewBuffer, MY_BUFFER_TAG); // Освобождаем наш буфер
            DbgPrint("Lab2: POST-WRITE - NewBuffer freed.\n");
        }

        ExFreePoolWithTag(context, MY_CONTEXT_TAG); // Освобождаем саму структуру контекста
        DbgPrint("Lab2: POST-WRITE - Context structure freed.\n");
        // После очистки, выходим. Дальнейшая обработка IRP_MJ_WRITE в post-op не нужна, если это был наш контекст.
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Остальная логика для других операций (например, READ или WRITE без нашего контекста)
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;

    // Получаем информацию о файле ТОЛЬКО если CompletionContext был NULL (т.е. это не наш обработанный WRITE)
    // или это не IRP_MJ_WRITE.
    // Для IRP_MJ_READ нам всегда нужно имя файла для проверки расширения.
    if (Data->Iopb->MajorFunction == IRP_MJ_READ || (Data->Iopb->MajorFunction == IRP_MJ_WRITE && CompletionContext == NULL)) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);
        if (!NT_SUCCESS(status)) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        status = FltParseFileNameInformation(nameInfo);
        if (!NT_SUCCESS(status)) {
            FltReleaseFileNameInformation(nameInfo);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        const UNICODE_STRING required_extension = RTL_CONSTANT_STRING(L"testlabext");
        if (RtlEqualUnicodeString(&required_extension, &(nameInfo->Extension), FALSE)) {
            DbgPrint("Lab2: POST-OP - Extension '.testlabext' matched for %s.\n",
                (Data->Iopb->MajorFunction == IRP_MJ_READ) ? "READ" : "unhandled WRITE");

            // Пользовательский код для IRP_MJ_WRITE (который был здесь ранее) был некорректен для post-operation.
            // Если CompletionContext был NULL для WRITE, значит, наша pre-op логика не сработала/не изменила его.
            // Такой WRITE здесь обрабатывать для модификации не нужно.
            // Просто выведем сообщение, если это такой случай.
            if (Data->Iopb->MajorFunction == IRP_MJ_WRITE && CompletionContext == NULL) {
                DbgPrint("Lab2: POST-WRITE - .testlabext file, but no CompletionContext. Write was not modified by pre-op.\n");
            }

            else if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
                DbgPrint("Lab2: POST-READ - Operation intercepted. Status: 0x%x, Bytes Read: %Iu\n",
                    Data->IoStatus.Status, Data->IoStatus.Information);

                if (NT_SUCCESS(Data->IoStatus.Status) && Data->IoStatus.Information > 0) {
                    PVOID targetBuffer = NULL;
                    ULONG bytesActuallyRead = (ULONG)Data->IoStatus.Information;
                    ULONG originalRequestedLength = Data->Iopb->Parameters.Read.Length;

                    // Получение указателя на буфер с данными (более безопасный способ)
                    if (Data->Iopb->Parameters.Read.MdlAddress != NULL) {
                        // Данные в MDL, нужно получить системный адрес
                        targetBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress, NormalPagePriority);
                    }
                    else if (Data->Flags & FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) {
                        // Данные в системном буфере (например, для Buffered I/O)
                        targetBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
                    }
                    else if (Data->Iopb->Parameters.Read.ReadBuffer != NULL) {
                        // Это может быть прямой пользовательский буфер (например, для NonCached I/O)
                        // Для простоты используем его, если другие варианты не подошли.
                        // Однако, для прямого пользовательского буфера может потребоваться отображение.
                        // В данном примере предполагаем, что он доступен.
                        targetBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
                    }                    if (!targetBuffer) {
                        DbgPrint("Lab2: POST-READ - Could not get target buffer pointer.\n");
                    }
                    else {
                        // Проверяем, что прочитанные данные выровнены по размеру блока AES
                        if (bytesActuallyRead % AES_BLOCK_SIZE == 0 && bytesActuallyRead > 0) {
                            // Выделяем временный буфер для расшифровки
                            // Используем PagedPool для временного буфера, так как это post-operation
                            PCHAR tempDecryptBuffer = ExAllocatePoolZero(PagedPool, bytesActuallyRead, MY_READ_TEMP_BUFFER_TAG);

                            if (tempDecryptBuffer) {
                                NTSTATUS decryptStatus = STATUS_SUCCESS;
                                try {
                                    // Копируем данные из целевого буфера во временный буфер
                                    // Это нужно, чтобы не изменять оригинальный буфер до успешной расшифровки
                                    RtlCopyMemory(tempDecryptBuffer, targetBuffer, bytesActuallyRead);
                                    
                                    // Расшифровываем данные 
                                    SIZE_T decryptedLength = bytesActuallyRead;
                                    DecryptBuffer((uint8_t*)tempDecryptBuffer, &decryptedLength);
                                      // Проверяем, что расшифрованная длина не превышает исходно запрошенную
                                    if (decryptedLength <= originalRequestedLength) {
                                        // Копируем расшифрованные данные обратно в целевой буфер
                                        RtlCopyMemory(targetBuffer, tempDecryptBuffer, decryptedLength);
                                        
                                        // Если расшифрованная длина меньше, чем фактически прочитано, очищаем оставшуюся часть буфера
                                        if (decryptedLength < bytesActuallyRead) {
                                            RtlZeroMemory((PUCHAR)targetBuffer + decryptedLength, bytesActuallyRead - decryptedLength);
                                        }
                                        
                                        Data->IoStatus.Information = decryptedLength; // Обновляем информацию о количестве прочитанных байт
                                        // Отмечаем, что данные в Data изменены
                                        FltSetCallbackDataDirty(Data);
                                        
                                        DbgPrint("Lab2: POST-READ - Data decrypted. EncryptedLen: %lu -> DecryptedLen: %lu, cleared %lu bytes\n", 
                                            bytesActuallyRead, (ULONG)decryptedLength, bytesActuallyRead - (ULONG)decryptedLength);
                                    }
                                    else {
                                        DbgPrint("Lab2: POST-READ - Decrypted data too large for buffer (decrypted %lu > available %lu)\n",
                                            (ULONG)decryptedLength, originalRequestedLength);
                                    }
                                    
                                } except(EXCEPTION_EXECUTE_HANDLER) {
                                    decryptStatus = GetExceptionCode();
                                    DbgPrint("Lab2: POST-READ - Exception 0x%x during decryption.\n", decryptStatus);
                                }
                                ExFreePoolWithTag(tempDecryptBuffer, MY_READ_TEMP_BUFFER_TAG);
                            }
                            else {
                                DbgPrint("Lab2: POST-READ - Failed to allocate tempDecryptBuffer.\n");
                            }
                        }
                        else {
                            DbgPrint("Lab2: POST-READ - Read data length (%lu) not aligned to AES block size (%d) or zero length. Skipping decryption.\n",
                                bytesActuallyRead, AES_BLOCK_SIZE);
                        }
                    }
                }
                else {
                    DbgPrint("Lab2: POST-READ - Read operation not successful or 0 bytes read. Status: 0x%x, Bytes: %Iu\n",
                        Data->IoStatus.Status, Data->IoStatus.Information);
                }
            } // Конец if (IRP_MJ_READ)
        } // Конец if (RtlEqualUnicodeString...

        if (nameInfo) { // Освобождаем nameInfo если было выделено
            FltReleaseFileNameInformation(nameInfo);
        }
    } // Конец if (нужно было получать nameInfo)

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtPreOperationNoPostOperationPassThrough: Entered\n") );

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
PtDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    return (BOOLEAN)
             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

