package de.darkatra.injector

// https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode
// 0x3c into the dll - RVA of PE signature
internal const val OFFSET_TO_PE_SIGNATURE_POINTER = 0x3c

internal enum class PEOffset(
    private val offset32: Int,
    private val offset64: Int
) {

    // RVA of Export Table
    EXPORT_TABLE_FROM_SIGNATURE(0x78, 0x88),

    // Number of function names exported by a module
    NUMBER_OF_EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE(0x18, 0x18),

    // RVA of Address Table - addresses of exported functions
    EXPORTED_FUNCTION_ADDRESSES_FROM_EXPORT_TABLE(0x1c, 0x1c),

    // RVA of Name Pointer Table - addresses of exported function names
    EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE(0x20, 0x20),

    // RVA of Ordinal Table - function order number as listed in the table
    EXPORTED_FUNCTION_ORDINALS_FROM_EXPORT_TABLE(0x24, 0x24);

    fun getOffset(processArchitecture: ProcessArchitecture): Int {
        return when (processArchitecture) {
            ProcessArchitecture.X_86 -> offset32
            ProcessArchitecture.X_64 -> offset64
        }
    }
}
