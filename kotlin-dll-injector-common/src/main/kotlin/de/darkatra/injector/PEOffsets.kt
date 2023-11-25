package de.darkatra.injector

// https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode
// 0x3c into the dll - RVA of PE signature
internal const val OFFSET_TO_PE_SIGNATURE_POINTER = 0x3c

// RVA of Export Table
internal const val EXPORT_TABLE_FROM_SIGNATURE_32 = 0x78
internal const val EXPORT_TABLE_FROM_SIGNATURE_64 = 0x88

// Number of function names exported by a module
internal const val NUMBER_OF_EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE = 0x18

// RVA of Address Table - addresses of exported functions
internal const val EXPORTED_FUNCTION_ADDRESSES_FROM_EXPORT_TABLE = 0x1c

// RVA of Name Pointer Table - addresses of exported function names
internal const val EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE = 0x20

// RVA of Ordinal Table - function order number as listed in the table
internal const val EXPORTED_FUNCTION_ORDINALS_FROM_EXPORT_TABLE = 0x24
