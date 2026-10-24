package de.darkatra.injector

// https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode
// 0x3c into the dll - RVA of PE signature
internal const val OFFSET_TO_PE_SIGNATURE_POINTER = 0x3c

// RVA of Export Table
internal const val EXPORT_TABLE_FROM_SIGNATURE_32 = 0x78
internal const val EXPORT_TABLE_FROM_SIGNATURE_64 = 0x88

// Magic of the optional header - tells PE32 and PE32+ apart
internal const val OPTIONAL_HEADER_MAGIC_FROM_SIGNATURE = 0x18
internal const val OPTIONAL_HEADER_MAGIC_32: Short = 0x10b
internal const val OPTIONAL_HEADER_MAGIC_64: Short = 0x20b

// Size of the image in memory
internal const val SIZE_OF_IMAGE_FROM_SIGNATURE = 0x50

// RVA and size of Import Table
internal const val IMPORT_TABLE_FROM_SIGNATURE_32 = 0x80
internal const val IMPORT_TABLE_FROM_SIGNATURE_64 = 0x90

// RVA and size of Bound Import Table
internal const val BOUND_IMPORT_TABLE_FROM_SIGNATURE_32 = 0xd0
internal const val BOUND_IMPORT_TABLE_FROM_SIGNATURE_64 = 0xe0

// RVA and size of Import Address Table
internal const val IAT_TABLE_FROM_SIGNATURE_32 = 0xd8
internal const val IAT_TABLE_FROM_SIGNATURE_64 = 0xe8

// Number of function names exported by a module
internal const val NUMBER_OF_EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE = 0x18

// RVA of Address Table - addresses of exported functions
internal const val EXPORTED_FUNCTION_ADDRESSES_FROM_EXPORT_TABLE = 0x1c

// RVA of Name Pointer Table - addresses of exported function names
internal const val EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE = 0x20

// RVA of Ordinal Table - function order number as listed in the table
internal const val EXPORTED_FUNCTION_ORDINALS_FROM_EXPORT_TABLE = 0x24
