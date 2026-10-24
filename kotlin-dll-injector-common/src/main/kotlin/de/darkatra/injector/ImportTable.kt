package de.darkatra.injector

internal class ImportTable(
    val bytes: ByteArray,
    val importDirectoryRva: Int,
    val importDirectorySize: Int,
    val importLookupTableOffset: Int,
    val importLookupTableRva: Int,
    val importAddressTableOffset: Int,
    val importAddressTableRva: Int,
    val dllPathOffset: Int,
    val dllPathRva: Int
)
