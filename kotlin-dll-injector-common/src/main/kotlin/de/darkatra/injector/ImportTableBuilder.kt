package de.darkatra.injector

import java.nio.ByteBuffer
import java.nio.ByteOrder

internal object ImportTableBuilder {

    internal const val IMPORT_DESCRIPTOR_SIZE = 20

    fun requiredSize(architecture: ProcessArchitecture, dllPath: String, originalDescriptorCount: Int): Int {

        val thunkSize = when (architecture) {
            ProcessArchitecture.X_86 -> Int.SIZE_BYTES
            ProcessArchitecture.X_64 -> Long.SIZE_BYTES
        }
        val descriptorBytes = (originalDescriptorCount + 2) * IMPORT_DESCRIPTOR_SIZE
        val importLookupTableOffset = align(descriptorBytes, thunkSize)
        val importAddressTableOffset = importLookupTableOffset + (2 * thunkSize)
        val dllPathOffset = importAddressTableOffset + (2 * thunkSize)
        return dllPathOffset + AnsiEncoding.encodePath(dllPath).size + 1
    }

    fun build(
        imageBaseAddress: Long,
        allocationAddress: Long,
        architecture: ProcessArchitecture,
        dllPath: String,
        originalDescriptors: List<ByteArray>
    ): ImportTable {

        if (originalDescriptors.any { it.size != IMPORT_DESCRIPTOR_SIZE }) {
            throw InjectionException("Every import descriptor must be $IMPORT_DESCRIPTOR_SIZE bytes.")
        }

        val thunkSize = when (architecture) {
            ProcessArchitecture.X_86 -> Int.SIZE_BYTES
            ProcessArchitecture.X_64 -> Long.SIZE_BYTES
        }
        val descriptorBytes = (originalDescriptors.size + 2) * IMPORT_DESCRIPTOR_SIZE
        val importLookupTableOffset = align(descriptorBytes, thunkSize)
        val importAddressTableOffset = importLookupTableOffset + (2 * thunkSize)
        val dllPathOffset = importAddressTableOffset + (2 * thunkSize)
        val dllPathBytes = AnsiEncoding.encodePath(dllPath)
        val bytes = ByteArray(dllPathOffset + dllPathBytes.size + 1)
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        val importLookupTableRva = toRva(imageBaseAddress, allocationAddress + importLookupTableOffset)
        val importAddressTableRva = toRva(imageBaseAddress, allocationAddress + importAddressTableOffset)
        val dllPathRva = toRva(imageBaseAddress, allocationAddress + dllPathOffset)

        buffer.putInt(0, importLookupTableRva)
        buffer.putInt(12, dllPathRva)
        buffer.putInt(16, importAddressTableRva)

        originalDescriptors.forEachIndexed { index, descriptor ->
            val offset = (index + 1) * IMPORT_DESCRIPTOR_SIZE
            descriptor.copyInto(bytes, offset)
        }

        when (architecture) {
            ProcessArchitecture.X_86 -> {
                buffer.putInt(importLookupTableOffset, 0x80000001.toInt())
                buffer.putInt(importAddressTableOffset, 0x80000001.toInt())
            }

            ProcessArchitecture.X_64 -> {
                buffer.putLong(importLookupTableOffset, 0x8000000000000001uL.toLong())
                buffer.putLong(importAddressTableOffset, 0x8000000000000001uL.toLong())
            }
        }

        dllPathBytes.copyInto(bytes, dllPathOffset)

        return ImportTable(
            bytes = bytes,
            importDirectoryRva = toRva(imageBaseAddress, allocationAddress),
            importDirectorySize = descriptorBytes,
            importLookupTableOffset = importLookupTableOffset,
            importLookupTableRva = importLookupTableRva,
            importAddressTableOffset = importAddressTableOffset,
            importAddressTableRva = importAddressTableRva,
            dllPathOffset = dllPathOffset,
            dllPathRva = dllPathRva
        )
    }

    private fun align(value: Int, alignment: Int): Int {

        return (value + alignment - 1) and -alignment
    }

    private fun toRva(imageBaseAddress: Long, address: Long): Int {

        val rva = address - imageBaseAddress
        if (rva !in 0..UInt.MAX_VALUE.toLong()) {
            throw InjectionException("Address 0x${address.toString(16)} cannot be represented as an RVA from image base 0x${imageBaseAddress.toString(16)}.")
        }
        return rva.toInt()
    }
}
