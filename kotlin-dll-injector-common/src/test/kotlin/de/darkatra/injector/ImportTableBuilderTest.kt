package de.darkatra.injector

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ImportTableBuilderTest {

    @Test
    fun `builds a 32-bit import table with the injected dll first`() {

        val originalDescriptor = ByteArray(ImportTableBuilder.IMPORT_DESCRIPTOR_SIZE) { (it + 1).toByte() }

        val result = ImportTableBuilder.build(
            imageBaseAddress = 0x00400000,
            allocationAddress = 0x00800000,
            architecture = ProcessArchitecture.X_86,
            dllPath = "C:\\patches\\game-patcher.dll",
            originalDescriptors = listOf(originalDescriptor)
        )

        val buffer = ByteBuffer.wrap(result.bytes).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(result.importLookupTableRva, buffer.getInt(0))
        assertEquals(result.dllPathRva, buffer.getInt(12))
        assertEquals(result.importAddressTableRva, buffer.getInt(16))
        assertContentEquals(originalDescriptor, result.bytes.copyOfRange(20, 40))
        assertContentEquals(ByteArray(20), result.bytes.copyOfRange(40, 60))
        assertEquals(0x80000001.toInt(), buffer.getInt(result.importLookupTableOffset))
        assertEquals(0, buffer.getInt(result.importLookupTableOffset + Int.SIZE_BYTES))
        assertEquals(0x80000001.toInt(), buffer.getInt(result.importAddressTableOffset))
        assertEquals(0, buffer.getInt(result.importAddressTableOffset + Int.SIZE_BYTES))
        assertEquals(60, result.importDirectorySize)
    }

    @Test
    fun `uses a 64-bit ordinal thunk for a 64-bit image`() {

        val result = ImportTableBuilder.build(
            imageBaseAddress = 0x0000000140000000,
            allocationAddress = 0x0000000141000000,
            architecture = ProcessArchitecture.X_64,
            dllPath = "C:\\patch.dll",
            originalDescriptors = emptyList()
        )

        val buffer = ByteBuffer.wrap(result.bytes).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(0x8000000000000001uL.toLong(), buffer.getLong(result.importLookupTableOffset))
        assertEquals(0, buffer.getLong(result.importLookupTableOffset + Long.SIZE_BYTES))
        assertEquals(0x8000000000000001uL.toLong(), buffer.getLong(result.importAddressTableOffset))
        assertEquals(0, buffer.getLong(result.importAddressTableOffset + Long.SIZE_BYTES))
    }

    @Test
    fun `rejects an allocation that cannot be represented by an RVA`() {

        assertFailsWith<InjectionException> {
            ImportTableBuilder.build(
                imageBaseAddress = 0x0000000140000000,
                allocationAddress = 0x0000000240000000,
                architecture = ProcessArchitecture.X_64,
                dllPath = "C:\\patch.dll",
                originalDescriptors = emptyList()
            )
        }
    }
}
