package de.darkatra.injector

import java.nio.CharBuffer
import java.nio.charset.Charset
import java.nio.charset.CodingErrorAction

internal object AnsiEncoding {

    private val charset: Charset by lazy {
        System.getProperty("sun.jnu.encoding")
            ?.let(Charset::forName)
            ?: Charset.defaultCharset()
    }

    private val encoder = charset.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)

    fun encodePath(path: String): ByteArray {

        if (path.contains('\u0000')) {
            throw InjectionException("The DLL path must not contain a null character.")
        }

        try {
            val encoded = encoder.encode(CharBuffer.wrap(path))
            return ByteArray(encoded.remaining()).also(encoded::get)
        } catch (e: CharacterCodingException) {
            throw InjectionException("The DLL path '$path' cannot be represented in the system ANSI code page (${charset.name()}).", e)
        }
    }
}
