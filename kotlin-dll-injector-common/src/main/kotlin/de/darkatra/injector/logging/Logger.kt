package de.darkatra.injector.logging

interface Logger {

    fun trace(message: String, throwable: Throwable? = null) = log(LogLevel.TRACE, message, throwable)

    fun info(message: String, throwable: Throwable? = null) = log(LogLevel.INFO, message, throwable)

    fun warn(message: String, throwable: Throwable? = null) = log(LogLevel.WARN, message, throwable)

    fun log(level: LogLevel, message: String, throwable: Throwable? = null)
}
