package de.darkatra.injector.logging

class NoopLogger : Logger {

    override fun log(level: LogLevel, message: String, throwable: Throwable?) {
        // noop
    }
}
