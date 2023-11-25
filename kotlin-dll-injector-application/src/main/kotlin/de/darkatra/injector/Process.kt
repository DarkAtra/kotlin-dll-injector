package de.darkatra.injector

data class Process(
    val name: String,
    val pid: Long
) {

    override fun toString(): String {
        return name
    }
}
