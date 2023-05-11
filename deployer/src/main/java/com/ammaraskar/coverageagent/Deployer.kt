package com.ammaraskar.coverageagent

import java.io.File
import java.util.*
import java.util.concurrent.TimeUnit

class Deployer {

    private val soName = "libcoverage_instrumenting_agent.so"

    fun deploy(packageName: String, adbDeviceName: String?) {
        println("Instrumenting app $packageName with coverage agent.")
        // Get the architecture of the device.
        val architecture = getDeviceArchitecture(adbDeviceName)
        println("[i] device architecture=${architecture}")


        val library = File("runtime_cpp/build/intermediates/merged_native_libs/debug/out/lib/${architecture}/${soName}")
        println("[i] Using library: ${library.absolutePath}")

        runAdbCommand(adbDeviceName, "push", library.absolutePath, "/data/local/tmp/")
        println("[+] Pushed library to /data/local/tmp/${soName}")

        println("[i] Trying to use run-as to copy to startup_agents")
        val copyDestinationWithRunAs = tryToCopyLibraryWithRunAs(packageName, adbDeviceName)
        if (copyDestinationWithRunAs.isPresent) {
            println("[+] Library copied to ${copyDestinationWithRunAs.get()}")
            return
        }

        println("[x] run-as failed, using su permissions instead.")

        // Use dumpsys package to figure out the data directory and user id of the application.
        val dumpSysOutput = runAdbCommand(adbDeviceName, "shell", "dumpsys", "package", packageName)

        var dataDir: String? = null
        var userId: String? = null
        for (line in dumpSysOutput.lines()) {
            if (line.contains("dataDir=")) dataDir = line.split("=")[1].trim()
            if (line.contains("userId=")) userId = line.split("=")[1].trim()
        }

        if (dataDir == null || userId == null) {
            println("[!] UNABLE to find app's dataDir or userId. (dataDir=$dataDir, userId=$userId)")
            return
        }
        println("[i] Grabbed app's dataDir=$dataDir and userId=$userId")

        runAdbCommand(adbDeviceName,
                "shell", "su", userId, "\"mkdir -p $dataDir/code_cache/startup_agents/\"")
        runAdbCommand(adbDeviceName,
                "shell", "su", userId, "\"cp /data/local/tmp/${soName} $dataDir/code_cache/startup_agents/\"")
        println("[+] Library copied to $dataDir/code_cache/startup_agents/")
    }

    private fun getDeviceArchitecture(adbDeviceName: String?): String {
        return runAdbCommand(adbDeviceName, "shell", "getprop", "ro.product.cpu.abi").trim()
    }

    private fun tryToCopyLibraryWithRunAs(packageName: String, adbDeviceName: String?): Optional<String> {
        return try {
            runAdbCommand(adbDeviceName, "shell", "run-as", packageName, "mkdir -p code_cache/startup_agents/")
            runAdbCommand(adbDeviceName, "shell", "run-as", packageName, "cp /data/local/tmp/${soName} code_cache/startup_agents/")

            Optional.of(runAdbCommand(adbDeviceName, "shell", "run-as", packageName, "pwd"))
        } catch (e: RuntimeException) {
            Optional.empty()
        }
    }

    private fun runAdbCommand(adbDeviceName: String?, vararg command: String): String {
        val adbCommand = mutableListOf("adb")
        if (adbDeviceName != null) {
            adbCommand.add("-s")
            adbCommand.add(adbDeviceName)
        }
        adbCommand.addAll(command)
        return runCommandAndGetOutput(adbCommand)
    }

    private fun runCommandAndGetOutput(command: List<String>): String {
        println("> ${command.joinToString(" ")}")
        val proc = ProcessBuilder(command)
                .redirectError(ProcessBuilder.Redirect.PIPE)
                .redirectOutput(ProcessBuilder.Redirect.PIPE)
                .start()

        val output = proc.inputStream.bufferedReader().readText()
        proc.waitFor(20, TimeUnit.SECONDS)

        if (proc.exitValue() != 0) {
            print(output)
            print(proc.errorStream.bufferedReader().readText())
            throw RuntimeException("${command.joinToString(" ")} returned exit code ${proc.exitValue()}")
        }
        return output
    }

}

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: Deployer <android-package-name> [adb-device-name]")
        return
    }

    Deployer().deploy(packageName = args[0], adbDeviceName = args.getOrNull(1))
}
