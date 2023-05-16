package com.ammaraskar.coverageagent

import java.io.File
import java.util.*
import java.util.concurrent.TimeUnit

class Deployer(private val adbDeviceName: String?) {

    private val soName = "libcoverage_instrumenting_agent.so"

    fun deploy(packageName: String) {
        println("Instrumenting app $packageName with coverage agent.")
        // Get the architecture of the device.
        val architecture = getDeviceArchitecture(adbDeviceName)
        println("[i] device architecture=${architecture}")


        val library = File("runtime_cpp/build/intermediates/merged_native_libs/debug/out/lib/${architecture}/${soName}")
        println("[i] Using library: ${library.absolutePath}")

        runAdbCommand("push", library.absolutePath, "/data/local/tmp/")
        println("[+] Pushed library to /data/local/tmp/${soName}")

        println("[i] Trying to use run-as to copy to startup_agents")
        val copyDestinationWithRunAs = tryToCopyLibraryWithRunAs(packageName)
        if (copyDestinationWithRunAs.isPresent) {
            println("[+] Library copied to ${copyDestinationWithRunAs.get()}")
            return
        }

        println("[x] run-as failed, using su permissions instead.")

        // Use dumpsys package to figure out the data directory and user id of the application.
        val dumpSysOutput = runAdbCommand("shell", "dumpsys", "package", packageName)

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

        runAdbCommand(
                "shell", "su", userId, "\"mkdir -p $dataDir/code_cache/startup_agents/\"")
        runAdbCommand(
                "shell", "su", userId, "\"cp /data/local/tmp/${soName} $dataDir/code_cache/startup_agents/\"")
        println("[+] Library copied to $dataDir/code_cache/startup_agents/")
    }

    private fun getDeviceArchitecture(adbDeviceName: String?): String {
        return runAdbCommand("shell", "getprop", "ro.product.cpu.abi").trim()
    }

    private fun tryToCopyLibraryWithRunAs(packageName: String): Optional<String> {
        return try {
            runAdbCommand("shell", "run-as", packageName, "mkdir -p code_cache/startup_agents/")
            runAdbCommand("shell", "run-as", packageName, "cp /data/local/tmp/${soName} code_cache/startup_agents/")

            Optional.of(runAdbCommand("shell", "run-as", packageName, "pwd"))
        } catch (e: RuntimeException) {
            Optional.empty()
        }
    }

    fun runAdbCommand(vararg command: String): String {
        val adbCommand = mutableListOf("adb")
        if (this.adbDeviceName != null) {
            adbCommand.add("-s")
            adbCommand.add(this.adbDeviceName)
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
        println("Usage: Deployer <android-package-name> [--device=adb-device-name] [--force-debuggable]")
        return
    }

    val deviceName = args.filter { it.startsWith("--device=") }.map { it.replace("--device=", "") }.firstOrNull()

    val deployer = Deployer(deviceName)
    if ("--force-debuggable" in args) {
        ForceAppDebuggable(deployer).makeDebuggable(packageName = args[0])
    }

    deployer.deploy(packageName = args[0])
}
