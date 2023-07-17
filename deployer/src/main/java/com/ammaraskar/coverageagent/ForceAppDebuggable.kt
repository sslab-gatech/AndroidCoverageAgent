package com.ammaraskar.coverageagent

import com.sun.jdi.*
import org.jdiscript.JDIScript
import org.jdiscript.util.VMSocketAttacher
import java.lang.IllegalArgumentException

/**
 * Local port to forward the jdwp connection to.
 */
const val HOST_PORT = 8690;

const val PACKAGE_SETTINGS_CLASS = "com.android.server.pm.PackageSetting";

/**
 * Forces an app to be debuggable by connecting to Android with a jvm debugger and altering the
 * PackageManager's memory.
 */
class ForceAppDebuggable(private var deployer: Deployer) {

    fun makeDebuggable(packageName: String) {
        // Kill any existing adb servers, Android Studio's adb server hijacks all jdwp connections
        // and makes them not work for any other clients.
        println("[i] Restarting adb daemon")
        deployer.runAdbCommand("kill-server")
        deployer.runAdbCommand("start-server")
        deployer.runAdbCommand("wait-for-device")

        println("[i] Retrieving pid for system_server")

        val pid = deployer.runAdbCommand("shell", "pidof", "system_server").trim()
        println("[+] Got system_server pid: $pid")

        println("[i] Forwarding jdwp port for system_server")
        deployer.runAdbCommand("forward", "tcp:$HOST_PORT", "jdwp:$pid")

        println("[i] Connecting to jdwp socket with jdiscript...")
        changeDebugFlagWithDebugger(packageName)
    }

    private fun changeDebugFlagWithDebugger(packageName: String) {
        val vm = VMSocketAttacher("localhost", HOST_PORT, 30).attach()
        println("[+] Debugger attached!")
        val j = JDIScript(vm)

        val packageSettingsClass = j.vm().classesByName(PACKAGE_SETTINGS_CLASS).firstOrNull()
                ?: throw IllegalStateException("$PACKAGE_SETTINGS_CLASS not found in system server java process");

        var nameField: Field? = null;
        var flagsField: Field? = null;

        for (field in packageSettingsClass.allFields()) {
            if (field.name().equals("name", ignoreCase = true) || field.name().equals("mName", ignoreCase = true)) {
                nameField = field;
            }
            if (field.name().equals("pkgFlags", ignoreCase = true) || field.name().equals("mPkgFlags", ignoreCase = true)) {
                flagsField = field
            }
        }

        // Make sure we actually managed to find the fields.
        if (nameField == null) {
            throw IllegalStateException("nameField was null :(")
        }
        if (flagsField == null) {
            throw IllegalStateException("flagsField was null :(")
        }

        for (settings in packageSettingsClass.instances(512)) {
            val instancePackageName = getJdiValueAsString(settings.getValue(nameField));
            //println("Package name: $instancePackageName")
            if (!instancePackageName.equals(packageName, ignoreCase = true)) {
                continue;
            }

            val flags = getJdiValueAsLong(settings.getValue(flagsField));
            println("[+] Found package settings, changing flags.")
            println("Instance - ${settings.uniqueID()}, mName=$instancePackageName flags=$flags")

            // Binary OR with the debuggable flag, 0x2
            val newFlags = flags or 0x2
            settings.setValue(flagsField, j.vm().mirrorOf(newFlags))

            println("[+] Flag changed.")
        }

        j.vm().dispose()
    }

    private fun getJdiValueAsLong(value: Value): Int {
        if (value is IntegerValue) {
            return value.value();
        }
        throw IllegalArgumentException("getJdiValueAsLong called on value of type ${value.type()}")
    }

    private fun getJdiValueAsString(value: Value): String {
        if (value is StringReference) {
            return value.value();
        }
        throw IllegalArgumentException("getJdiValueAsString called on value of type ${value.type()}")
    }
}
