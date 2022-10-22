# CoverageAgent

This repository contains code for an Android JVMTI agent that can be attached to an app in order
to instrument it for AFL-style code coverage.

It consists of two portions, Java code in the `runtime_java` folder that gets called at runtime
when a basic block is hit.

The code to add this call is generated in `runtime_cpp` which is a JVMTI agent with a
`ClassFileLoadHook` that transforms dex files when they are loaded. In particular it adds a call
to `Instrumentation.reachedBlock(blockId)`. It also adds the java code to the classpath so it can
be loaded by the app at runtime.

## Building

Normally you can build by importing the project into Android Studio and building. On the command line:

### Windows

(Replace `ANDROID_SDK_ROOT` with your actual Android SDK folder)

```bash
set ANDROID_SDK_ROOT=%APPDATA%\Local\Android\Sdk
gradlew.bat assemble
```

### Linux

```bash
ANDROID_SDK_ROOT=/path/to/sdk gradlew.bat assemble
```
