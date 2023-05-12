#include <string>
#include <sstream>
#include <optional>
#include <random>
#include <fstream>

#include <jni.h>

#include <unistd.h>

#include <android/log.h>

#include <sys/mman.h>

#include "include/jvmti.h"

#include "jvmti_allocator.h"

#include "slicer/dex_ir_builder.h"
#include "slicer/reader.h"
#include "slicer/writer.h"
#include "slicer/code_ir.h"
#include "slicer/instrumentation.h"
#include "slicer/control_flow_graph.h"

#include <cmrc/cmrc.hpp>

// Declare the embedded files used to carry along the dex.
CMRC_DECLARE(dex_resources);

#define COVERAGE_MAP_SIZE (64 * 1024)

#define LOG_TAG "ammaraskar"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifdef NDEBUG
#define ALOGD(...) ((void)0)
#else
// Only print debug output and dump dex files in debug builds.
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define DUMP_DEX
#endif

#define NATIVE_LOG_DIR "/data/local/tmp/"
#define NATIVE_LOG_FILE_BASE "native_trace.log"

extern "C" JNIEXPORT jstring JNICALL
Java_com_ammaraskar_tool_test_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    ALOGI("I am inside the JNI!");

    pid_t pid = getpid();
    std::string hello = "Hello from C++, my PID is " + std::to_string(pid);
    return env->NewStringUTF(hello.c_str());
}

using namespace lir;

class Transformer {
public:
    explicit Transformer(std::shared_ptr<ir::DexFile> dexIr) : dexIr_(dexIr), builder(dexIr) {
        // Initialize the types and methods we need.
        auto integerType = builder.GetType("I");
        auto instrClassType = builder.GetType("Lcom/ammaraskar/coverageagent/Instrumentation;");
        // proto for `void f(int)`, i.e void function taking an integer arg.
        auto methodProto = builder.GetProto(builder.GetType("V"),
                                            builder.GetTypeList({integerType}));
        instrumentationMethod = builder.GetMethodDecl(builder.GetAsciiString("reachedBlock"), methodProto,
                                                      instrClassType);
    }

    bool transform() {
        for (auto &method : dexIr_->encoded_methods) {
            ALOGD("checking method: %s.%s%s\n",
                   method->decl->parent->Decl().c_str(),
                   method->decl->name->c_str(),
                   method->decl->prototype->Signature().c_str());

            // Do not look into abstract/bridge/native/synthetic methods.
            if ((method->access_flags &
                 (dex::kAccAbstract | dex::kAccBridge | dex::kAccNative | dex::kAccSynthetic)) !=
                0) {
                continue;
            }

            lir::CodeIr codeIr(method.get(), dexIr_);
            lir::ControlFlowGraph cfg(&codeIr, false);

            slicer::AllocateScratchRegs alloc_regs(1);

            alloc_regs.Apply(&codeIr);
            dex::u4 scratch_reg = *alloc_regs.ScratchRegs().begin();

            // TODO: handle very "high" registers
            if (scratch_reg > 0xff) {
                printf("WARNING: can't instrument method %s.%s%s\n",
                       method->decl->parent->Decl().c_str(),
                       method->decl->name->c_str(),
                       method->decl->prototype->Signature().c_str());
                continue;
            }

            // Seed a random number generator with the name of the current method.
            std::string functionName = method->decl->parent->Decl() + "." + method->decl->name->c_str() + "." + method->decl->prototype->Signature();
            std::size_t methodNameHash = std::hash<std::string>{}(functionName);
            std::mt19937 randomGen(methodNameHash);
            std::uniform_int_distribution<> randomDistribution(0, COVERAGE_MAP_SIZE - 1);

            // If it contains a synchronized block, we only instrument the entry point.
            if (containsSynchronizedBlock(cfg)) {
                // Only instrument the method entry point.
                auto entry_block = *(cfg.basic_blocks.begin());
                auto entry_instruction = entry_block.region.first;
                instrument(codeIr, scratch_reg, entry_instruction, randomDistribution(randomGen));
            } else {
                // Instrument each basic block entry point.
                for (const auto &block: cfg.basic_blocks) {
                    // Find first bytecode in the basic block.
                    lir::Instruction *trace_point = nullptr;
                    for (auto instr = block.region.first; instr != nullptr; instr = instr->next) {
                        trace_point = dynamic_cast<lir::Bytecode *>(instr);
                        if (trace_point != nullptr || instr == block.region.last) {
                            break;
                        }
                    }

                    SLICER_CHECK_NE(trace_point, nullptr);
                    // special case: don't separate 'move-result-<kind>' from the preceding invoke
                    auto opcode = dynamic_cast<lir::Bytecode *>(trace_point)->opcode;
                    if (opcode == dex::OP_MOVE_RESULT ||
                        opcode == dex::OP_MOVE_RESULT_WIDE ||
                        opcode == dex::OP_MOVE_RESULT_OBJECT) {
                        trace_point = trace_point->next;
                    }

                    // special case: 'move-exception' must be the first instruction in a catch block
                    if (opcode == dex::OP_MOVE_EXCEPTION) {
                        trace_point = trace_point->next;
                    }

                    instrument(codeIr, scratch_reg, trace_point, randomDistribution(randomGen));
                }
            }

            codeIr.Assemble();
        }

        return true;
    }

private:
    static bool containsSynchronizedBlock(lir::ControlFlowGraph &cfg) {
        // Returns true if the method contains a synchronized block.
        for (const auto &block : cfg.basic_blocks) {
            for (auto instr = block.region.first;
                 instr != nullptr && instr != block.region.last; instr = instr->next) {
                // Check all bytecode instructions.
                lir::Bytecode *bytecode = dynamic_cast<lir::Bytecode *>(instr);
                if (bytecode != nullptr) {
                    auto opcode = bytecode->opcode;
                    if (opcode == dex::OP_MONITOR_ENTER || opcode == dex::OP_MONITOR_EXIT ||
                        opcode == dex::OP_MOVE_EXCEPTION) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    void instrument(lir::CodeIr &codeIr, dex::u4 scratch_reg, lir::Instruction *trace_point,
                    int basic_block_id) {
        // scratch_reg = block_id
        auto load_block_id = codeIr.Alloc<lir::Bytecode>();
        load_block_id->opcode = dex::OP_CONST;
        load_block_id->operands.push_back(codeIr.Alloc<lir::VReg>(scratch_reg));
        load_block_id->operands.push_back(codeIr.Alloc<lir::Const32>(basic_block_id));
        codeIr.instructions.InsertBefore(trace_point, load_block_id);

        // call Instrumentation.reachedBlock(block_id)
        auto trace_call = codeIr.Alloc<lir::Bytecode>();
        trace_call->opcode = dex::OP_INVOKE_STATIC_RANGE;
        trace_call->operands.push_back(codeIr.Alloc<lir::VRegRange>(scratch_reg, 1));
        trace_call->operands.push_back(codeIr.Alloc<Method>(instrumentationMethod,
                                                            instrumentationMethod->orig_index));
        codeIr.instructions.InsertBefore(trace_point, trace_call);
    }

    std::shared_ptr<ir::DexFile> dexIr_;
    ir::Builder builder;
    ir::MethodDecl *instrumentationMethod = nullptr;
};


// Converts a class name to a type descriptor
// (ex. "java.lang.String" to "Ljava/lang/String;")
std::string classNameToDescriptor(const char *className) {
    std::stringstream ss;
    ss << "L";
    for (auto p = className; *p != '\0'; ++p) {
        ss << (*p == '.' ? '/' : *p);
    }
    ss << ";";
    return ss.str();
}

std::optional<std::pair<dex::u1 *, size_t>>
transformClass(const char *name, size_t classDataLen, const unsigned char *classData,
               dex::Writer::Allocator *allocator) {
    ALOGD("Trying to instrument class: %s", name);
    dex::Reader reader(classData, classDataLen);

    // Find the actual class amongst all the classData.
    dex::u4 index = reader.FindClassIndex(classNameToDescriptor(name).c_str());
    assert(index != dex::kNoIndex);
    reader.CreateClassIr(index);
    std::shared_ptr<ir::DexFile> ir = reader.GetIr();

    {
        Transformer transformer(ir);
        if (!transformer.transform()) {
            return std::nullopt;
        }
    }

    size_t new_size;
    dex::Writer writer(ir);
    dex::u1 *newClassData = writer.CreateImage(allocator, &new_size);
    return std::make_pair(newClassData, new_size);
}

#ifdef DUMP_DEX
std::string dataDir;
void dump(const char *className, const char *suffix, const unsigned char *classData, jint classDataLen) {
    std::string classNameDots = className;
    std::replace(classNameDots.begin(), classNameDots.end(), '/', '.');
    std::string path = dataDir + "/coverageagent/" + classNameDots + suffix;
    // Create the directory
    std::string dirname = path.substr(0, path.find_last_of('/'));
    std::filesystem::create_directory(dirname);

    ALOGD("Dumping %s to %s", classNameDots.c_str(), path.c_str());
    FILE *f = fopen(path.c_str(), "wb");
    fwrite(classData, classDataLen, 1, f);
    fclose(f);
}
#endif

void transformHook(jvmtiEnv *jvmtiEnv, JNIEnv *env,
                   jclass classBeingRedefined, jobject loader, const char *name,
                   jobject protectionDomain, jint classDataLen,
                   const unsigned char *classData, jint *newClassDataLen,
                   unsigned char **newClassData) {
    //ALOGI("transformHook(%s, loader=%px)", name, loader);

    // Don't instrument the instrumentation class
    if (strncmp(name, "com/ammaraskar/coverageagent/Instrumentation", 44) == 0) {
        return;
    }

    ALOGD("Transform hook called with name: %s", name);

    JvmtiAllocator allocator(jvmtiEnv);
    auto new_class = transformClass(name, classDataLen, classData, &allocator);

    if (new_class) {
#ifdef DUMP_DEX
        dump(name, ".orig.dex", classData, classDataLen);
        dump(name, ".dex", new_class->first, new_class->second);
#endif
        *newClassData = new_class->first;
        *newClassDataLen = new_class->second;
    }
}


void nativeFunctionHook(JNIEnv *env, void *nativeHook);

std::string getPackageName() {
    // Get the package name from /proc/self/cmdline
    std::ifstream cmdline("/proc/self/cmdline");
    std::string packageName;
    std::getline(cmdline, packageName, '\0');
    return packageName;
}


class NativeHook {
public:
    // Constructor
    NativeHook(void *originalFunction, std::string className, std::string functionName,
               std::string methodSignature) : originalFunction(originalFunction),
                                              className(className),
                                              functionName(functionName),
                                              methodSignature(methodSignature) {
        createTrampoline();

    }

    void instrumentation(JNIEnv *env) {
        ALOGD("Instrumentation called for: %s in class %s (signature: %s)", functionName.c_str(),
              className.c_str(), methodSignature.c_str());

        // Get the log index
        instrumentationClass = env->FindClass("com/ammaraskar/coverageagent/Instrumentation");
        if (instrumentationClass == nullptr) {
            ALOGE("Could not find Instrumentation class");
            return;
        }
        logIndexField = env->GetStaticFieldID(instrumentationClass, "logIndex", "I");
        if (logIndexField == nullptr) {
            ALOGE("Could not find logIndex field");
            return;
        }
        int logIndex = env->GetStaticIntField(instrumentationClass, logIndexField);

        if (logIndex != -1) {
            // Append call to the log file
            std::string dirName = NATIVE_LOG_DIR + getPackageName() + "/";
            std::string logFileName = dirName + NATIVE_LOG_FILE_BASE + "." + std::to_string(logIndex);

            // Create the directory if it doesn't exist
            std::filesystem::create_directory(dirName);

            std::ofstream logFile;
            logFile.open(logFileName, std::ios_base::app);
            logFile << className << "," << functionName << "," << methodSignature << std::endl;
            logFile.close();
        }
    }

    // Contains the original function, the function name, the method signature, and the trampoline
    std::string className;
    std::string functionName;
    std::string methodSignature;
    void *originalFunction;
    void *trampoline;

    static void *currentPage;
    static int currentPageOffset;

private:
    void createTrampoline() {
        unsigned int trampoline_code_size;
#ifdef __x86_64__
        trampoline_code_size = 55;
#elif __aarch64__
        // TODO
        trampoline_code_size = 0;
#elif __i386__
        // TODO
        trampoline_code_size = 0;
#elif __arm__
        // TODO
        trampoline_code_size = 0;
#else
#error "Unsupported architecture"
#endif

        // Get memory for the trampoline_ptr code
        unsigned char *trampoline_ptr = static_cast<unsigned char *>(getTrampolineMemory(trampoline_code_size));

        /*
         * In the assembly, we want to:
         * 1. Save the argument registers
         * 2. Call the instrumentation
         * 3. Restore the argument registers
         * 4. Jump to the original function
         */
#ifdef __x86_64__
        // Fix the stack alignment (push rax)
        trampoline_ptr[0] = 0x50;

        // Save the argument registers (push rdi, rsi, rdx, rcx, r8, r9)
        trampoline_ptr[1] = 0x57;
        trampoline_ptr[2] = 0x56;
        trampoline_ptr[3] = 0x52;
        trampoline_ptr[4] = 0x51;
        trampoline_ptr[5] = 0x41;
        trampoline_ptr[6] = 0x50;
        trampoline_ptr[7] = 0x41;
        trampoline_ptr[8] = 0x51;

        // Call the instrumentation
        // mov rax, <address>
        trampoline_ptr[9] = 0x48;
        trampoline_ptr[10] = 0xb8;
        *reinterpret_cast<void **>(&trampoline_ptr[11]) = reinterpret_cast<void *>(&nativeFunctionHook);
        // mov rsi, <this>
        trampoline_ptr[19] = 0x48;
        trampoline_ptr[20] = 0xbe;
        *reinterpret_cast<void **>(&trampoline_ptr[21]) = reinterpret_cast<void *>(this);
        // call rax
        trampoline_ptr[29] = 0xff;
        trampoline_ptr[30] = 0xd0;

        // Restore the argument registers (pop r9, r8, rcx, rdx, rsi, rdi)
        trampoline_ptr[31] = 0x41;
        trampoline_ptr[32] = 0x59;
        trampoline_ptr[33] = 0x41;
        trampoline_ptr[34] = 0x58;
        trampoline_ptr[35] = 0x59;
        trampoline_ptr[36] = 0x5a;
        trampoline_ptr[37] = 0x5e;
        trampoline_ptr[38] = 0x5f;

        // Fix the stack alignment (add rsp, 8)
        trampoline_ptr[39] = 0x48;
        trampoline_ptr[40] = 0x83;
        trampoline_ptr[41] = 0xc4;
        trampoline_ptr[42] = 0x08;

        // Jump to the original function
        // mov rax, <address>
        trampoline_ptr[43] = 0x48;
        trampoline_ptr[44] = 0xb8;
        *reinterpret_cast<void **>(&trampoline_ptr[45]) = originalFunction;
        // jmp rax
        trampoline_ptr[53] = 0xff;
        trampoline_ptr[54] = 0xe0;

#elif __aarch64__
        // TODO
#elif __i386__
        // TODO
#elif __arm__
        // TODO
#else
#error "Unsupported architecture"
#endif

        // Flush the instruction cache
        __builtin___clear_cache(reinterpret_cast<char *>(trampoline_ptr),
                                reinterpret_cast<char *>(trampoline_ptr) + trampoline_code_size);

        this->trampoline =  trampoline_ptr;
    }

    void *getTrampolineMemory(int size) {
        if (currentPage == nullptr || currentPageOffset + size > 4096) {
            currentPage = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (currentPage == MAP_FAILED) {
                ALOGE("Failed to allocate trampoline");
                exit(1);
            }

            currentPageOffset = 0;
        }

        currentPageOffset += size;

        return reinterpret_cast<char *>(currentPage) + currentPageOffset - size;
    }

    JNIEnv *env;
    jclass instrumentationClass;
    jfieldID logIndexField;
};

void *NativeHook::currentPage = nullptr;
int NativeHook::currentPageOffset = 0;


void nativeFunctionHook(JNIEnv *env, void *nativeHook) {
    reinterpret_cast<NativeHook *>(nativeHook)->instrumentation(env);
}


void transformNativeHook(jvmtiEnv *jvmtiEnv, JNIEnv *env,
                         jthread thread, jmethodID method, void *address, void **new_address_ptr) {
    char *method_name;
    char *method_signature;
    jclass declaring_class;
    char *class_name;

    // Get the class name and method name
    jvmtiError error = jvmtiEnv->GetMethodName(method, &method_name, &method_signature, NULL);
    if (error != JVMTI_ERROR_NONE) {
        ALOGE("Failed to get method name");
        return;
    }
    error = jvmtiEnv->GetMethodDeclaringClass(method, &declaring_class);
    if (error != JVMTI_ERROR_NONE) {
        ALOGE("Failed to get declaring class");
        return;
    }
    error = jvmtiEnv->GetClassSignature(declaring_class, &class_name, NULL);
    if (error != JVMTI_ERROR_NONE) {
        ALOGE("Failed to get class signature");
        return;
    }

    ALOGI("Hooking native function: %s in class %s (signature: %s)\n", method_name, class_name,
          method_signature);

    NativeHook *nativeHook = new NativeHook(address, class_name, method_name, method_signature);
    *new_address_ptr = reinterpret_cast<void *>(nativeHook->trampoline);
}

void addInstrumentationClassToClassPath(jvmtiEnv *jvmtiEnv, char* appDataDir) {
    auto dexFile = cmrc::dex_resources::get_filesystem().open("gen/Instrumentation.dex");

    // Put the dexFile on disk so we can add it to the classpath.
    std::string outputFileName = std::string(appDataDir) + "/code_cache/instrumentation.dex";
    ALOGI("Writing to file: %s", outputFileName.c_str());
    std::ofstream outputDexFile(outputFileName, std::ofstream::binary);
    std::copy(dexFile.begin(), dexFile.end(), std::ostreambuf_iterator<char>(outputDexFile));
    outputDexFile.close();
    ALOGI("File created. Adding to classpath");

    jvmtiEnv->AddToBootstrapClassLoaderSearch(outputFileName.c_str());
}

jvmtiEnv *CreateJvmtiEnv(JavaVM *vm) {
    jvmtiEnv *jvmti_env;
    jint result = vm->GetEnv((void **) &jvmti_env, JVMTI_VERSION_1_2);
    if (result != JNI_OK) {
        return nullptr;
    }

    return jvmti_env;
}

bool hookNative(char *dir) {
    // check if ".hook_native" exists in dir
    std::string hookNativeFile = std::string(dir) + "/.hook_native";
    return access(hookNativeFile.c_str(), F_OK) == 0;
}

// Early attachment (e.g. 'java -agent[lib|path]:filename.so').
extern "C" JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *input,
                                                 void *reserved) {
    ALOGI("========== Agent_OnLoad Start =======");

    bool hook_native = hookNative(input);

    jvmtiEnv *env = CreateJvmtiEnv(vm);
    if (env == nullptr) {
        ALOGE("Unable to create jvmti env");
        return JNI_ERR;
    }

    jvmtiCapabilities caps = {0};
    caps.can_retransform_classes = 1;
    if (env->AddCapabilities(&caps) != JVMTI_ERROR_NONE) {
        ALOGE("Unable to add can_retransform_classes capability");
        return JNI_ERR;
    }

    jvmtiEventCallbacks callbacks = {0};
    callbacks.ClassFileLoadHook = transformHook;

    if (hook_native) {
        caps.can_generate_native_method_bind_events = 1;
        if (env->AddCapabilities(&caps) != JVMTI_ERROR_NONE) {
            ALOGE("Unable to add can_generate_native_method_bind_events capability");
            return JNI_ERR;
        }
        callbacks.NativeMethodBind = transformNativeHook;
    }

    if (env->SetEventCallbacks(&callbacks, sizeof(callbacks)) != JVMTI_ERROR_NONE) {
        ALOGE("Unable to set jvmti file load hook");
        return JNI_ERR;
    }
    if (env->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr) !=
        JVMTI_ERROR_NONE) {
        ALOGE("Unable to set event notification (JVMTI_EVENT_CLASS_FILE_LOAD_HOOK)");
        return JNI_ERR;
    }
    if (env->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, nullptr) !=
        JVMTI_ERROR_NONE) {
        ALOGE("Unable to set event notification (JVMTI_EVENT_VM_INIT)");
        return JNI_ERR;
    }
    if (hook_native &&
        env->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_NATIVE_METHOD_BIND, nullptr) !=
        JVMTI_ERROR_NONE) {
        ALOGE("Unable to set event notification (JVMTI_EVENT_NATIVE_METHOD_BIND)");
        return JNI_ERR;
    }

    // Add the instrumentation class to the classpath. The input passed in to startup_agents is the
    // app's data directory.
    addInstrumentationClassToClassPath(env, input);
#ifdef DUMP_DEX
    dataDir = strdup(input);
#endif

    ALOGI("========== Agent_OnLoad End =======");

    return JNI_OK;
}

// Late attachment (e.g. 'am attach-agent').
JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char* options, void* reserved) {
    return Agent_OnLoad(vm, options, reserved);
}
