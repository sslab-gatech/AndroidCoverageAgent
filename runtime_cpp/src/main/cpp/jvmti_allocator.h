//
// An allocator for a dex writer based on the jvmti's allocation APIs.
//

#ifndef ANDROID_JVMTI_TEST_JVMTI_ALLOCATOR_H
#define ANDROID_JVMTI_TEST_JVMTI_ALLOCATOR_H

#include "include/jvmti.h"
#include "slicer/writer.h"

class JvmtiAllocator: public dex::Writer::Allocator {
public:
    explicit JvmtiAllocator(::jvmtiEnv* jvmti) :
            jvmti_(jvmti) {
    }

    void* Allocate(size_t size) override {
        unsigned char* res = nullptr;
        jvmti_->Allocate(size, &res);
        return res;
    }

    void Free(void* ptr) override {
        jvmti_->Deallocate(reinterpret_cast<unsigned char*>(ptr));
    }

private:
    ::jvmtiEnv* jvmti_;
};

#endif //ANDROID_JVMTI_TEST_JVMTI_ALLOCATOR_H
