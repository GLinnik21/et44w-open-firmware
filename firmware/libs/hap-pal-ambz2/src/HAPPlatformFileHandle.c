// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
//
// Copyright 2020 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdlib.h>

#include "HAPPlatform+Init.h"
#include "HAPPlatformFileHandle.h"
#include "HAPPlatformRunLoop+Internal.h"

static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "FileHandle" };

typedef struct HAPPlatformFileHandle HAPPlatformFileHandle;

struct HAPPlatformFileHandle {
    int fileDescriptor;
    HAPPlatformFileHandleEvent interests;
    HAPPlatformFileHandleCallback callback;
    void* _Nullable context;
    HAPPlatformFileHandle* _Nullable prevFileHandle;
    HAPPlatformFileHandle* _Nullable nextFileHandle;
    /** Whether the descriptor was put into the select sets in the current iteration. */
    bool isAwaitingEvents;
};

// Circular doubly-linked list with a sentinel node.
static HAPPlatformFileHandle sentinel = { .fileDescriptor = -1,
                                          .prevFileHandle = &sentinel,
                                          .nextFileHandle = &sentinel };

// Next handle to visit while dispatching; moved on by Deregister so callbacks may remove handles.
static HAPPlatformFileHandle* cursor = &sentinel;

HAP_RESULT_USE_CHECK
HAPError HAPPlatformFileHandleRegister(
        HAPPlatformFileHandleRef* fileHandle_,
        int fileDescriptor,
        HAPPlatformFileHandleEvent interests,
        HAPPlatformFileHandleCallback callback,
        void* _Nullable context) {
    HAPPrecondition(fileHandle_);

    HAPPlatformFileHandle* fileHandle = calloc(1, sizeof(HAPPlatformFileHandle));
    if (!fileHandle) {
        HAPLog(&logObject, "Cannot allocate more file handles.");
        *fileHandle_ = 0;
        return kHAPError_OutOfResources;
    }
    fileHandle->fileDescriptor = fileDescriptor;
    fileHandle->interests = interests;
    fileHandle->callback = callback;
    fileHandle->context = context;
    fileHandle->prevFileHandle = sentinel.prevFileHandle;
    fileHandle->nextFileHandle = &sentinel;
    sentinel.prevFileHandle->nextFileHandle = fileHandle;
    sentinel.prevFileHandle = fileHandle;

    *fileHandle_ = (HAPPlatformFileHandleRef) fileHandle;
    return kHAPError_None;
}

void HAPPlatformFileHandleUpdateInterests(
        HAPPlatformFileHandleRef fileHandle_,
        HAPPlatformFileHandleEvent interests,
        HAPPlatformFileHandleCallback callback,
        void* _Nullable context) {
    HAPPrecondition(fileHandle_);
    HAPPlatformFileHandle* fileHandle = (HAPPlatformFileHandle * _Nonnull) fileHandle_;

    fileHandle->interests = interests;
    fileHandle->callback = callback;
    fileHandle->context = context;
}

void HAPPlatformFileHandleDeregister(HAPPlatformFileHandleRef fileHandle_) {
    HAPPrecondition(fileHandle_);
    HAPPlatformFileHandle* fileHandle = (HAPPlatformFileHandle * _Nonnull) fileHandle_;
    HAPPrecondition(fileHandle->prevFileHandle);
    HAPPrecondition(fileHandle->nextFileHandle);

    if (fileHandle == cursor) {
        cursor = fileHandle->nextFileHandle;
    }
    fileHandle->prevFileHandle->nextFileHandle = fileHandle->nextFileHandle;
    fileHandle->nextFileHandle->prevFileHandle = fileHandle->prevFileHandle;

    fileHandle->nextFileHandle = NULL;
    fileHandle->prevFileHandle = NULL;
    HAPPlatformFreeSafe(fileHandle);
}

int HAPPlatformFileHandleCollect(fd_set* readSet, fd_set* writeSet, fd_set* errorSet) {
    int maxFileDescriptor = -1;

    for (HAPPlatformFileHandle* h = sentinel.nextFileHandle; h != &sentinel; h = h->nextFileHandle) {
        h->isAwaitingEvents = false;
        if (h->fileDescriptor < 0) {
            continue;
        }
        HAPAssert(h->fileDescriptor < FD_SETSIZE);
        if (h->interests.isReadyForReading) {
            FD_SET(h->fileDescriptor, readSet);
            h->isAwaitingEvents = true;
        }
        if (h->interests.isReadyForWriting) {
            FD_SET(h->fileDescriptor, writeSet);
            h->isAwaitingEvents = true;
        }
        if (h->interests.hasErrorConditionPending) {
            FD_SET(h->fileDescriptor, errorSet);
            h->isAwaitingEvents = true;
        }
        if (h->isAwaitingEvents && h->fileDescriptor > maxFileDescriptor) {
            maxFileDescriptor = h->fileDescriptor;
        }
    }
    return maxFileDescriptor;
}

void HAPPlatformFileHandleDispatch(fd_set* readSet, fd_set* writeSet, fd_set* errorSet) {
    cursor = sentinel.nextFileHandle;
    while (cursor != &sentinel) {
        HAPPlatformFileHandle* h = cursor;
        cursor = h->nextFileHandle;

        // Handles registered during dispatch were not in the sets.
        if (!h->isAwaitingEvents) {
            continue;
        }
        h->isAwaitingEvents = false;
        if (!h->callback) {
            continue;
        }

        HAPPlatformFileHandleEvent events;
        events.isReadyForReading = h->interests.isReadyForReading && FD_ISSET(h->fileDescriptor, readSet);
        events.isReadyForWriting = h->interests.isReadyForWriting && FD_ISSET(h->fileDescriptor, writeSet);
        events.hasErrorConditionPending =
                h->interests.hasErrorConditionPending && FD_ISSET(h->fileDescriptor, errorSet);
        if (events.isReadyForReading || events.isReadyForWriting || events.hasErrorConditionPending) {
            h->callback((HAPPlatformFileHandleRef) h, events, h->context);
        }
    }
}
