// SPDX-License-Identifier: MIT
#include "Interface/Context/Context.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/X86Tables/X86Tables.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CPUID.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include <FEXCore/Core/Thunks.h>
#include "FEXCore/Debug/InternalThreadState.h"

namespace FEXCore::Context {
fextl::unique_ptr<FEXCore::Context::Context> FEXCore::Context::Context::CreateNewContext(const FEXCore::HostFeatures& Features) {
  return fextl::make_unique<FEXCore::Context::ContextImpl>(Features);
}

void FEXCore::Context::ContextImpl::CompileRIP(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP) {
  CompileBlock(Thread->CurrentFrame, GuestRIP);
}

void FEXCore::Context::ContextImpl::CompileRIPCount(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) {
  CompileBlock(Thread->CurrentFrame, GuestRIP, MaxInst);
}

void FEXCore::Context::ContextImpl::SetSignalDelegator(FEXCore::SignalDelegator* _SignalDelegation) {
  SignalDelegation = _SignalDelegation;
}

void FEXCore::Context::ContextImpl::SetSyscallHandler(FEXCore::HLE::SyscallHandler* Handler) {
  SyscallHandler = Handler;
  SourcecodeResolver = Handler->GetSourcecodeResolver();
}

void FEXCore::Context::ContextImpl::SetThunkHandler(FEXCore::ThunkHandler* Handler) {
  ThunkHandler = Handler;
}

FEXCore::CPUID::FunctionResults FEXCore::Context::ContextImpl::RunCPUIDFunction(uint32_t Function, uint32_t Leaf) {
  return CPUID.RunFunction(Function, Leaf);
}

FEXCore::CPUID::XCRResults FEXCore::Context::ContextImpl::RunXCRFunction(uint32_t Function) {
  return CPUID.RunXCRFunction(Function);
}

FEXCore::CPUID::FunctionResults FEXCore::Context::ContextImpl::RunCPUIDFunctionName(uint32_t Function, uint32_t Leaf, uint32_t CPU) {
  return CPUID.RunFunctionName(Function, Leaf, CPU);
}

bool FEXCore::Context::ContextImpl::IsAddressInCodeBuffer(FEXCore::Core::InternalThreadState* Thread, uintptr_t Address) const {
  return Thread->CPUBackend->IsAddressInCodeBuffer(Address) || CodeCache.IsAddressInMappedCodeBuffer(Address);
}

fextl::shared_ptr<CPU::CodeBuffer> FEXCore::Context::ContextImpl::FindCodeBufferContaining(uintptr_t HostAddress) {
  std::scoped_lock lk {CodeBufferListLock};
  for (auto& WeakBuffer : CodeBufferList) {
    if (auto Buffer = WeakBuffer.lock()) {
      const auto Base = reinterpret_cast<uintptr_t>(Buffer->Ptr);
      if (HostAddress >= Base && HostAddress < Base + Buffer->AllocatedSize) {
        return Buffer;
      }
    }
  }
  return nullptr;
}

void FEXCore::Context::ContextImpl::RetainCodeBufferAt(uintptr_t HostAddress) {
  if (HostAddress == 0) {
    return;
  }

  auto Buffer = FindCodeBufferContaining(HostAddress);
  if (!Buffer) {
    return;
  }

  std::scoped_lock lk {RetainedCodeBufferLock};
  auto [It, Inserted] = RetainedCodeBuffers.try_emplace(Buffer.get(), std::move(Buffer), 0);
  It->second.second++;
}

void FEXCore::Context::ContextImpl::ReleaseCodeBufferAt(uintptr_t HostAddress) {
  if (HostAddress == 0) {
    return;
  }

  auto Buffer = FindCodeBufferContaining(HostAddress);
  if (!Buffer) {
    return;
  }

  std::scoped_lock lk {RetainedCodeBufferLock};
  auto It = RetainedCodeBuffers.find(Buffer.get());
  if (It == RetainedCodeBuffers.end()) {
    return;
  }

  if (--It->second.second == 0) {
    RetainedCodeBuffers.erase(It);
  }
}
} // namespace FEXCore::Context
