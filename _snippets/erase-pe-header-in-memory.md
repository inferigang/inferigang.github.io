---
layout: raw_code
lang: en
title: Erase PE Header in Memory
author: Otávio
author_url:
author_nickname: estr3llas
tags: [windows, cpp, antianalysis]
code: |
  #define PAGE_SIZE 0x1000
  #define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

  #define STATUS_PROCEDURE_NOT_FOUND 0xC000007A
  #define STATUS_INVALID_PAGE_PROTECTION 0xC0000045
  #define STATUS_SECTION_PROTECTION 0xC000004E
  #define STATUS_SUCCESS 0x00000000

  typedef
  NTSYSCALLAPI
  NTSTATUS
  (NTAPI* pNtProtectVirtualMemory) (
      _In_ HANDLE ProcessHandle,
      _Inout_ PVOID* BaseAddress,
      _Inout_ PSIZE_T RegionSize,
      _In_ ULONG NewProtect,
      _Out_ PULONG OldProtect
  );

  NTSTATUS EraseHeader() {

      // Retrieve our module's base address
      auto base = CONTAINING_RECORD(
          NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink,
          LDR_DATA_TABLE_ENTRY,
          InLoadOrderLinks
      );

      // Retrieve ntdll's base address
      auto ntdll = CONTAINING_RECORD(
          NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink->Flink,
          LDR_DATA_TABLE_ENTRY,
          InLoadOrderLinks
      );

      // Check if NtProtectVirtualMemory actually exists
      if (!GetProcAddress(reinterpret_cast<HMODULE>(ntdll), "NtProtectVirtualMemory")) {
          SetLastError(ERROR_PROC_NOT_FOUND);
          return STATUS_PROCEDURE_NOT_FOUND;
      }

      // Retrieve its address
      static auto _vprotect = reinterpret_cast<
          pNtProtectVirtualMemory > (
              GetProcAddress(reinterpret_cast<HMODULE>(ntdll), "NtProtectVirtualMemory")
              );

      // Change the protection of the 1st page of our PE (likely our PE header in memory)
      // to PAGE_READWRITE, so we can zero it out.
      ULONG oldProtect = 0;
      SIZE_T size = PAGE_SIZE;

      auto status = _vprotect(
          NtCurrentProcess(),
          reinterpret_cast<PVOID*>(base),
          &size,
          PAGE_READWRITE,
          &oldProtect
      );

      if(!NT_SUCCESS(status)) {
          return status;
      }

      // Zero out the whole page
      __try {
          RtlSecureZeroMemory(
              base,
              PAGE_SIZE
          );
      }
      // If somehow RtlSecureZeroMemory fails, restore protections
      __except (EXCEPTION_EXECUTE_HANDLER) {
          ULONG dummy;
          _vprotect(
              NtCurrentProcess(),
              reinterpret_cast<PVOID*>(base),
              &size,
              oldProtect,
              &dummy
          );
          return STATUS_ACCESS_VIOLATION;
      }

      // Restore protections anyway
      status = _vprotect(
          NtCurrentProcess(),
          reinterpret_cast<PVOID*>(base),
          &size,
          oldProtect,
          &oldProtect
      );

      return status;
  }
---
