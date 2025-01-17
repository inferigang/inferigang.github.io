---
layout: raw_code
lang: en
title: Increase PE's SizeOfImage field
author: Otávio
author_url:
author_nickname: estr3llas
tags: [windows, cpp, antianalysis]
code: |
 void IncreaseSizeOfImage(PPEB peb) {
      const auto ldr_data = peb->LoaderData;
      const auto& [flink, blink] = ldr_data->InLoadOrderModuleList;

      // Retrieve our executable NTDLL's record
      const auto pe = reinterpret_cast<peb::PLDR_DATA_TABLE_ENTRY>(flink->Flink);

      // Get the SizeOfImage field
      auto pSize = &pe->SizeOfImage;

      // Increase it by an arbitrary number
      *pSize = static_cast<
          ULONG > (
              static_cast< INT_PTR > (pe->SizeOfImage + 0x10000000));
  }
---
