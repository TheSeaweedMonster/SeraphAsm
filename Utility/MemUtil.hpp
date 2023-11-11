#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <winternl.h>

namespace Seraph
{
	namespace MemUtil
	{
		constexpr const uint32_t WRITABLE_MEMORY = (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		constexpr const uint32_t READABLE_MEMORY = (WRITABLE_MEMORY | PAGE_READONLY | PAGE_EXECUTE_READ);
		constexpr const uint32_t EXECUTABLE_MEMORY = (PAGE_EXECUTE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READ);

		extern HANDLE hProcess;
		extern HANDLE hBaseModule;

		extern PROCESSENTRY32 findProcess(const std::vector<std::wstring>& processNames);
		extern bool openProcessByEntry(const PROCESSENTRY32& processName);
		extern bool isProcessOpened();

		extern std::vector<std::pair<std::wstring, HMODULE>> getModules();
		extern HMODULE getModule(const std::wstring& wstrModContain);
		extern PEB getPeb();

		#if _WIN64
		MEMORY_BASIC_INFORMATION64 getPage(const uintptr_t location);
		#else
		MEMORY_BASIC_INFORMATION getPage(const uintptr_t location);
		#endif

		extern std::string mreads(uintptr_t location, const size_t count = 1024);

		template <typename T>
		static T mread(uintptr_t location)
		{
			size_t nbytes = NULL;
			T value;
			ReadProcessMemory(hProcess, reinterpret_cast<void*>(location), &value, sizeof(T), &nbytes);
			return value;
		}

		template <typename T>
		static bool mwrite(uintptr_t location, const T& value)
		{
			size_t nbytes = NULL;
			return WriteProcessMemory(hProcess, reinterpret_cast<void*>(location), &value, sizeof(T), &nbytes);
		}

		template <typename T>
		static std::vector<T> mread(uintptr_t location, const size_t count)
		{
			size_t nbytes = NULL;
			std::vector<T> value(count, 0);
			ReadProcessMemory(hProcess, reinterpret_cast<void*>(location), &value[0], count * sizeof(T), &nbytes);
			return value;
		}

		template <typename T>
		static bool mwrite(uintptr_t location, const std::vector<T>& value)
		{
			size_t nbytes = NULL;
			return WriteProcessMemory(hProcess, reinterpret_cast<void*>(location), &value[0], value.size(), &nbytes);
		}

		extern void mwrites(uintptr_t location, const std::string& str);
	}
}
