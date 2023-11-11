#include "MemUtil.hpp"
#include <Psapi.h>
#include <TlHelp32.h>

std::vector<THREADENTRY32> getProcessThreadEntries(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return {};

	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);
		return {};
	}

	std::vector<THREADENTRY32>threadEntries;

	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
			threadEntries.push_back(te32);
	} while (Thread32Next(hThreadSnap, &te32));

	// Clean up the snapshot
	CloseHandle(hThreadSnap);
	return threadEntries;
}

namespace Seraph
{
	namespace MemUtil
	{
		HANDLE hProcess;
		HANDLE hBaseModule;

		PROCESSENTRY32 findProcess(const std::vector<std::wstring>& processNames)
		{
			PROCESSENTRY32 pEntry = { 0 };
			pEntry.dwSize = sizeof(PROCESSENTRY32);

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (Process32First(snapshot, &pEntry) == TRUE)
			{
				while (Process32Next(snapshot, &pEntry) == TRUE)
				{
					for (size_t i = 0; i < processNames.size(); i++)
					{
						if (lstrcmpiW(pEntry.szExeFile, processNames[i].c_str()) == 0)
						{
							CloseHandle(snapshot);
							return pEntry;
						}
					}
				}
			}

			CloseHandle(snapshot);
			pEntry = { 0 };
			return pEntry;
		}

		bool openProcessByEntry(const PROCESSENTRY32& processEntry)
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processEntry.th32ProcessID);
			if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
				return false;

			hBaseModule = getModule(processEntry.szExeFile);
			if (!hBaseModule || hBaseModule == INVALID_HANDLE_VALUE)
				return false;
			
			return true;
		}

		std::vector<std::pair<std::wstring, HMODULE>> getModules()
		{
			std::vector<std::pair<std::wstring, HMODULE>> results = {};
			HMODULE hMods[1024];
			DWORD cbNeeded;
			unsigned int i;

			if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
			{
				for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
				{
					TCHAR szModName[MAX_PATH];
					if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
					{
						std::wstring wstrModName = szModName;
						results.push_back({ wstrModName, hMods[i] });
					}
				}
			}

			return results;
		}

		HMODULE getModule(const std::wstring& wstrModContain)
		{
			for (const auto& mod : getModules())
			{
				std::wstring str1 = L"";
				std::wstring str2 = L"";
				for (const auto c : mod.first) str1 += tolower(c);
				for (const auto c : wstrModContain) str2 += tolower(c);
				if (str1.find(str2) != std::wstring::npos)
				{
					return mod.second;
				}
			}
			return nullptr;
		}

		PEB getPeb()
		{
			PEB mpeb = { 0 };

			typedef LONG PROCESSINFOCLASS;
			typedef LONG KPRIORITY;

			struct PROCESS_BASIC_INFORMATION
			{
				NTSTATUS ExitStatus;
				PPEB PebBaseAddress;
				ULONG_PTR AffinityMask;
				KPRIORITY BasePriority;
				ULONG_PTR UniqueProcessId;
				ULONG_PTR InheritedFromUniqueProcessId;
			};

			typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;
			typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
				IN  HANDLE ProcessHandle,
				IN  PROCESSINFOCLASS ProcessInformationClass,
				OUT PVOID ProcessInformation,
				IN  ULONG ProcessInformationLength,
				OUT PULONG ReturnLength    OPTIONAL
				);

			HMODULE hNtDll = LoadLibraryA("ntdll.dll");
			if (hNtDll != NULL)
			{
				// 0 = ProcessBasicInformation
				constexpr const auto ProcessBasicInformation = 0;

				const auto gNtQueryInformationProcess = reinterpret_cast<pfnNtQueryInformationProcess> (
					GetProcAddress(hNtDll, "NtQueryInformationProcess")
				);

				// Try to allocate buffer 
				const auto hHeap = GetProcessHeap();
				const auto dwSize = sizeof(PROCESS_BASIC_INFORMATION);

				auto pbi = reinterpret_cast<PPROCESS_BASIC_INFORMATION>(HeapAlloc(hHeap,
					HEAP_ZERO_MEMORY,
					dwSize));

				// Did we successfully allocate memory
				if (pbi)
				{
					ULONG dwSizeNeeded = 0;
					NTSTATUS dwStatus = gNtQueryInformationProcess(hProcess,
						ProcessBasicInformation,
						pbi,
						dwSize,
						&dwSizeNeeded);

					ReadProcessMemory(hProcess, pbi->PebBaseAddress, &mpeb, sizeof(PEB), nullptr);
				}
			}

			return mpeb;
		}

		#if _WIN64
		MEMORY_BASIC_INFORMATION64 getPage(const uintptr_t location)
		{
			MEMORY_BASIC_INFORMATION64 page = { 0 };
			VirtualQueryEx(hProcess, reinterpret_cast<void*>(location), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&page), sizeof(page));
			return page;
		}
		#else
		MEMORY_BASIC_INFORMATION getPage(const uintptr_t location)
		{
			MEMORY_BASIC_INFORMATION page = { 0 };
			VirtualQueryEx(hProcess, reinterpret_cast<void*>(location), &page, sizeof(page));
			return page;
		}
		#endif

		std::string mreads(uintptr_t location, const size_t count)
		{
			size_t nbytes = NULL;
			char* buffer = new char[count];
			ReadProcessMemory(hProcess, reinterpret_cast<void*>(location), buffer, count, &nbytes);
			std::string result(buffer);
			delete[] buffer;
			return result;
		}

		void mwrites(uintptr_t location, const std::string& str)
		{
			size_t nbytes = NULL;
			WriteProcessMemory(hProcess, reinterpret_cast<void*>(location), str.data(), str.length(), &nbytes);
		}
	}
}
