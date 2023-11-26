#include "MemUtil.hpp"
#include <Psapi.h>
#include <TlHelp32.h>
#include "Sections.hpp"

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
		DWORD targetProcessId = 0;
		HANDLE hProcess;
		HANDLE hBaseModule;
		size_t baseModuleSize;

		PROCESSENTRY32 findProcess(const std::vector<std::wstring>& processNames)
		{
			PROCESSENTRY32 entry = { 0 };
			entry.dwSize = sizeof(PROCESSENTRY32);

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (Process32First(snapshot, &entry) == TRUE)
			{
				while (Process32Next(snapshot, &entry) == TRUE)
				{
					for (size_t i = 0; i < processNames.size(); i++)
					{
						if (lstrcmpiW(entry.szExeFile, processNames[i].c_str()) == 0)
						{
							CloseHandle(snapshot);
							return entry;
						}
					}
				}
			}

			CloseHandle(snapshot);
			return entry;
		}

		bool openProcessByEntry(const PROCESSENTRY32& processEntry)
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processEntry.th32ProcessID);
			if (hProcess == INVALID_HANDLE_VALUE)
				return false;

			targetProcessId = processEntry.th32ProcessID;
			hBaseModule = getModule(processEntry.szExeFile, &baseModuleSize);
			//if (hBaseModule == INVALID_HANDLE_VALUE)
			//	return false;

			return true;
		}

		bool isProcessOpened()
		{
			PROCESSENTRY32 entry = { 0 };
			entry.dwSize = sizeof(PROCESSENTRY32);

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (Process32First(snapshot, &entry) == TRUE)
			{
				while (Process32Next(snapshot, &entry) == TRUE)
				{
					if (entry.th32ProcessID == targetProcessId)
					{
						CloseHandle(snapshot);
						return true;
					}
				}
			}

			CloseHandle(snapshot);
			return false;
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

		HMODULE getModule(const std::wstring& wstrModContain, size_t* modSize)
		{
			for (const auto& mod : getModules())
			{
				std::wstring str1 = L"";
				std::wstring str2 = L"";
				for (const auto c : mod.first) str1 += tolower(c);
				for (const auto c : wstrModContain) str2 += tolower(c);
				if (str1.find(str2) != std::wstring::npos)
				{
					if (modSize)
					{
						MEMORY_BASIC_INFORMATION page = { 0 };
						VirtualQueryEx(hProcess, reinterpret_cast<void*>(mod.second), &page, sizeof(page));

						*modSize = page.RegionSize;
					}
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

		bool isRel(const uintptr_t address)
		{
			return (getRel(address) % 0x10 == 0);
		}

		bool isCall(const uintptr_t address)
		{
			return (
				isRel(address)
				&& getRel(address) > reinterpret_cast<uintptr_t>(hBaseModule)
				&& getRel(address) < reinterpret_cast<uintptr_t>(hBaseModule) + baseModuleSize
			);
		}

		bool isPrologue(const uintptr_t address)
		{
			#if _WIN64
			return (
				//(address > reinterpret_cast<uintptr_t>(hBaseModule) && address < reinterpret_cast<uintptr_t>(hBaseModule) + baseModuleSize) &&
				(address % 0x10 == 0) &&
				((mread<uint16_t>(address - 1) == 0x8BCC) ||
				(mread<uint16_t>(address) == 0x8948 && (mread<uint8_t>(address + 2) / 0x40 == 1) && mread<uint8_t>(address + 2) % 8 == 4)
				)
			);
			#else
			return (
				//(address > reinterpret_cast<uintptr_t>(hBaseModule) && address < reinterpret_cast<uintptr_t>(hBaseModule) + baseModuleSize) &&
				(address % 0x10 == 0) &&
				// Check for 3 different prologues, each with different registers
				((   mread<uint8_t>(address) == 0x55 && mread<uint16_t>(address + 1) == 0xEC8B)
				 || (mread<uint8_t>(address) == 0x53 && mread<uint16_t>(address + 1) == 0xDC8B)
				 || (mread<uint8_t>(address) == 0x56 && mread<uint16_t>(address + 1) == 0xF48B))
			);
			#endif
		}

		uintptr_t getRel(const uintptr_t address)
		{
			return address + 5 + mread<uint32_t>(address + 1);
		}

		uintptr_t nextPrologue(const uintptr_t address)
		{
			uintptr_t at = address;

			if (isPrologue(at))
				at += 16;
			else
				at += (at % 16);

			while (!isPrologue(at))
				at += 16;

			return at;
		}

		uintptr_t prevPrologue(const uintptr_t address)
		{
			uintptr_t at = address;

			if (isPrologue(at))
				at -= 16;
			else
				at -= (at % 16);

			while (!isPrologue(at))
				at -= 16;

			return at;
		}

		uintptr_t getPrologue(const uintptr_t address)
		{
			return (isPrologue(address)) ? address : prevPrologue(address);
		}

		#if _WIN64
		MEMORY_BASIC_INFORMATION getPage(const uintptr_t location)
		{
			MEMORY_BASIC_INFORMATION page = { 0 };
			VirtualQueryEx(hProcess, reinterpret_cast<void*>(location), &page, sizeof(page));
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
			uint8_t* buffer = new uint8_t[count];
			ReadProcessMemory(hProcess, reinterpret_cast<void*>(location), buffer, count, &nbytes);
			std::string result = "";
			for (size_t i = 0; i < count; i++)
			{
				if (!((buffer[i] >= 0x20 && buffer[i] <= 0x7F) || buffer[i] == '\n' || buffer[i] == '\r' || buffer[i] == '\b' || buffer[i] == '\t'))
					break;

				result += static_cast<char>(buffer[i]);
			}
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