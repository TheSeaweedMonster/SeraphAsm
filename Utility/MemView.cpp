#include <Windows.h>
#include "MemView.hpp"
#include "MemUtil.hpp"
#include "../Seraph.hpp"
#include <conio.h>
#include <Psapi.h>
#include <iostream>
#include <codecvt>
#include <winternl.h>

std::pair<std::wstring, uintptr_t> getAssociatedModule(const uintptr_t location)
{
	std::pair<std::wstring, uintptr_t>closestModule = { std::wstring(), UINTPTR_MAX};

	for (const auto& mod : Seraph::MemUtil::getModules())
	{
		if (location >= reinterpret_cast<uintptr_t>(mod.second))
		{
			const auto dist = location - reinterpret_cast<uintptr_t>(mod.second);
			if (dist >= 0 && dist < (location - closestModule.second))
			{
				//MEMORY_BASIC_INFORMATION64 page = { 0 };
				//VirtualQueryEx(Seraph::MemUtil::hProcess, mod.second, reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&page), sizeof(page));

				//if (location >= page.BaseAddress && location < page.BaseAddress + page.RegionSize)
				//{
					const size_t pos = mod.first.find_last_of('\\') + 1;
					closestModule = { mod.first.substr(pos, mod.first.length() - pos), reinterpret_cast<uintptr_t>(mod.second)};
				//}
			}
		}
	}

	return closestModule;
}

std::pair<std::string, std::vector<uint8_t>> aobstring(const std::string& str)
{
	std::string mask = "";
	std::vector<uint8_t> bytes = {};
	uint8_t sh = 0, b = 0;
	for (char c : str)
	{
		if (c == ' ') continue;
		if (c == '?')
		{
			if (sh++)
			{
				mask += '?';
				bytes.push_back(0);
				sh = 0;
			}
			continue;
		}
		if (c >= 0x61 && c <= 0x66)
			c -= 0x20;
		if (c >= 0x41 && c <= 0x46)
			c -= (0x41 - 10);
		else if (c >= 0x30 && c <= 0x39)
			c -= 0x30;
		if (!sh++)
			b |= c << 4;
		else
		{
			mask += '.';
			bytes.push_back(b | c);
			b = 0;
			sh = 0;
		}
	}
	return { mask, bytes };
}

namespace Seraph
{
	namespace MemUtil
	{
		void MemView::start()
		{
			auto mode = (locations.empty()) ? MAINMENU_MODE : SELECTION_MODE;
			auto scanMode = 0;
			bool hexView = true;
			bool refresh = true;
			uint8_t infoMode = 0;

			uint8_t* buffer = nullptr;
			size_t bufferIndex = 0;

			Disassembler<TargetArchitecture::x64> dis64;
			BaseSet_x86_64::Opcode firstOpcode = { 0 };

			std::pair<std::string, std::vector<uint8_t>> aobmask = { std::string(), { } };

			selectionIndex = 0;

			if (locations.size() == 1)
			{
				mode = HEXVIEW_MODE;
				viewing = locations.front();
			}

			while (mode != EXIT_MODE)
			{
				int key = 0, keyPress = kbhit();
				if (!(keyPress || refresh))
				{
					Sleep(5);
					continue;
				}
				else if (keyPress)
				{
					key = getch();
					if (key == 0)
						key = getch();
					else if (key == 0xE0)
					{
						key = getch();
						switch (key)
						{
						case 'A': // code for arrow up
							key = VK_UP;
							break;
						case 'B': // code for arrow down
							key = VK_DOWN;
							break;
						case 'C': // code for arrow right
							key = VK_RIGHT;
							break;
						case 'D': // code for arrow left
							key = VK_LEFT;
							break;
						}
					}
				}

				refresh = false;

				system("cls");

				switch (key)
				{
				case 0x1B:
					locations.clear();
					selectionIndex = 0; // reset from hexview/etc. mode
					mode = MAINMENU_MODE;
					break;
				case 'g': // Go to mode is (should be) accessible at any time.
					mode = GOTO_MODE;
					refresh = true;
					break;
				}

				switch (mode)
				{
				case MAINMENU_MODE:
				{
					std::vector<std::string>menuOptions = {"Go to address", "Scan code", "Scan all", "View imports", "View peb", "Scan for caves", "Query memory regions"};
					printf("What's on the menu today?\n\n");

					bool showMenu = true;

					switch (tolower(key))
					{
					case 'w':
					case VK_UP:
						if (selectionIndex > 0)
							selectionIndex--;
						break;
					case 's':
					case VK_DOWN:
						if (selectionIndex < menuOptions.size() - 1)
							selectionIndex++;
						break;
					case 'd':
					case '\r':
					case '\n':
						switch (selectionIndex)
						{
						case 0: // Go to address
							refresh = true;
							mode = GOTO_MODE;
							break;
						case 1: // Scan code
							refresh = true;
							scanMode = SCAN_CODE;
							mode = SCANNER_MODE;
							break;
						case 2: // Scan all
							refresh = true;
							scanMode = SCAN_ALL;
							mode = SCANNER_MODE;
							break;
						case 3: // View imports
							showMenu = false;

							printf("\n\nHere are a list of dll imports used:\n\n");

							for (const auto& mod : getModules())
							{
								const auto pos = mod.first.find_last_of('\\') + 1;
								wprintf(L"[%p] %s\n", mod.second, mod.first.substr(pos, mod.first.length() - pos).c_str());
							}

							break;
						case 4: // View peb
						{
							showMenu = false;

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

									PEB mpeb = { 0 };
									PEB* peb = &mpeb;
									ReadProcessMemory(hProcess, pbi->PebBaseAddress, &mpeb, sizeof(PEB), nullptr);

									printf("\n\nProcess information: \n\n");
									printf("AffinityMask: %p\n", pbi->AffinityMask);
									printf("BasePriority: %p\n", pbi->BasePriority);
									printf("ExitStatus: %p\n", pbi->ExitStatus);
									printf("InheritedFromUniqueProcessId: %p\n", pbi->InheritedFromUniqueProcessId);
									printf("PebBaseAddress: %p\n", pbi->PebBaseAddress);
									printf("UniqueProcessId: %p\n", pbi->UniqueProcessId);

									printf("\n\nProcess environment block:\n\n", pbi->PebBaseAddress);
									printf("BeingDebugged: %02X\n", peb->BeingDebugged);
									printf("AtlThunkSListPtr: %p\n", peb->AtlThunkSListPtr);
									printf("AtlThunkSListPtr32: %p\n", peb->AtlThunkSListPtr32);
									printf("Ldr: %p\n", peb->Ldr);
									PEB_LDR_DATA ldrData = mread<PEB_LDR_DATA>(reinterpret_cast<uintptr_t>(peb->Ldr));
									printf("Ldr->InMemoryOrderModuleList: %p\n", ldrData.InMemoryOrderModuleList);
									printf("SessionId: %p\n", peb->SessionId);
									wprintf(L"ProcessParameters: %p\n", peb->ProcessParameters);
									RTL_USER_PROCESS_PARAMETERS userProcessParams = mread<RTL_USER_PROCESS_PARAMETERS>(reinterpret_cast<uintptr_t>(peb->ProcessParameters));
									wprintf(L"ProcessParameters->CommandLine: %p\n", userProcessParams.CommandLine);
									wprintf(L"ProcessParameters->ImagePathName: %p\n", userProcessParams.ImagePathName);
									printf("PostProcessInitRoutine: %p\n", peb->PostProcessInitRoutine);
								}
								else
								{
									printf("Failed to allocate memory on heap\n");
								}
							}
							else
							{
								printf("Failed to get ntdll\n");
							}

							break;
						}
						case 5: // Scan for caves
						{
							refresh = true;
							scanMode = SCAN_CODE;
							mode = SCAN_AOB_MODE;
							aobmask = { std::string(256, '.'), std::vector<uint8_t>(128, 0) };
							break;
						}
						case 6: // Query memory regions
						{
							showMenu = false;

							printf("\n\nRegions currently in use (with PAGE_EXECUTE flag):\n\n");

							MEMORY_BASIC_INFORMATION64 page = { 0 };
							SYSTEM_INFO info = { 0 };
							GetSystemInfo(&info);

							printf("Scanning...\n");

							for (uintptr_t at = 0; at < reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress); at += (page.RegionSize) ? page.RegionSize : 0x1000)
							{
								VirtualQueryEx(hProcess, reinterpret_cast<void*>(at), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&page), sizeof(page));

								if (page.State & MEM_COMMIT && page.Protect & EXECUTABLE_MEMORY)
								{
									const auto modData = getAssociatedModule(at);

									if (modData.first.empty())
										printf("Region: %p, size: %p\n", at, page.RegionSize);
									else
										wprintf(L"Region: %s+%p, size: %p\n", modData.first.c_str(), at - modData.second, page.RegionSize);
								}
							}

							break;
						}
						}

						selectionIndex = 0;
						break;
					}

					if (showMenu)
					{
						for (size_t i = 0; i < menuOptions.size(); i++)
						{
							if (i == selectionIndex)
								printf("->");
							else
								printf("  ");

							printf("%s\n", menuOptions[i].c_str());
						}

						printf("\n\n[W] - Up\n[S] - Down\n[ENTER] - Select option\n");
					}

					break;
				}
				case SCAN_AOB_MODE:
				{
					if (aobmask.second.empty())
						break;

					std::vector<uintptr_t>results;

					MEMORY_BASIC_INFORMATION64 page = { 0 };
					SYSTEM_INFO info = { 0 };
					GetSystemInfo(&info);

					printf("Scanning...");

					for (uintptr_t at = reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress); at < reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress); at += page.RegionSize)
					{
						VirtualQueryEx(hProcess, reinterpret_cast<void*>(at), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&page), sizeof(page));

						bool condition = false;

						switch (scanMode)
						{
						case SCAN_CODE:
							condition = ((page.State & MEM_COMMIT) && (page.Protect & EXECUTABLE_MEMORY));
							break;
						case SCAN_ALL:
							condition = ((page.State & MEM_COMMIT) && (page.Protect & READABLE_MEMORY));
							break;
						}

						if (condition)
						{
							const auto buffer = mread<uint8_t>(page.BaseAddress, page.RegionSize);

							// Search through the whole memory page
							for (size_t i = 0; i < page.RegionSize - aobmask.second.size();)
							{
								bool matched = true;

								for (size_t j = 0; j < aobmask.second.size(); j++)
								{
									if (buffer[i++] != aobmask.second[j] && aobmask.first[j] == '.')
									{
										matched = false;
										break;
									}
								}

								if (matched)
									results.push_back(at + i);
							}
						}

						if (!page.RegionSize)
							page.RegionSize = 0x1000;
					}

					printf("Scan finished\nResults: %i\n", results.size());
					Sleep(1000);

					mode = SELECTION_MODE;
					refresh = true;
					locations = results;

					break;
				}
				case SCANNER_MODE:
				{
					const std::vector<std::string>scanOptions = { "AOB", "String", "Int16", "Int32", "Int64", "Float", "Double" };

					switch (tolower(key))
					{
					case 'w':
					case VK_UP:
						if (selectionIndex > 0)
							selectionIndex--;
						break;
					case 's':
					case VK_DOWN:
						if (selectionIndex < scanOptions.size() - 1)
							selectionIndex++;
						break;
					case 'd':
					case '\r':
					case '\n':
					{
						refresh = true;

						aobmask.first.clear();
						aobmask.second.clear();

						std::string str;
						printf("Enter an AOB to scan:\n\n>");
						std::getline(std::cin, str);

						switch (selectionIndex)
						{
						case 0: // AOB
							aobmask = aobstring(str);
							mode = SCAN_AOB_MODE;
							break;
						case 1: // String
							for (const auto c : str)
							{
								aobmask.first += c;
								aobmask.second.push_back(c);
							}
							mode = SCAN_AOB_MODE;
							break;
						case 2: // Int16
						{
							uint16_t val = std::atoi(str.c_str());

							mode = SCAN_AOB_MODE;
							aobmask.first = std::string(sizeof(uint16_t), '.');

							for (size_t i = 0; i < sizeof(uint16_t); i++)
								aobmask.second.push_back(((i) ? val >> (i * 8) : val) & 0xff);
							break;
						}
						case 3: // Int32
						{
							uint32_t val = std::atoi(str.c_str());

							mode = SCAN_AOB_MODE;
							aobmask.first = std::string(sizeof(uint32_t), '.');

							for (size_t i = 0; i < sizeof(uint32_t); i++)
								aobmask.second.push_back(((i) ? val >> (i * 8) : val) & 0xff);
							break;
						}
						case 4: // Int64
						{
							uint64_t val = std::atoi(str.c_str());

							mode = SCAN_AOB_MODE;
							aobmask.first = std::string(sizeof(uint64_t), '.');

							for (size_t i = 0; i < sizeof(uint64_t); i++)
								aobmask.second.push_back(((i) ? val >> (i * 8) : val) & 0xff);
							break;
						}
						case 5: // Float
						{
							float_t val = std::atof(str.c_str());

							mode = SCAN_AOB_MODE;
							aobmask.first = std::string(sizeof(float_t), '.');

							uint8_t b[sizeof(float_t)];
							memcpy(&b, &val, sizeof(float_t));
							for (size_t i = 0; i < sizeof(float_t); i++)
								aobmask.second.push_back(b[i]);
							break;
						}
						case 6: // Double
						{
							double_t val = std::atof(str.c_str());

							mode = SCAN_AOB_MODE;
							aobmask.first = std::string(sizeof(double_t), '.');

							uint8_t b[sizeof(double_t)];
							memcpy(&b, &val, sizeof(double_t));
							for (size_t i = 0; i < sizeof(double_t); i++)
								aobmask.second.push_back(b[i]);
							break;
						}
						}

						break;
					}
					}

					for (size_t i = 0; i < scanOptions.size(); i++)
					{
						if (i == selectionIndex)
							printf("->");
						else
							printf("  ");

						printf("%s\n", scanOptions[i].c_str());
					}

					break;
				}
				case GOTO_MODE:
				{
					hexView = true;

					std::string addr;
					printf("Enter an address to jump to: ");
					std::getline(std::cin, addr);

					uintptr_t location = 0;
					const size_t p1 = addr.find('+');
					const size_t p2 = addr.find('-');

					if (addr.find('.') != std::string::npos)
					{
						std::wstring modName;
						std::string functionName;
						size_t offset = 0;

						if (p1 != std::wstring::npos)
							offset = std::strtoull(addr.substr(p1 + 1, addr.length() - (p1 + 1)).c_str(), nullptr, 16);

						if (p2 != std::wstring::npos)
							modName = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(addr.substr(0, p2));
						else if (p1 != std::wstring::npos)
							modName = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(addr.substr(0, p1));
						else
							modName = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(addr.c_str());

						if (p2 != std::wstring::npos)
						{
							if (p1 != std::wstring::npos)
								functionName = addr.substr(p2 + 2, p1 - (p2 + 2));
							else
								functionName = addr.substr(p2 + 2, addr.length() - (p2 + 2));
						}

						if (!modName.empty())
						{
							if (!functionName.empty())
								location = reinterpret_cast<uintptr_t>(GetProcAddress(getModule(modName), functionName.c_str())) + offset;
							else
								location = reinterpret_cast<uintptr_t>(getModule(modName)) + offset;
						}

						wprintf(L"Mod Name: %s\n", modName.c_str());
						printf("Function Name: %s\n", functionName.c_str());
						wprintf(L"Offset: %08X\n", offset);
					}
					else
					{
						location = std::strtoull(addr.c_str(), nullptr, 16);
					}

					//locations = { location };
					viewing = location;
					mode = HEXVIEW_MODE;
					refresh = true;

					break;
				}
				case SELECTION_MODE:
				{
					switch (tolower(key))
					{
					case 'w':
					case VK_UP:
						if (selectionIndex > 0)
							selectionIndex--;
						break;
					case 's':
					case VK_DOWN:
						if (selectionIndex < locations.size() - 1)
							selectionIndex++;
						break;
					case 'd':
					case '\r':
					case '\n':
						refresh = true;
						viewing = locations[selectionIndex];
						mode = HEXVIEW_MODE;
						break;
					case 'g':
						mode = GOTO_MODE;
						refresh = true;
						break;
					}

					if (mode != SELECTION_MODE)
						break;

					for (size_t j = 0, i = 0; i < locations.size(); i++)
					{
						if (selectionIndex - 20 >= 0 && i <= selectionIndex - 20)
							continue;

						if (i == selectionIndex)
							printf("->");
						else
							printf("  ");

						printf("%p\n", locations[i]);

						if (j++ > 20)
						{
							printf("... %i more\n", locations.size() - selectionIndex);
							break;
						}
					}

					break;
				}
				case HEXVIEW_MODE:
				{
					switch (tolower(key))
					{
					case 'z':
					case VK_LEFT:
						if (!hexView)
						{
							if (bufferIndex > 0)
							{
								bufferIndex--;
								//viewing--;
							}
							break;
						}

						if (editSlotIndex == 1)
							editSlotIndex--;
						else
						{
							if (viewIndex > 0)
								viewIndex--;
							else
								viewing--;

							editSlotIndex = 1;
						}

						//editSlotIndex = 0;
						break;
					case 'x':
					case VK_RIGHT:
						if (!hexView)
						{
							bufferIndex += firstOpcode.len;
							//viewing++;
							break;
						}

						if (editSlotIndex == 0)
							editSlotIndex++;
						else
						{
							if (viewIndex < (maxRows * maxCols) - 1)
								viewIndex++;
							else
								viewing++;

							editSlotIndex = 0;
						}

						
						//editSlotIndex = 0;
						break;
					case 's':
					case VK_DOWN:
						if (!hexView)
						{
							bufferIndex += maxCols;
							//viewing += maxCols;
							break;
						}

						if (viewIndex < (maxRows * maxCols) - (maxCols + 1))
							viewIndex += maxCols;
						else
							viewing += maxCols;

						editSlotIndex = 0;
						break;
					case 'w':
					case VK_UP:
						if (!hexView)
						{
							if (bufferIndex >= maxCols)
							{
								bufferIndex -= maxCols;
								//viewing -= maxCols;
							}
							break;
						}

						if (viewIndex >= maxCols)
							viewIndex -= maxCols;
						else
							viewing -= maxCols;

						editSlotIndex = 0;
						break;
					case '\b':
						if (buffer) delete[] buffer;
						buffer = nullptr;
						bufferIndex = 0;

						refresh = true;
						viewing = 0;
						editSlotIndex = 0;
						mode = SELECTION_MODE;
						break;
					case 'g':
						if (buffer) delete[] buffer;
						buffer = nullptr;
						bufferIndex = 0;

						mode = GOTO_MODE;
						refresh = true;
						break;
					case 'i':
						infoMode++;
						if (infoMode > 2)
							infoMode = 0;
						refresh = true;
						break;
					case 'v':
						if (buffer) delete[] buffer;
						buffer = nullptr;
						bufferIndex = 0;

						hexView = !hexView;
						refresh = true;
						Sleep(500);
						break;
					}

					if (mode != HEXVIEW_MODE)
						break;

					if (hexView)
					{
						buffer = new uint8_t[maxRows * maxCols];
						memset(buffer, '\0', maxRows * maxCols);

						MEMORY_BASIC_INFORMATION64 page = { 0 };
						VirtualQueryEx(hProcess, reinterpret_cast<void*>(viewing), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&page), sizeof(page));
					
						if ((page.State & MEM_COMMIT) && (page.Protect & MemUtil::READABLE_MEMORY))
							ReadProcessMemory(hProcess, reinterpret_cast<void*>(viewing), buffer, maxRows * maxCols, nullptr);
						else
							printf("UNREADABLE MEMORY\n");

						bool doingEdit = false;
						char editValue = 0;

						if (key >= 0x30 && key <= 0x39)
						{
							doingEdit = true;
							editValue = (key - 0x30);
						}
						else if (key >= 0x41 && key <= 0x46)
						{
							doingEdit = true;
							editValue = (key - (0x41 - 10));
						}
						else if (key >= 0x61 && key <= 0x66)
						{
							doingEdit = true;
							editValue = (key - (0x61 - 10));
						}

						if (doingEdit)
						{
							switch (editSlotIndex)
							{
							case 0:
							{
								editSlotIndex++;
								const auto base = ((buffer[viewIndex] >> 4) << 4);
								const auto rem = buffer[viewIndex] - base;
								buffer[viewIndex] = (editValue << 4) | rem;
								mwrite<uint8_t>(viewing + viewIndex, buffer[viewIndex]);
								break;
							}
							case 1:
							{
								editSlotIndex = 0;
								const auto base = ((buffer[viewIndex] >> 4) << 4);
								buffer[viewIndex] = ((buffer[viewIndex] >> 4) << 4) | editValue;
								mwrite<uint8_t>(viewing + viewIndex, buffer[viewIndex]);
								viewIndex++;
								break;
							}
							}
						}

						//const auto closestModule = getAssociatedModule(viewing);
						//
						//if (closestModule.first.empty())
						//	printf("%p:\n\n", viewing);
						//else
						//	wprintf(L"%s+%p:\n\n", closestModule.first.c_str(), (viewing - closestModule.second));
					
						printf("%p: ", viewing);
						for (size_t i = 0; i < maxRows * maxCols; i++)
						{
							if ((i / maxCols) && i % maxCols == 0)
							{
								printf(" -- [");
								for (size_t j = 0; j < maxCols; j++)
									printf("%c", isalpha(buffer[(i - maxCols) + j]) ? static_cast<char>(buffer[(i - maxCols) + j]) : '.');
								printf("]\n%p: ", viewing + i);
							}

							if (i == viewIndex)
							{
								if (editSlotIndex == 0)
									printf("*%02X", buffer[i]);
								else
								{
									const auto b1 = buffer[i] >> 4;
									const auto b2 = buffer[i] - ((buffer[i] >> 4) << 4);
									printf(" %c*%c", static_cast<char>((b1 < 10) ? 0x30 + b1 : 0x41 + (b1 - 10)), static_cast<char>((b2 < 10) ? 0x30 + b2 : 0x41 + (b2 - 10)));
								}
							}
							else
							{
								printf(" %02X", buffer[i]);
							}
						}

						printf("\n\n");
						printf("byte		%d\n", buffer[viewIndex]);
						printf("short		%d\n", *reinterpret_cast<uint16_t*>(&buffer[viewIndex]));
						printf("int32		%d\n", *reinterpret_cast<uint32_t*>(&buffer[viewIndex]));
						printf("int64		%ld\n", *reinterpret_cast<uint64_t*>(&buffer[viewIndex]));
						printf("float		%f\n", *reinterpret_cast<float_t*>(&buffer[viewIndex]));
						printf("double		%lf\n", *reinterpret_cast<double_t*>(&buffer[viewIndex]));

						printf("\n\nAdditional options:\n[BKSPC] - Go back to selection\n[G] - Go to address\n[ESC] - Return to menu\n[V] - Switch view to disassembly\n");

						delete[] buffer;
						buffer = nullptr;
					}
					else
					{
						if (!buffer)
						{
							buffer = new uint8_t[2048];
							ReadProcessMemory(hProcess, reinterpret_cast<void*>(viewing), buffer, 2048, nullptr);

							std::vector<uint8_t> v(2048, 0);
							memcpy(&v[0], buffer, 2048);

							ByteStream stream(v);
							dis64.use(stream);
							dis64.setOffset(viewing);

							bufferIndex = 0;
						}

						//MEMORY_BASIC_INFORMATION64 page = { 0 };
						//VirtualQueryEx(hProcess, reinterpret_cast<void*>(viewing), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&page), sizeof(page));

						//if ((page.State & MEM_COMMIT) && (page.Protect & MemUtil::READABLE_MEMORY))
						//	ReadProcessMemory(hProcess, reinterpret_cast<void*>(viewing), buffer, 2048, nullptr);
						//else
						//	printf("UNREADABLE MEMORY\n");

						dis64.reset();
						dis64.setpos(bufferIndex);
						firstOpcode = dis64.readNext();

						auto op = firstOpcode;
						auto at = viewing + bufferIndex;

						for (int i = 0; i < 16; i++)
						{
							char s[64];
							sprintf(s, "%p: %s", at, op.text.c_str());
							printf(s);
							for (size_t i = strlen(s); i < 64; i++)
								printf(" ");

							switch (infoMode)
							{
							case 0:
								for (const auto b : op.bytes)
									printf("%02X ", b);
								break;
							case 1:
							{
								std::string data = "";

								for (const auto& operand : op.operands)
								{
									if (operand.imm32)
									{
										const auto offset = at + op.len + operand.imm32;
										
										MEMORY_BASIC_INFORMATION64 page = { 0 };
										VirtualQueryEx(hProcess, reinterpret_cast<void*>(offset), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&page), sizeof(page));

										if ((page.State & MEM_COMMIT) && (page.Protect & MemUtil::READABLE_MEMORY))
										{
											std::string str = "";
											for (const auto c : mreads(offset, 32))
												str += (c == '\n' || c == '\r') ? ' ' : c;
											if (str.size() > 3)
												data += "// \"" + str + "\"";
										}
									}
								}

								if (!data.empty())
									std::cout << data.c_str();
								break;
							}
							case 2:
								break;
							}

							printf("\n");
							at += op.len;
							op = dis64.readNext();
						}

						printf("\n\nAdditional options:\n[BKSPC] - Go back to selection\n[G] - Go to address\n[ESC] - Return to menu\n[I] - Switch informative mode\n   1.) Show instruction bytes\n   2.) Extra info\n   3.) Decompilation (N/A)\n[V] - Switch view to hexview\n");
					}

					break;
				}
				case EXIT_MODE:
					break;
				}

				Sleep(5);
			}

			if (buffer)
			{
				delete[] buffer;
			}
		}
	}
}
