#pragma once
#include <Windows.h>
#include <any>
#include <vector>
#include <cstdint>
#include <intrin.h>

#if INTPTR_MAX == INT64_MAX
#define FUNCTION_STACK_VALUE 0x123456ABCDEF
#elif INTPTR_MAX == INT32_MAX
#define FUNCTION_STACK_VALUE 0x1234ABCD
#endif
#define FUNCTION_WRAP_BEGIN optimize("", off)
#define FUNCTION_WRAP_END optimize("", on)
#define INCLUDE_MARKERS_BEGIN optimize( "g", off )
#define INCLUDE_MARKERS_END optimize( "g", on )
#define GET_FUNCTION_STACK(s) void** s = reinterpret_cast<void**>(FUNCTION_STACK_VALUE);
#define MAKE_STRING(s, varname, lbl) auto varname = s; _MARK_STRING(lbl)
#define MAKE_WSTRING(s, varname, lbl) auto varname = s; _MARK_WSTRING(lbl)
#define GET_FUNCTION(f) f; _MARK_GET_FUNCTION()
#define MARK_END_FUNCTION _MARK_END_FUNCTION()

#define _MARK_GET_FUNCTION1(label) goto label
#define _MARK_GET_FUNCTION2(label) __nop();__nop();
#define _MARK_GET_FUNCTION3(label) label: void
#define _MARK_GET_FUNCTION() _MARK_GET_FUNCTION1(Random<int>()); \
_MARK_GET_FUNCTION2(randomLabel); \
_MARK_GET_FUNCTION3(randomLabel);

#define _MARK_END_FUNCTION1(label) goto label
#define _MARK_END_FUNCTION2(label) __halt();__halt();
#define _MARK_END_FUNCTION3(label) label: void
#define _MARK_END_FUNCTION() _MARK_END_FUNCTION1(randomLabel); \
_MARK_END_FUNCTION2(randomLabel); \
_MARK_END_FUNCTION3(randomLabel);

#define _MARK_STRING1(label) goto label
#define _MARK_STRING2(label) __nop();__halt();
#define _MARK_STRING3(label) label: void
#define _MARK_STRING(randomLabel) _MARK_STRING1(randomLabel); \
_MARK_STRING2(randomLabel); \
_MARK_STRING3(randomLabel);

#define _MARK_WSTRING1(label) goto label
#define _MARK_WSTRING2(label) __halt();__nop();
#define _MARK_WSTRING3(label) label: void
#define _MARK_WSTRING(randomLabel) _MARK_WSTRING1(randomLabel); \
_MARK_WSTRING2(randomLabel); \
_MARK_WSTRING3(randomLabel);

namespace Seraph
{
	namespace MemUtil
	{
		constexpr size_t FIND_END_MARKER = 0;

		// Please disable the following:
		// C/C++ --> Code Generation --> Security Check: Disable Security Check (/GS-)
		// 
		// The size of the function at `location` (in this current
		// process) will be calculated, and inserted into the other 
		// process.
		// The function you're injecting must follow these guidelines:
		// 1. Any/all functions you wish to call must be transferred over through the `data` arg
		// 2. 

		uintptr_t injectFunction(const HANDLE attachedHandle, uintptr_t location, void* function, const size_t functionSize, std::vector<std::any>data = { });
		uintptr_t injectFunction(const HANDLE attachedHandle, uintptr_t location, void* function, std::vector<std::any>data = { });
	}
}