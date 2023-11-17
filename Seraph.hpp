// Written by TheSeaweedMonster, 09/13/2023
// Leave these credits please
// And thank you
#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <unordered_map>

namespace Seraph
{
    enum class TargetArchitecture  { ARM, x86, x64 };

    // Formatted exception for compilation/parser errors
    //
    class SeraphException : public std::exception
    {
    protected:
        std::string message;
    public:
        inline SeraphException(const char* fmt, ...)
        {
            va_list vaArgList;
            char vfmt[256];

            __crt_va_start(vaArgList, fmt);
            vsnprintf_s(vfmt, 256, fmt, vaArgList);
            __crt_va_end(vaArgList);

            message = std::string(vfmt);
        }

        inline char* what()
        {
            return const_cast<char*>(message.c_str());
        }
    };

    // Generic wrapper for an std::vector<uint8_t>
    //
    class ByteStream : public std::vector<uint8_t>
    {
        size_t pos = 0;
    public:
        ByteStream(void) = default;
        ByteStream(const std::vector<uint8_t>& s) { *this = s; }
        ByteStream(const ByteStream& s){ *this = s; }

        inline ByteStream& operator<<(const uint8_t b)
        {
            push_back(b);
            return *this;
        }
        
        inline ByteStream& operator=(const ByteStream& o)
        {
            resize(o.size());
            memcpy(const_cast<uint8_t*>(&data()[0]), &o.data()[0], o.size());
            return *this;
        }
        
        inline ByteStream& operator=(const std::vector<uint8_t>& o)
        {
            resize(o.size());
            if (!o.empty())
                memcpy(const_cast<uint8_t*>(&data()[0]), &o[0], o.size());
            return *this;
        }
        
        inline bool operator==(ByteStream& o)
        {
            if (o.size() != size()) return false;

            for (size_t i = 0; i < o.size(); i++)
                if (data()[i] != o.data()[i])
                    return false;

            return true;
        }
        
        inline bool operator!=(const ByteStream& o)
        {
            return !(*this == o);
        }

        inline uint8_t operator++(const int)
        {
            return next();
        }

        /// <summary>
        /// Sets the byte value at the ith index of the stream to b
        /// </summary>
        /// <param name="i">index</param>
        /// <param name="b">new value</param>
        /// <returns>void</returns>
        const void set(const size_t i, const uint8_t b)
        {
            if (size() > i)
                *const_cast<uint8_t*>(&data()[i]) = b;
        }

        const void add(const uint8_t b)
        {
            *this << b;
        }

        const void add(const std::vector<uint8_t>& b)
        {
            for (size_t i = 0; i < b.size(); i++)
                *this << b[i];
        }

        /// <summary>
        /// Removes the last element in the stream
        /// </summary>
        /// <param name="count">number of times to remove the last element</param>
        void pop(const size_t count = 1)
        {
            for (size_t i = 0; i < count; i++)
                pop_back();
        }
        
        /// <summary>
        /// Returns the byte at the current index in the stream, and increases the current position
        /// </summary>
        /// <returns></returns>
        const uint8_t next()
        {
            return (size() > pos) ? data()[pos++] : 0;
        }

        // Returns the byte at the previous index in the stream
        const uint8_t prev()
        {
            if (empty()) return 0;
            return (size() > pos && pos > 0) ? data()[pos - 1] : data()[0];
        }
        
        // Miscellaneous / Self-explanatory
        // 
        const uint8_t current()
        {
            return (size() > pos) ? data()[pos] : 0;
        }

        const uint8_t* pcurrent()
        {
            return reinterpret_cast<uint8_t*>(const_cast<uint8_t*>(data()) + pos);
        }

        const size_t getpos()
        {
            return pos;
        }

        const bool good()
        {
            return (size() > pos);
        }

        void setpos(const size_t i)
        {
            pos = i;
        }

        const void skip(const size_t count)
        {
            pos += count;
        }
    };

    struct OpInfo_x86
    {
        std::string encoding;
        std::string opcodeName;
        std::vector<uint8_t> opTypes;
        std::vector<std::string> opTypeNames;
        std::string description;
        std::string mode;
        std::vector<uint8_t> baseSequence;
    };

    // ===================================================
    // ==========   Instruction Set Templates   ==========
    //
    template <typename T_OP>
    struct GenericOpcode
    {
        size_t len = 0;
        std::string text = "";
        std::string desc = "";

        uint32_t prefix = 0;
        uint32_t segment = 0;
        uint32_t flags = 0;

        std::vector<uint8_t> bytes = {};
        std::vector<T_OP> operands = {};

        OpInfo_x86* extendedInfo = nullptr;

        T_OP src() { return operands.empty() ? T_OP() : operands.front(); };
        T_OP dest() { return (operands.size() < 2) ? T_OP() : operands[1]; };
    };

    struct BaseSet_x86_64
    {
        // Prefix flags for the user
        static const uint16_t PRE_REPE      = 0x0001;
        static const uint16_t PRE_REPNE     = 0x0002;
        static const uint16_t PRE_LOCK      = 0x0004;
        static const uint16_t PRE_SEG_CS    = 0x0008;
        static const uint16_t PRE_SEG_SS    = 0x0010;
        static const uint16_t PRE_SEG_DS    = 0x0020;
        static const uint16_t PRE_SEG_ES    = 0x0040;
        static const uint16_t PRE_SEG_FS    = 0x0080;
        static const uint16_t PRE_SEG_GS    = 0x0100;
        static const uint16_t PRE_REX       = 0x0200;
        static const uint16_t PRE_OPSOR1    = 0x0400; // Operand Size Override
        static const uint16_t PRE_OPSOR2    = 0x0800; // (...more information needed)
       
        // Basic filters
        static const uint32_t OP_NONE       = 0x00000000;
        static const uint32_t OP_SRC_ONLY   = 0x00000001;
        static const uint32_t OP_SRC_DEST   = 0x00000002;
        static const uint32_t OP_RM         = 0x00000004;
        static const uint32_t OP_SIB        = 0x00000008;
        static const uint32_t OP_IMM8       = 0x00000010;
        static const uint32_t OP_IMM16      = 0x00000020;
        static const uint32_t OP_IMM32      = 0x00000040;
        static const uint32_t OP_IMM64      = 0x00000080;
        static const uint32_t OP_DISP8      = 0x00000100;
        static const uint32_t OP_DISP16     = 0x00000200;
        static const uint32_t OP_DISP32     = 0x00000400;
        static const uint32_t OP_DISP64     = 0x00000800;
        static const uint32_t OP_R8         = 0x00001000;
        static const uint32_t OP_R16        = 0x00002000;
        static const uint32_t OP_R32        = 0x00004000;
        static const uint32_t OP_R64        = 0x00008000;
        static const uint32_t OP_XMM        = 0x00010000;
        static const uint32_t OP_MM         = 0x00020000;
        static const uint32_t OP_ST         = 0x00040000;
        static const uint32_t OP_SREG       = 0x00080000;
        static const uint32_t OP_DR         = 0x00100000;
        static const uint32_t OP_CR         = 0x00200000;

        enum class Symbols
        {
            not_set,        // Placeholder - not set
            al,             // 8-bit registers
            bl,
            cl,
            dl,
            ah,
            bh,
            ch,
            dh,
            ax,             // 16-bit registers
            cx,
            dx,
            bx,
            sp,
            bp,
            si,
            di,
            eax,            // 32-bit registers
            ecx,
            edx,
            ebx,
            esp,
            ebp,
            esi,
            edi,
            rax,            // 64-bit registers
            rcx,
            rdx,
            rbx,
            rsp,
            rbp,
            rsi,
            rdi,
            cs,             // Segment registers
            ds,
            es,
            fs,
            gs,
            ss,
            hs,
            is,
            cri,            // Control registers
            dri,            // Debug registers
            one,            // When the number "1" is present in the operand -- for instructions that perform an operation once
            rel8,           // A relative address in the range from 128 bytes before the end of the instruction to 127 bytes after the end of the instruction
            rel16,          // A 16-bit relative address within the same code segment as the instruction.
            rel32,          // A 32-bit relative address within the same code segment as the instruction.
            rel64,          // ### x64 mode ###
            ptr16_16,       // A far pointer; The value on the left is a 16-bit selector or value destined for the code segment reg. The value to the right corresponds to the offset within the destination segment
            ptr16_32,       // A far pointer; Same as ptr16_16 but with a 32-bit offset
            r8,             // One of the byte general-purpose registers AL, CL, DL, BL, AH, CH, DH, or BH.
            r16,            // One of the word general-purpose registers AX, CX, DX, BX, SP, BP, SI, or DI.
            r16_32,         // r32 by default, r16 depending on operand size prefix
            r32,            // One of the doubleword general-purpose registers EAX, ECX, EDX, EBX, ESP, EBP, ESI, or EDI.
            r64,            // ### x64 Mode ###
            imm8,           // An immediate byte value -- a signed number between –128 and +127 inclusive.
            imm16,          // An immediate word value between –32,768 and +32,767 inclusive. 
            imm32,          // An immediate doubleword value between +2,147,483,647 and –2,147,483,648 inclusive.
            imm64,          // ### x64 Mode ###
            rm8,            // A byte operand that is either the contents of a byte general-purpose register (AL, BL, CL, DL, AH, BH, CH, and DH), or a byte from memory.
            rm16,           // A word general-purpose register or memory operand (AX, BX, CX, DX, SP, BP, SI, and DI).
            rm16_32,        // rm32 by default. rm16 depending on operand size prefix
            rm32,           // A doubleword general-purpose register or memory operand (EAX, EBX, ECX, EDX, ESP, EBP, ESI, and EDI).
            rm64,            // ### x64 Mode ###
            m,              // A 16- or 32-bit operand in memory
            m8,             // A byte operand in memory, usually expressed as a variable or array name, but pointed to by the DS:(E)SI or ES:(E)DI registers. This nomenclature is used only with the string instructions and the XLAT instruction.
            m16,            // A word operand in memory, usually expressed as a variable or array name, but pointed to by the DS:(E)SI or ES:(E)DI registers. This nomenclature is used only with the string instructions.
            m32,            // A doubleword operand in memory, usually expressed as a variable or array name, but pointed to by the DS:(E)SI or ES:(E)DI registers. This nomenclature is used only with the string instructions.
            m64,            // A memory quadword operand in memory. This nomenclature is used only with the CMPXCHG8B instruction.
            m128,           // A memory double quadword operand in memory. This nomenclature is used only with the Streaming SIMD Extensions
            m16_16,         // A far pointer; Left: pointer's segment selector. Right: 16-bit offset from segment
            m16_32,         // A far pointer; Left: pointer's segment selector. Right: 32-bit offset from segment
            m16and16,       // The m16&16 and m32&32 operands are used by the BOUND instruction to provide an operand w/ an upper and lower bounds for array indices.
            m16and32,       // The m16&32 operand is used by LIDT and LGDT to provide a word with which to load the limit field, and a dword with which to load the base field of the corresponding GDTR and IDTR registers.
            m32and32,       // ^
            moffs8,         // A simple memory variable (memory offset) of type byte, word, or doubleword used by some variants of the MOV instruction.  The actual address is given by a simple offset relative to the segment base. No ModR/M byte is used.
            moffs16,        // ^ 16 bit
            moffs32,        // ^ 32 bit
            moffs64,        // ### x64 Mode ###
            sreg,           // A segment register. The segment register bit assignments are ES=0, CS=1, SS=2, DS=3, FS=4, and GS=5
            m32real,        // A single-, double-, and extended-real (respectively*) floating-point operand in memory
            m64real,        // *
            m80real,        // *
            m16int,         // A word-, short-, and long-integer (respectively*) floating-point operand in memory.
            m32int,         // *
            m64int,         // *
            m80dec,
            m80bcd,
            st0,            // (or ST) - The top element of the FPU register stack.
            sti,            // The ith element from the top of the FPU register stack. (i = 0 through 7)
            mm,             // An MMX™ technology register. The 64-bit MMX™ technology registers are: MM0 through MM7
            mm2,            // Indicates the instruction uses xmm register(s) and does not use mod. (0xC0+)
            xmm,            // A SIMD floating-point register. The 128-bit SIMD floating-point registers are: XMM0 through XMM7.
            xmm2,           // Indicates the instruction uses xmm register(s) and does not use mod. (0xC0+)
            mm_m32,         // The low order 32 bits of an MMX™ technology register or a 32-bit memory operand. The 64-bit MMX™ technology registers are: MM0 through MM7
            mm_m64,         // An MMX™ technology register or a 64-bit memory operand. The 64-bit MMX™ technology registers are: MM0 through MM7.
            xmm_m32,        // A SIMD floating-points register or a 32-bit memory operand. The 128-bit SIMD floating-point registers are XMM0 through XMM7
            xmm_m64,        // A SIMD floating-point register or a 64-bit memory operand. The 64-bi SIMD floating-point registers are XMM0 through XMM7
            xmm_m128,       // A SIMD floating-point register or a 128-bit memory operand. The 128-bit SIMD floating-point registers are XMM0 through XMM7
            m14_28byte,     // used with FSTENV
            m2byte,         // used with FSTCW//FSTSW
            m94_108byte,    // used with FSAVE
            m512byte        // used with FXSAVE/FXRSTOR
        };

        // To-do: some of these encodings are redundant and indicated by
        // the format of the instruction
        enum class OpEncoding
        {
            // Placeholder -- No format used.
            none,
            /* A digit between 0 and 7 indicates that the ModR/M byte of the instruction uses
            only the r/m (register or memory) operand. The reg field contains the digit that provides an
            extension to the instruction's opcode */
            digit,
            /* Indicates that the ModR/M byte of the instruction contains both a register operand and an r/m operand. */
            r,
            /* A 1-byte (cb), 2-byte (cw), 4-byte (cd), or 6-byte (cp) value following the
            opcode that is used to specify a code offset and possibly a new value for the code segment
            register. */
            cb,
            cw,
            cd,
            cp,
            /* A 1 - byte(ib), 2 - byte(iw), or 4 - byte(id) immediate operand to the instruction
            that follows the opcode, ModR/M bytes or scale-indexing bytes. The opcode determines if
            the operand is a signed value. All words and doublewords are given with the low-order
            byte first. */
            ib,
            iw,
            id,
            /* A register code, from 0 through 7, added to the hexadecimal byte given at
            the left of the plus sign to form a single opcode byte. The register codes are given in Table
            3-1. */
            rb,
            rw,
            rd,
            /* A number used in floating-point instructions when one of the operands is ST(i) from
            the FPU register stack. The number i (which can range from 0 to 7) is added to the
            hexadecimal byte given at the left of the plus sign to form a single opcode byte */
            i,
            // Used to denote a different instruction depending on the RM byte
            m0,
            m1,
            m2,
            m3,
            m4,
            m5,
            m6,
            m7
        };

        static const uint32_t OPS_NONE = 0;
        static const uint32_t OPS_DEFAULT_64_BITS = 0x00000001;
        static const uint32_t OPS_REMOVED_X64 = 0x00000002;
        static const uint32_t OPS_IS_PREFIX = 0x00000004;
        static const uint32_t OPS_16MODE = 0x00000008;
        static const uint32_t OPS_PRE_F3 = 0x00000010;
        static const uint32_t OPS_EXTEND_IMM64 = 0x00000020;

        struct OpData
        {
            std::vector<uint8_t> code = {};
            std::vector<OpEncoding> entries = {};
            std::vector<BaseSet_x86_64::Symbols> symbols = {};
            uint32_t settings = 0;
        };

        struct OpRef
        {
            OpData extData;
            std::string opCodeName;
            std::string opCodeDescription;
        };

        struct Operand
        {
            uint32_t flags = 0;
            Symbols opmode = Symbols::not_set;
            uint8_t bitSize = 0;
            uint8_t immSize = 0;
            uint8_t regExt = 0;
            uint8_t mul = 0;
            uint8_t segment = 0;
            uint8_t hasMod = 0;

            std::vector<uint8_t> regs = {};
            std::vector<std::string> pattern = {}; // reserved

            union
            {
                uint8_t imm8 = 0;
                uint16_t imm16;
                uint32_t imm32;
                uint64_t imm64;
            };
            union
            {
                uint8_t rel8 = 0;
                uint16_t rel16;
                uint32_t rel32;
                uint64_t rel64;
            };
            union
            {
                uint8_t disp8 = 0;
                uint16_t disp16;
                uint32_t disp32;
                uint64_t disp64;
            };
        };

        typedef GenericOpcode<Operand> Opcode;
    };

    struct BaseSet_ARM
    {
        // . . .

        struct Operand
        {
            uint32_t flags;
            std::vector<uint8_t> regs;
        };

        typedef GenericOpcode<Operand> Opcode;
    };



    // ===================================================
    // ==========   String-To-Binary Assembly   ==========
    //

    template <TargetArchitecture ArchType>
	class Assembler
	{
    protected:
        TargetArchitecture targetArch = ArchType;

        // Used to identify the correct bytecode to use
        // based on the instruction's name, type and format(s)
        std::unordered_map<std::string, std::vector<BaseSet_x86_64::OpData>> oplookup_x86_64;

        // Used to identify the correct prefix bytecode to use
        std::unordered_map<std::string, uint8_t> prelookup_x86_64;
    public:
        Assembler();

        // Parse assembly code string to raw instructions
        //std::vector<GenericOpcode> parse(const std::string& source);

        // Convert instructions into a stream of bytes, which
        // can be used for memory edits
        //ByteStream compile(const std::vector<Instruction>& source, const AssemblyOptions& options = Default);

        /// <summary>
        // Parses and converts assembly code string directly to
        // a stream of bytes.
        // Throws a SeraphException if there are errors.
        /// </summary>
        ByteStream compile(const std::string& source, const uintptr_t offset = 0);
	};




    // =====================================================
    // ====  First-Stage: Binary-To-String Disassembly  ====
    //
    enum class DisassemblyOptions
    {
        Default
    };

    template <TargetArchitecture ArchType>
    class Disassembler {};

    template <>
    class Disassembler<TargetArchitecture::x86>
	{
    protected:
        // Used to identify the correct bytecode to use
        // based on the instruction's name, type and format(s)
        std::vector<std::vector<BaseSet_x86_64::OpRef>> oplookup_x86_64;

        // Used to identify the correct prefix bytecode to use
        std::unordered_map<std::string, uint8_t> prelookup_x86_64;

        DisassemblyOptions options;
        ByteStream stream;
        uintptr_t startIndex = 0;
        uintptr_t codeOffset = 0;
    public:
        Disassembler();
        Disassembler(const DisassemblyOptions& _options);
        Disassembler(const ByteStream& _stream);
        Disassembler(const ByteStream& _stream, const DisassemblyOptions& _options);

        void use(const ByteStream& _stream) { stream = _stream; startIndex = stream.getpos(); }
        void reset() { stream.setpos(startIndex); }
        void setOffset(const uintptr_t _offset) { codeOffset = _offset; };

        BaseSet_x86_64::Opcode readNext();
    };

    template <>
    class Disassembler<TargetArchitecture::x64>
	{
    protected:
        // Used to identify the correct bytecode to use
        // based on the instruction's name, type and format(s)
        std::vector<std::vector<BaseSet_x86_64::OpRef>> oplookup_x86_64;

        // Used to identify the correct prefix bytecode to use
        std::unordered_map<std::string, uint8_t> prelookup_x86_64;

        DisassemblyOptions options;
        ByteStream stream;
        uintptr_t startIndex = 0;
        uintptr_t codeOffset = 0;
    public:
        Disassembler();
        Disassembler(const DisassemblyOptions& _options);
        Disassembler(const ByteStream& _stream);
        Disassembler(const ByteStream& _stream, const DisassemblyOptions& _options);

        void use(const ByteStream& _stream) { stream = _stream; startIndex = stream.getpos(); }
        void reset() { stream.setpos(startIndex); }
        void setpos(const size_t pos) { stream.setpos(startIndex + pos); }
        void setOffset(const uintptr_t _offset) { codeOffset = _offset; };

        BaseSet_x86_64::Opcode readNext();
    };

    template <>
    class Disassembler<TargetArchitecture::ARM>
	{
    protected:
        DisassemblyOptions options;
        ByteStream stream;
        uintptr_t offset = 0;
    public:
        Disassembler();
        Disassembler(const DisassemblyOptions& _options);
        Disassembler(const ByteStream& _stream) : stream(_stream), options(DisassemblyOptions::Default) {};
        Disassembler(const ByteStream& _stream, const DisassemblyOptions& _options) : stream(_stream), options(_options) {};

        BaseSet_ARM::Opcode readNext();
	};

    // =====================================================
    // ==== Final-Stage: Binary-To-String Decompilation ====
    //
    enum class DecompileOptions
    {
        Default
    };

    // Attempt to return human-readable code from disassembly.
    // Limitations:
    // Only supports x86 and x64
    // Goals:
    // Add support for ARM
    template <TargetArchitecture ArchType>
    std::string decompile(const ByteStream& source, const DecompileOptions& options = DecompileOptions::Default);
}
