#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <unordered_map>

namespace Seraph
{
    enum class TargetArchitecture  { ARM, x86, x64 };

    class ByteStream
    {
        size_t pos = 0;
        std::vector<uint8_t> content = {};
    public:
        ByteStream(void) = default;
        ByteStream(const std::vector<uint8_t>& s) { *this = s; }
        ByteStream(const ByteStream& s){ *this = s; }
        
        inline ByteStream& operator<<(const uint8_t b)
        {
            content.push_back(b);
            return *this;
        }
        
        inline ByteStream& operator=(const ByteStream& o)
        {
            content.resize(o.content.size());
            memcpy(&content[0], &o.content[0], o.content.size());
            return *this;
        }
        
        inline ByteStream& operator=(const std::vector<uint8_t>& o)
        {
            content.resize(o.size());
            if (!o.empty())
                memcpy(&content[0], &o[0], o.size());
            return *this;
        }
        
        inline bool operator==(const ByteStream& o)
        {
            if (o.content.size() != content.size()) return false;

            for (size_t i = 0; i < o.content.size(); i++)
                if (content[i] != o.content[i])
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

        const void set(const size_t i, const uint8_t b)
        {
            if (content.size() > i)
                content[i] = b;
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
        
        const uint8_t next()
        {
            return (content.size() > pos) ? content[pos++] : 0;
        }
        
        const uint8_t prev()
        {
            if (content.empty()) return 0;
            return (content.size() > pos && pos > 0) ? content[pos - 1] : content[0];
        }
        
        const uint8_t current()
        {
            return (content.size() > pos) ? content[pos] : 0;
        }

        const uint8_t* pcurrent()
        {
            return reinterpret_cast<uint8_t*>(content.data() + pos);
        }
        
        const size_t getpos()
        {
            return pos;
        }
        
        const bool good()
        {
            return (content.size() > pos);
        }

        const void reset()
        {
            setpos(0);
        }

        void setpos(const size_t i)
        {
            pos = i;
        }
        
        const size_t size()
        {
            return content.size();
        }
        
        const void skip(const size_t count)
        {
            pos += count;
        }
        
        const uint8_t* data()
        {
            return content.data();
        }
        
        void pop(const size_t count = 1)
        {
            for (size_t i = 0; i < count; i++)
            {
                content.pop_back();
            }
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

        uint32_t prefix = 0;
        uint32_t segment = 0;
        uint32_t flags = 0;
        std::vector<T_OP> operands = { };

        OpInfo_x86* extendedInfo;

        T_OP src() { return operands.empty() ? T_OP() : operands.front(); };
        T_OP dest() { return (operands.size() < 2) ? T_OP() : operands[1]; };
    };

    struct BaseSet_x86
    {
        enum class R8 : const uint8_t  { NotSet = -1, AH, AL, CH, CL, DH, DL, BH, BL /* SPL, BPL, SIL, DIL */ };
        enum class R16 : const uint8_t { NotSet = -1, AX, CX, DX, BX, SP, BP, SI, DI };
        enum class R32 : const uint8_t { NotSet = -1, EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI };

        // Prefix flags for the user
        static const uint16_t PRE_REPNE     = 0x0001;
        static const uint16_t PRE_REPE      = 0x0002;
        static const uint16_t PRE_66        = 0x0004;
        static const uint16_t PRE_67        = 0x0008;
        static const uint16_t PRE_LOCK      = 0x0010;

        static const uint16_t PRE_SEG_CS    = 0x0020;
        static const uint16_t PRE_SEG_SS    = 0x0040;
        static const uint16_t PRE_SEG_DS    = 0x0080;
        static const uint16_t PRE_SEG_ES    = 0x0100;
        static const uint16_t PRE_SEG_FS    = 0x0200;
        static const uint16_t PRE_SEG_GS    = 0x0400;
        
        // Prefix bytes (used internally)
        static const uint8_t B_LOCK         = 0xF0;
        static const uint8_t B_REPNE        = 0xF2;
        static const uint8_t B_REPE         = 0xF3;
        static const uint8_t B_66           = 0x66;
        static const uint8_t B_67           = 0x67;
        static const uint8_t B_SEG_CS       = 0x2E;
        static const uint8_t B_SEG_SS       = 0x36;
        static const uint8_t B_SEG_DS       = 0x3E;
        static const uint8_t B_SEG_ES       = 0x26;
        static const uint8_t B_SEG_FS       = 0x64;
        static const uint8_t B_SEG_GS       = 0x65;

        // Basic filters
        static const uint32_t OP_NONE       = 0x00000000;
        static const uint32_t OP_SRC_ONLY   = 0x00000001;
        static const uint32_t OP_SRC_DEST   = 0x00000002;
        static const uint32_t OP_RM         = 0x00000004;
        static const uint32_t OP_SIB        = 0x00000008;
        static const uint32_t OP_IMM8       = 0x00000010;
        static const uint32_t OP_IMM16      = 0x00000020;
        static const uint32_t OP_IMM32      = 0x00000040;
        static const uint32_t OP_DISP8      = 0x00000080;
        static const uint32_t OP_DISP16     = 0x00000100;
        static const uint32_t OP_DISP32     = 0x00000200;
        static const uint32_t OP_R8         = 0x00000400;
        static const uint32_t OP_R16        = 0x00000800;
        static const uint32_t OP_R32        = 0x00001000;
        static const uint32_t OP_XMM        = 0x00004000;
        static const uint32_t OP_MM         = 0x00008000;
        static const uint32_t OP_ST         = 0x00010000;
        static const uint32_t OP_SREG       = 0x00020000;
        static const uint32_t OP_DR         = 0x00040000;
        static const uint32_t OP_CR         = 0x00080000;

        enum class Symbols
        {
            not_set,        // Placeholder - not set
            rel8,           // A relative address in the range from 128 bytes before the end of the instruction to 127 bytes after the end of the instruction
            rel16,          // A 16-bit relative address within the same code segment as the instruction.
            rel32,          // A 32-bit relative address within the same code segment as the instruction.
            ptr16_16,       // A far pointer; The value on the left is a 16-bit selector or value destined for the code segment reg. The value to the right corresponds to the offset within the destination segment
            ptr16_32,       // A far pointer; Same as ptr16_16 but with a 32-bit offset
            r8,             // One of the byte general-purpose registers AL, CL, DL, BL, AH, CH, DH, or BH.
            r16,            // One of the word general-purpose registers AX, CX, DX, BX, SP, BP, SI, or DI.
            r32,            // One of the doubleword general-purpose registers EAX, ECX, EDX, EBX, ESP, EBP, ESI, or EDI.
            imm8,           // An immediate byte value -- a signed number between –128 and +127 inclusive.
            imm16,          // An immediate word value between –32,768 and +32,767 inclusive. 
            imm32,          // An immediate doubleword value between +2,147,483,647 and –2,147,483,648 inclusive.
            rm8,            // A byte operand that is either the contents of a byte general-purpose register (AL, BL, CL, DL, AH, BH, CH, and DH), or a byte from memory.
            rm16,           // A word general-purpose register or memory operand (AX, BX, CX, DX, SP, BP, SI, and DI).
            rm32,           // A doubleword general-purpose register or memory operand (EAX, EBX, ECX, EDX, ESP, EBP, ESI, and EDI).
            m,              // A 16- or 32-bit operand in memory
            m8,             // A byte operand in memory, usually expressed as a variable or array name, but pointed to by the DS:(E)SI or ES:(E)DI registers. This nomenclature is used only with the string instructions and the XLAT instruction.
            m16,            // A word operand in memory, usually expressed as a variable or array name, but pointed to by the DS:(E)SI or ES:(E)DI registers. This nomenclature is used only with the string instructions.
            m32,            // A doubleword operand in memory, usually expressed as a variable or array name, but pointed to by the DS:(E)SI or ES:(E)DI registers. This nomenclature is used only with the string instructions.
            m64,            // A memory quadword operand in memory. This nomenclature is used only with the CMPXCHG8B instruction.
            m128,           // A memory double quadword operand in memory. This nomenclature is used only with the Streaming SIMD Extensions
            m16_16,         // A far pointer; Left: pointer's segment selector. Right: 16-bit offset from segment
            m16_32,         // A far pointer; Left: pointer's segment selector. Right: 32-bit offset from segment
            // The m16&16 and m32&32 operands are used by the BOUND
            // instruction to provide an operand containing an upper and lower bounds for array indices.
            // The m16 & 32 operand is used by LIDT and LGDT to provide a word with which to load
            // the limit field, and a doubleword with which to load the base field of the corresponding
            // GDTR and IDTR registers.
            m16and16,       // A memory operand consisting of data item pairs whosesizes are indicated on the left and the right side of the ampersand. All memory addressing modes are allowed.
            m16and32,       // ^ 16 and 32
            m32and32,       // ^ 32 and 32
            moffs8,         // A simple memory variable (memory offset) of type byte, word, or doubleword used by some variants of the MOV instruction.  The actual address is given by a simple offset relative to the segment base. No ModR/M byte is used.
            moffs16,        // ^ 16 bit
            moffs32,        // ^ 32 bit
            sreg,           // A segment register. The segment register bit assignments are ES=0, CS=1, SS=2, DS=3, FS=4, and GS=5
            m32real,        // A single-, double-, and extended-real (respectively*) floating-point operand in memory
            m64real,        // *
            m80real,        // *
            m16int,         // A word-, short-, and long-integer (respectively*) floating-point operand in memory.
            m32int,         // *
            m64int,         // *
            st0,            // (or ST) - The top element of the FPU register stack.
            sti,            // The ith element from the top of the FPU register stack. (i = 0 through 7)
            mm,             // An MMX™ technology register. The 64-bit MMX™ technology registers are: MM0 through MM7
            xmm,            // A SIMD floating-point register. The 128-bit SIMD floating-point registers are: XMM0 through XMM7.
            mm_m32,         // The low order 32 bits of an MMX™ technology register or a 32-bit memory operand. The 64-bit MMX™ technology registers are: MM0 through MM7
            mm_m64,         // An MMX™ technology register or a 64-bit memory operand. The 64-bit MMX™ technology registers are: MM0 through MM7.
            xmm_m32,        // A SIMD floating-points register or a 32-bit memory operand. The 128-bit SIMD floating-point registers are XMM0 through XMM7
            xmm_m64,        // A SIMD floating-point register or a 64-bit memory operand. The 64-bi SIMD floating-point registers are XMM0 through XMM7
            xmm_m128,       // A SIMD floating-point register or a 128-bit memory operand. The 128-bit SIMD floating-point registers are XMM0 through XMM7
        };

        struct Operand
        {
            uint32_t flags = 0;
            Symbols opmode = Symbols::not_set;
            uint8_t mul = 0;
            std::vector<uint8_t> regs;
            std::vector<std::string> pattern; // reserved
            union
            {
                uint8_t imm8;
                uint16_t imm16;
                uint32_t imm32;
            };
            union
            {
                uint8_t rel8;
                uint16_t rel16;
                uint32_t rel32;
            };
            union
            {
                uint8_t disp8;
                uint16_t disp16;
                uint32_t disp32;
            };
        };

        typedef GenericOpcode<Operand> Opcode;
    };

    struct BaseSet_x64 : public BaseSet_x86
    {
        enum class R64 : const uint8_t { NotSet = 255u, RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI };
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
    public:
        Assembler(void) { }
        Assembler(const TargetArchitecture arch) : targetArch(arch) { }

        // Parse assembly code string to raw instructions
        //std::vector<GenericOpcode> parse(const std::string& source);

        // Convert instructions into a stream of bytes, which
        // can be used for memory edits
        //ByteStream compile(const std::vector<Instruction>& source, const AssemblyOptions& options = Default);

        // Parses and converts assembly code string directly to
        // a stream of bytes
        ByteStream compile(const std::string& source, const std::vector<std::pair<std::string, void*>>& locations = {});
	};




    // =====================================================
    // ====  First-Stage: Binary-To-String Disassembly  ====
    //
    enum class DisassemblyOptions
    {
        Default
    };

    template <TargetArchitecture ArchType>
    class Disassembler { };

    template <>
    class Disassembler<TargetArchitecture::x86>
	{
    protected:
        DisassemblyOptions options;
        ByteStream stream;
        uintptr_t offset;
        int pos = 0;
    public:
        Disassembler() : offset(0), stream(), options(DisassemblyOptions::Default) { void(); };
        Disassembler(const ByteStream& _stream) : offset(0), stream(_stream), options(DisassemblyOptions::Default) { void(); };
        Disassembler(const ByteStream& _stream, const DisassemblyOptions& _options) : offset(0), stream(_stream), options(_options) { void(); };
        Disassembler(const uintptr_t _address, const ByteStream& _stream) : offset(_address), stream(_stream), options(DisassemblyOptions::Default) { void(); };
        Disassembler(const uintptr_t _address, const ByteStream& _stream, const DisassemblyOptions& _options) : offset(_address), stream(_stream), options(_options) { void(); };

        BaseSet_x86::Opcode readNext();
	};

    template <>
    class Disassembler<TargetArchitecture::x64>
	{
    protected:
        DisassemblyOptions options;
        ByteStream stream;
        int pos = 0;
    public:
        Disassembler(void) = default;
        Disassembler(const ByteStream& _stream) : stream(_stream), options(DisassemblyOptions::Default) {};
        Disassembler(const ByteStream& _stream, const DisassemblyOptions& _options) : stream(_stream), options(_options) { };

        BaseSet_x64::Opcode readNext();
    };

    template <>
    class Disassembler<TargetArchitecture::ARM>
	{
    protected:
        DisassemblyOptions options;
        ByteStream stream;
        int pos = 0;
    public:
        Disassembler(void) = default;
        Disassembler(const ByteStream& _stream) : stream(_stream), options(DisassemblyOptions::Default) {};
        Disassembler(const ByteStream& _stream, const DisassemblyOptions& _options) : stream(_stream), options(_options) { };

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
