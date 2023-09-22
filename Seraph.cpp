// Written by TheSeaweedMonster, 09/13/2023
// Leave these credits please
// And thank you
#include "Seraph.hpp"
#include <Windows.h>
#include <fstream>
#include <sstream>
#include <assert.h>
#include <iomanip>
#include <unordered_map>

static std::vector<std::string> split(const std::string& str, char delim)
{
    std::vector<std::string> strings;
    size_t start;
    size_t end = 0;
    while ((start = str.find_first_not_of(delim, end)) != std::string::npos)
    {
        end = str.find(delim, start);
        strings.push_back(str.substr(start, end - start));
    }
    return strings;
}

static std::string getCurrentDirectory()
{
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/") + 1;

    return std::string(buffer).substr(0, pos);
}

namespace Seraph
{
    // Referenced by the Assembler (x86 arch, shared by x64 arch)
    namespace Mnemonics
    {
        static const std::vector<std::string> R8 = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };
        static const std::vector<std::string> R16 = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
        static const std::vector<std::string> R32 = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
        static const std::vector<std::string> SREG = { "es", "cx", "ss", "ds", "fs", "gs", "hs", "is"};
        static const std::vector<std::string> STI = { "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"};
        static const std::vector<std::string> CRI = { "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7"};
        static const std::vector<std::string> DRI = { "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7"};
        static const std::vector<std::string> MM = { "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"};
        static const std::vector<std::string> XMM = { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"};
    };

    class Parser
    {
    protected:
        ByteStream stream;
    public:
        Parser(ByteStream& refStream) : stream(refStream) { };
        struct Node
        {
            enum class NodeType {
                Label,
                AsmNode
            } type;

            enum class Specifier {
                None,
                BytePtr,
                WordPtr,
                DwordPtr,
                QwordPtr,
                TwordPtr
            };

            std::string opPrefix = "";
            std::string opName = "";
            std::string label = "";

            Specifier sizeIndicator = Specifier::None;

            std::vector<std::string> operands = {};

            BaseSet_x86::Opcode opData;

            size_t streamIndex = 0;
            int32_t bitSize = 0;
            bool hasMod = false;
            int32_t modIndex = 0xFF;
        };

        struct Body
        {
            std::string label; // or memory location
            std::vector<Node> nodes;
        };

        struct Scope
        {
            std::vector<Body>bodies;
        };

        template<TargetArchitecture archType>
        static Scope compile(const std::string& source)
        {
            switch (archType)
            {
            case TargetArchitecture::x86:
            case TargetArchitecture::x64:
            {
                Scope scope = Scope();
                Body body = Body();
                Node currentNode = Node();

                if (source.empty())
                    return Scope();
                else
                {
                    std::vector<Scope>scopes = {};
                    std::string label = "";
                    bool isNewLine = false;

                    // Begin parsing...
                    size_t at = 0;
                    while (at < source.length())
                    {
                        const auto c = source[at];
                        switch (c)
                        {
                        case ';':
                            break;
                        case ',': // asm node, moving to next operand
                        case ' ':
                            if (!label.empty())
                            {
                                // Check for keywords used (at the operands)
                                if (c == ' ' && !isNewLine)
                                {
                                    const std::vector<std::string> keywords = { "none", "byte", "word", "dword", "qword", "tword" };

                                    size_t isKeyword, keywordIndex;

                                    for (keywordIndex = 0, isKeyword = 0; keywordIndex < keywords.size(); keywordIndex++)
                                    {
                                        if (label == keywords[keywordIndex])
                                        {
                                            isKeyword = true;
                                            break;
                                        }
                                    }

                                    if (isKeyword)
                                    {
                                        // Use the enumerator value (corresponds to the array index)
                                        currentNode.sizeIndicator = static_cast<Node::Specifier>(keywordIndex);

                                        at++; // Skip past the space character

                                        // Skip over "ptr" in the case of "byte ptr", "dword ptr", ...
                                        if (source.length() > at + 3)
                                        {
                                            if (source.substr(at, 3) == "ptr")
                                            {
                                                at += 3;
                                                while (source[at] == ' ') at++;
                                                at--;
                                            }
                                        }

                                        // The label has been used; start the next one
                                        label = "";
                                        break;
                                    }
                                }

                                // Exception or rule here for spaces ' ': allows us to do ', '
                                // between operands. because normally a space may indicate
                                // that we're going into the operands
                                if (c == ',' || (c == ' ' && !isNewLine))
                                {
                                    // asm node, moving to (next) operand
                                    if (currentNode.type == Node::NodeType::AsmNode)
                                        currentNode.operands.push_back(label);
                                }

                                // Is this the first word on a new line ?
                                if (c == ' ' && isNewLine)
                                {
                                    const std::vector<std::string> prefixes = { "lock", "rep", "repe", "repne" };
                                    bool isPrefix = false;

                                    // Check prefixes...In the case of a prefix there
                                    // is more than one space character in the instruction
                                    for (const auto& prefix : prefixes)
                                    {
                                        if (label == prefix)
                                        {
                                            isPrefix = true;

                                            // Set the prefix first
                                            currentNode.type = Node::NodeType::AsmNode;
                                            currentNode.opPrefix = label;

                                            break;
                                        }
                                    }

                                    if (!isPrefix)
                                    {
                                        // asm node, moving to operand(s) 
                                        currentNode.type = Node::NodeType::AsmNode;
                                        currentNode.opName = label;
                                        isNewLine = false;
                                    }
                                }

                                // The label has been used; start the next one
                                label = "";
                            }

                            break;
                        case '\n':
                        case '\r': // asm node is finished.
                            if (!label.empty() && currentNode.type == Node::NodeType::AsmNode)
                            {
                                currentNode.operands.push_back(label);
                                label = "";

                                body.nodes.push_back(currentNode);
                                currentNode = Node();
                            }

                            // Exception for single opcodes -- careful: not a label
                            if (!label.empty() && at > 0)
                            {
                                if (source[at - 1] != ':')
                                {
                                    currentNode.type = Node::NodeType::AsmNode;
                                    currentNode.opName = label;
                                    body.nodes.push_back(currentNode);
                                    currentNode = Node();
                                    label = "";
                                }
                            }

                            isNewLine = true;
                            break;
                        case ':': // initializing a label
                            if (isNewLine)
                            {
                                // if we want to expand the scope
                                //scope.bodies.push_back(body); // redundant?
                                //body = Body();
                                currentNode.type = Node::NodeType::Label;
                                currentNode.label = label;
                                body.nodes.push_back(currentNode);
                                //body.label = label;
                                currentNode = Node();
                                label = "";
                                isNewLine = false;
                                break;
                            }

                            label += c;
                            break;
                        case '[':
                        case ']':
                        case '+':
                        case '-':
                        case '*':
                            label += c;
                            break;
                        default:
                            // a-z or A-Z or 0-9 and accepted characters for operands 
                            if ((c >= 0x61 && c <= 0x7A) || (c >= 0x41 && c <= 0x5A) || (c >= 0x30 && c <= 0x39))
                                label += c;
                            break;
                        }

                        at++;
                    }

                    scope.bodies.push_back(body); // redundant?
                    scopes.push_back(scope);

                    return scope;
                }
            }
            }

            return Scope(); 
        }

    };

    BaseSet_x86::Opcode Disassembler<TargetArchitecture::x86>::readNext()
    {
        BaseSet_x86::Opcode opcode;

        // Coming soon!

        return opcode;
    }

    // Parses and converts assembly code string directly to
    // a stream of bytes
    ByteStream Assembler<TargetArchitecture::x86>::compile(const std::string& source, const uintptr_t offset)
    {
        ByteStream stream;

        // Initialize reference table for instructions,
        // and other opcode format information

        using Symbols = BaseSet_x86::Symbols;
        using Operand = BaseSet_x86::Operand;

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

        struct OpData
        {
            std::vector<uint8_t> code;
            std::vector<OpEncoding> entries;
            std::vector<Symbols> symbols;
        };


        // Used to identify the correct bytecode to use
        // based on the instruction's name, type and format(s)
        std::unordered_map<std::string, std::vector<OpData>> oplookup;

        // To-do: this should be reorganized. I will probably 
        // sort it by just opcode number rather than alphabetically
        oplookup["aaa"] = { { { 0x37 }, { } } };
        oplookup["aad"] = { { { 0xD5, 0x0A }, { }, { } } };
        oplookup["aam"] = { { { 0xD4, 0x0A }, { }, { } } };
        oplookup["aas"] = { { { 0x3F }, { } } };
        oplookup["add"] = {
            { { 0x00 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x01 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x01 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x02 }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x03 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x03 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x04 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x05 }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x05 }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m0, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m0, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m0, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m0, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["or"] = {
            { { 0x08 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x09 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x09 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x0A }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x0B }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x0C }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x0D }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x0D }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["adc"] = {
            { { 0x10 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x11 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x11 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x12 }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x13 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x13 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x14 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x15 }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x15 }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m2, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m2, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["sbb"] = {
            { { 0x18 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x19 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x19 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x1A }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x1B }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x1B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x1C }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x1D }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x1D }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m3, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m3, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m3, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m3, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["and"] = {
            { { 0x20 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x21 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x21 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x22 }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x23 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x23 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x24 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x25 }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x25 }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m4, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m4, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["sub"] = {
            { { 0x28 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x29 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x29 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x2A }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x2B }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x2B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x2C }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x2D }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x2D }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m5, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m5, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["xor"] = {
            { { 0x30 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x31 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x31 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x32 }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x33 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x33 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x34 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x35 }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x35 }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m6, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m6, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["cmp"] = {
            { { 0x38 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x39 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x3A }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x3B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x3C }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x3D }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x3D }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m7, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m7, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["cmps"] = {
            { { 0xA6 }, { }, { Symbols::m8, Symbols::m8 } },
            { { 0xA7 }, { }, { Symbols::m16, Symbols::m16 } },
            { { 0xA7 }, { }, { Symbols::m32, Symbols::m32 } },
        };
        oplookup["arpl"] = {
            { { 0x63 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
        };
        oplookup["bound"] = {
            { { 0x62 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x62 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["call"] = {
            { { 0xE8 }, { OpEncoding::cw }, { Symbols::rel16 } },
            { { 0xE8 }, { OpEncoding::cd }, { Symbols::rel32 } },
            { { 0x9A }, { OpEncoding::cd }, { Symbols::ptr16_16 } },
            { { 0x9A }, { OpEncoding::cp }, { Symbols::ptr16_32 } },
            { { 0xFF }, { OpEncoding::m2 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m2 }, { Symbols::rm32 } },
            { { 0xFF }, { OpEncoding::m3 }, { Symbols::m16_16 } },
            { { 0xFF }, { OpEncoding::m3 }, { Symbols::m16_32 } },
        };
        oplookup["cbw"] = { { { 0x98 }, { }, { } } };
        oplookup["clc"] = { { { 0xF8 }, { } } };
        oplookup["cld"] = { { { 0xFC }, { } } };
        oplookup["cli"] = { { { 0xFA }, { } } };
        oplookup["cmc"] = { { { 0xF5 }, { }, { } } };
        oplookup["cmovo"] = {
            { { 0x0F, 0x40 }, { OpEncoding::m0, OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x40 }, { OpEncoding::m0, OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovno"] = {
            { { 0x0F, 0x41 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x41 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovb"] = {
            { { 0x0F, 0x42 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x42 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovnb"] = {
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovae"] = {
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmove"] = {
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovz"] = {
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovne"] = {
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovnz"] = {
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovbe"] = {
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovna"] = {
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmova"] = {
            { { 0x0F, 0x47 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x47 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovs"] = {
            { { 0x0F, 0x48 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x48 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovns"] = {
            { { 0x0F, 0x49 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x49 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovp"] = {
            { { 0x0F, 0x4A }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4A }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovnp"] = {
            { { 0x0F, 0x4B }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovl"] = {
            { { 0x0F, 0x4C }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4C }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovnl"] = {
            { { 0x0F, 0x4D }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4D }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovng"] = {
            { { 0x0F, 0x4E }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4E }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cmovg"] = {
            { { 0x0F, 0x4F }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4F }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["cwd"] = { { { 0x99 }, { }, { } } };
        oplookup["daa"] = { { { 0x27 }, { } } };
        oplookup["das"] = { { { 0x2F }, { } } };
        oplookup["dec"] = {
            { { 0x48 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0xFE }, { OpEncoding::m1 }, { Symbols::rm8 } },
            { { 0xFF }, { OpEncoding::m1 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m1 }, { Symbols::rm32 } },
        };
        oplookup["div"] = {
            { { 0xF6 }, { OpEncoding::m6 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m6 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m6 }, { Symbols::rm32 } },
        };
        oplookup["enter"] = {
            { { 0xC8 }, { OpEncoding::iw }, { Symbols::imm16, Symbols::imm8 } }
        };
        oplookup["fcmovb"] = {
            { { 0xDA, 0xC0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fcmove"] = {
            { { 0xDA, 0xC8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fcmovbe"] = {
            { { 0xDA, 0xD0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fcmovu"] = {
            { { 0xDA, 0xD8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fild"] = {
            { { 0xDF }, { OpEncoding::m0 }, { Symbols::m16int } },
            { { 0xDB }, { OpEncoding::m0 }, { Symbols::m32int } },
            { { 0xDF }, { OpEncoding::m5 }, { Symbols::m64int } }
        };
        oplookup["fist"] = {
            { { 0xDF }, { OpEncoding::m2 }, { Symbols::m16int } },
            { { 0xDB }, { OpEncoding::m2 }, { Symbols::m32int } }
        };
        oplookup["fistp"] = {
            { { 0xDF }, { OpEncoding::m3 }, { Symbols::m16int } },
            { { 0xDB }, { OpEncoding::m3 }, { Symbols::m32int } },
            { { 0xDF }, { OpEncoding::m7 }, { Symbols::m64int } }
        };
        oplookup["fbld"] = {
            { { 0xDF }, { OpEncoding::m4 }, { Symbols::m80dec } }
        };
        oplookup["fbstp"] = {
            { { 0xDF }, { OpEncoding::m6 }, { Symbols::m80bcd } }
        };

        oplookup["fcmovnb"] = {
            { { 0xDB, 0xC0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fcmovne"] = {
            { { 0xDB, 0xC8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fcmovnbe"] = {
            { { 0xDB, 0xD0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fcmovnu"] = {
            { { 0xDB, 0xD8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fnclex"] = { { { 0xDB, 0xE2 }, { }, { } } };
        oplookup["fninit"] = { { { 0xDB, 0xE3 }, { }, { } } };
        oplookup["fucompp"] = { { { 0xDA, 0xE9 }, { }, { } } };
        oplookup["fucom"] = {
            { { 0xDD, 0xE0 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xDD, 0xE1 }, { }, { } }
        };
        oplookup["fucomi"] = {
            { { 0xDB, 0xE8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fucomip"] = {
            { { 0xDF, 0xE8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fcomip"] = {
            { { 0xDF, 0xF0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fucomp"] = {
            { { 0xDD, 0xE8 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xDD, 0xE9 }, { }, { } }
        };
        oplookup["fcomi"] = {
            { { 0xDB, 0xF0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup["fstenv"] = {
            { { 0x9B, 0xD9 }, { OpEncoding::m6 }, { Symbols::m14_28byte } }
        };
        oplookup["fstcw"] = {
            { { 0x9B, 0xD9 }, { OpEncoding::m7 }, { Symbols::m2byte } }
        };
        oplookup["fclex"] = { { { 0x9B, 0xDB, 0xE2 }, { }, { } } };
        oplookup["finit"] = { { { 0x9B, 0xDB, 0xE3 }, { }, { } } };
        oplookup["fsave"] = {
            { { 0x9B, 0xDD }, { OpEncoding::m6 }, { Symbols::m94_108byte } }
        };
        oplookup["fstsw"] = {
            { { 0x9B, 0xDD }, { OpEncoding::m7 }, { Symbols::m2byte } },
            { { 0x9B, 0xDF, 0xE0 }, { }, { Symbols::ax } }
        };
        oplookup["fadd"] = {
            { { 0xD8 }, { OpEncoding::m0 }, { Symbols::m32real } },
            { { 0xD8, 0xC0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC }, { OpEncoding::m0 }, { Symbols::m64real } },
            { { 0xDC, 0xC0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup["faddp"] = {
            { { 0xDE, 0xC0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xC1 }, { }, { } }
        };
        oplookup["fmulp"] = {
            { { 0xDE, 0xC8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xC9 }, { }, { } }
        };
        oplookup["fcompp"] = {
            { { 0xDE, 0xD9 }, { }, { } }
        };
        oplookup["fsubrp"] = {
            { { 0xDE, 0xE0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xE1 }, { }, { } }
        };
        oplookup["fsubp"] = {
            { { 0xDE, 0xE8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xE9 }, { }, { } }
        };
        oplookup["fdivrp"] = {
            { { 0xDE, 0xF0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xF1 }, { }, { } }
        };
        oplookup["fdivp"] = {
            { { 0xDE, 0xF8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xF9 }, { }, { } }
        };
        oplookup["fiadd"] = {
            { { 0xDE }, { OpEncoding::m0 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m0 }, { Symbols::m32int } },
        };
        oplookup["fmul"] = {
            { { 0xD8 }, { OpEncoding::m1 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m1 }, { Symbols::m64real } },
            { { 0xD8, 0xC8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xC8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup["fimul"] = {
            { { 0xDE }, { OpEncoding::m1 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m1 }, { Symbols::m32int } }
        };
        oplookup["fcom"] = {
            { { 0xD8 }, { OpEncoding::m2 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m2 }, { Symbols::m64real } },
            { { 0xD8, 0xD0 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xD8, 0xD1 }, { }, { } }
        };
        oplookup["ficom"] = {
            { { 0xDE }, { OpEncoding::m2 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m2 }, { Symbols::m32int } }
        };
        oplookup["fcomp"] = {
            { { 0xD8 }, { OpEncoding::m3 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m3 }, { Symbols::m64real } },
            { { 0xD8, 0xD8 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xD8, 0xD9 }, { }, { } }
        };
        oplookup["ficomp"] = {
            { { 0xDE }, { OpEncoding::m3 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m3 }, { Symbols::m32int } }
        };
        oplookup["fsub"] = {
            { { 0xD8 }, { OpEncoding::m4 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m4 }, { Symbols::m64real } },
            { { 0xD8, 0xE0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xE0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup["fisub"] = {
            { { 0xDE }, { OpEncoding::m4 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m4 }, { Symbols::m32int } }
        };
        oplookup["fsubr"] = {
            { { 0xD8 }, { OpEncoding::m5 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m5 }, { Symbols::m64real } },
            { { 0xD8, 0xE8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xE8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup["fisubr"] = {
            { { 0xDE }, { OpEncoding::m5 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m5 }, { Symbols::m32int } }
        };
        oplookup["fdiv"] = {
            { { 0xD8 }, { OpEncoding::m6 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m6 }, { Symbols::m64real } },
            { { 0xD8, 0xF0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xF0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup["fidiv"] = {
            { { 0xDE }, { OpEncoding::m6 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m6 }, { Symbols::m32int } }
        };
        oplookup["fdivr"] = {
            { { 0xD8 }, { OpEncoding::m7 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m7 }, { Symbols::m64real } },
            { { 0xD8, 0xF8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xF8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup["fidivr"] = {
            { { 0xDE }, { OpEncoding::m7 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m7 }, { Symbols::m32int } }
        };
        oplookup["fld"] = {
            { { 0xD9 }, { OpEncoding::m0 }, { Symbols::m32real } },
            { { 0xDD }, { OpEncoding::m0 }, { Symbols::m64real } },
            { { 0xD9, 0xC0 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xDB }, { OpEncoding::m5 }, { Symbols::m80real } }
        };
        oplookup["fst"] = {
            { { 0xD9 }, { OpEncoding::m2 }, { Symbols::m32real } },
            { { 0xDD }, { OpEncoding::m2 }, { Symbols::m64real } },
            { { 0xDD, 0xD0 }, { OpEncoding::i }, { Symbols::sti } }
        };
        oplookup["fstp"] = {
            { { 0xD9 }, { OpEncoding::m3 }, { Symbols::m32real } },
            { { 0xDB }, { OpEncoding::m7 }, { Symbols::m80real } },
            { { 0xDD }, { OpEncoding::m3 }, { Symbols::m64real } },
            { { 0xDD, 0xD8 }, { OpEncoding::i }, { Symbols::sti } }
        };
        oplookup["frstor"] = {
            { { 0xDD }, { OpEncoding::m4 }, { Symbols::m94_108byte } }
        };
        oplookup["fnsave"] = {
            { { 0xDD }, { OpEncoding::m6 }, { Symbols::m94_108byte } }
        };
        oplookup["fnstsw"] = {
            { { 0xDD }, { OpEncoding::m7 }, { Symbols::m2byte } },
            { { 0xDF, 0xE0 }, { }, { Symbols::ax } }
        };
        oplookup["ffree"] = {
            { { 0xDD, 0xC0 }, { OpEncoding::i }, { Symbols::sti } }
        };
        oplookup["fldenv"] = {
            { { 0xD9 }, { OpEncoding::m4 }, { Symbols::m14_28byte } }
        };
        oplookup["fldcw"] = {
            { { 0xD9 }, { OpEncoding::m5 }, { Symbols::m2byte } }
        };
        oplookup["fnstenv"] = {
            { { 0xD9 }, { OpEncoding::m6 }, { Symbols::m14_28byte } }
        };
        oplookup["fnstcw"] = {
            { { 0xD9 }, { OpEncoding::m7 }, { Symbols::m2byte } }
        };
        oplookup["fxch"] = {
            { { 0xD9, 0xC8 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xD9, 0xC9 }, { }, { } }
        };
        oplookup["fnop"] = { { { 0xD9, 0xD0 }, { }, { } } };
        oplookup["fchs"] = { { { 0xD9, 0xE0 }, { }, { } } };
        oplookup["fabs"] = { { { 0xD9, 0xE1 }, { }, { } } };
        oplookup["ftst"] = { { { 0xD9, 0xE4 }, { }, { } } };
        oplookup["fxam"] = { { { 0xD9, 0xE5 }, { }, { } } };
        oplookup["fld1"] = { { { 0xD9, 0xE8 }, { }, { } } };
        oplookup["fldl2t"] = { { { 0xD9, 0xE9 }, { }, { } } };
        oplookup["fldl2e"] = { { { 0xD9, 0xEA }, { }, { } } };
        oplookup["fldpi"] = { { { 0xD9, 0xEB }, { }, { } } };
        oplookup["fldlg2"] = { { { 0xD9, 0xEC }, { }, { } } };
        oplookup["fldln2"] = { { { 0xD9, 0xED }, { }, { } } };
        oplookup["fldz"] = { { { 0xD9, 0xEE }, { }, { } } };
        oplookup["f2xm1"] = { { { 0xD9, 0xF0 }, { }, { } } };
        oplookup["fyl2x"] = { { { 0xD9, 0xF1 }, { }, { } } };
        oplookup["fptan"] = { { { 0xD9, 0xF2 }, { }, { } } };
        oplookup["fpatan"] = { { { 0xD9, 0xF3 }, { }, { } } };
        oplookup["fxtract"] = { { { 0xD9, 0xF4 }, { }, { } } };
        oplookup["fprem1"] = { { { 0xD9, 0xF5 }, { }, { } } };
        oplookup["fdecstp"] = { { { 0xD9, 0xF6 }, { }, { } } };
        oplookup["fincstp"] = { { { 0xD9, 0xF7 }, { }, { } } };
        oplookup["fprem"] = { { { 0xD9, 0xF8 }, { }, { } } };
        oplookup["fyl2xp1"] = { { { 0xD9, 0xF9 }, { }, { } } };
        oplookup["fsqrt"] = { { { 0xD9, 0xFA }, { }, { } } };
        oplookup["fsincos"] = { { { 0xD9, 0xFB }, { }, { } } };
        oplookup["frndint"] = { { { 0xD9, 0xFC }, { }, { } } };
        oplookup["fscale"] = { { { 0xD9, 0xFD }, { }, { } } };
        oplookup["fsin"] = { { { 0xD9, 0xFE }, { }, { } } };
        oplookup["fcos"] = { { { 0xD9, 0xFF }, { }, { } } };
        oplookup["hlt"] = { { { 0xF4 }, { }, { } } };
        oplookup["inc"] = {
            { { 0x40 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0xFE }, { OpEncoding::m0 }, { Symbols::rm8 } },
            { { 0xFF }, { OpEncoding::m0 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m0 }, { Symbols::rm32 } },
        };
        oplookup["in"] = {
            { { 0xE4 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0xE5 }, { OpEncoding::ib }, { Symbols::ax, Symbols::imm8 } },
            { { 0xE5 }, { OpEncoding::ib }, { Symbols::eax, Symbols::imm8 } },
            { { 0xEC }, { }, { Symbols::al, Symbols::dx } },
            { { 0xED }, { }, { Symbols::ax, Symbols::dx } },
            { { 0xED }, { }, { Symbols::eax, Symbols::dx } }
        };
        oplookup["ins"] = {
            { { 0x6C }, { }, { Symbols::m8, Symbols::dx } },
            { { 0x6D }, { }, { Symbols::m16, Symbols::dx } },
            { { 0x6D }, { }, { Symbols::m32, Symbols::dx } }
        };
        oplookup["int3"] = { { { 0xCC }, { }, { } } };
        oplookup["int"] = {
            { { 0xCD }, { OpEncoding::ib }, { Symbols::imm8 } }
        };
        oplookup["into"] = { { { 0xCE }, { }, { } } };
        oplookup["iret"] = { { { 0xCF }, { }, { } } };
        oplookup["iretd"] = { { { 0xCF }, { }, { } } };
        oplookup["idiv"] = {
            { { 0xF6 }, { OpEncoding::m7 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m7 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m7 }, { Symbols::rm32 } },
        };
        oplookup["imul"] = {
            { { 0x69 }, { OpEncoding::r, OpEncoding::iw }, { Symbols::r16, Symbols::rm16, Symbols::imm16 } },
            { { 0x69 }, { OpEncoding::r, OpEncoding::id }, { Symbols::r32, Symbols::rm32, Symbols::imm32 } },
            { { 0x69 }, { OpEncoding::r, OpEncoding::iw }, { Symbols::r16, Symbols::imm16 } },
            { { 0x69 }, { OpEncoding::r, OpEncoding::id }, { Symbols::r32, Symbols::imm32 } },
            { { 0x6B }, { OpEncoding::r, OpEncoding::ib }, { Symbols::r16, Symbols::rm16, Symbols::imm8 } },
            { { 0x6B }, { OpEncoding::r, OpEncoding::ib }, { Symbols::r32, Symbols::rm32, Symbols::imm8 } },
            { { 0x6B }, { OpEncoding::r, OpEncoding::ib }, { Symbols::r16, Symbols::imm8 } },
            { { 0x6B }, { OpEncoding::r, OpEncoding::ib }, { Symbols::r32, Symbols::imm8 } },
            { { 0xF6 }, { OpEncoding::m5 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m5 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m5 }, { Symbols::rm32 } },
        };
        oplookup["jmp"] = {
            { { 0xEB }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0xE9 }, { OpEncoding::cw }, { Symbols::rel16 } },
            { { 0xE9 }, { OpEncoding::cd }, { Symbols::rel32 } },
            { { 0xEA }, { OpEncoding::cd }, { Symbols::ptr16_16 } },
            { { 0xEA }, { OpEncoding::cp }, { Symbols::ptr16_32 } },
            { { 0xFF }, { OpEncoding::m4 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m4 }, { Symbols::rm32 } },
            { { 0xFF }, { OpEncoding::m5 }, { Symbols::m16_16 } },
            { { 0xFF }, { OpEncoding::m5 }, { Symbols::m16_32 } },
        };
        oplookup["jo"] = {
            { { 0x70 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x80 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jno"] = {
            { { 0x71 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x81 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jb"] = {
            { { 0x72 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x82 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jae"] = {
            { { 0x73 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x83 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jnb"] = {
            { { 0x73 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x83 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["je"] = {
            { { 0x74 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x84 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jz"] = {
            { { 0x74 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x84 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jne"] = {
            { { 0x75 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x85 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jnz"] = {
            { { 0x75 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x85 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jbe"] = {
            { { 0x76 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x86 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jna"] = {
            { { 0x76 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x86 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["ja"] = {
            { { 0x77 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x87 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["js"] = {
            { { 0x78 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x88 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jns"] = {
            { { 0x79 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x89 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jp"] = {
            { { 0x7A }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8A }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jpo"] = {
            { { 0x7B }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8B }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jl"] = {
            { { 0x7C }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8C }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jnl"] = {
            { { 0x7D }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8D }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jle"] = {
            { { 0x7E }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8E }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jng"] = {
            { { 0x7E }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8E }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["jg"] = {
            { { 0x7F }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8F }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup["lahf"] = { { { 0x9F }, { } } };
        oplookup["leave"] = { { { 0xC9 }, { } } };
        oplookup["lea"] = {
            { { 0x8D }, { OpEncoding::r }, { Symbols::r16, Symbols::m } },
            { { 0x8D }, { OpEncoding::r }, { Symbols::r32, Symbols::m } },
        };
        oplookup["les"] = {
            { { 0xC4 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0xC4 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } }
        };
        oplookup["lds"] = {
            { { 0xC5 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0xC5 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } }
        };
        oplookup["lodsb"] = { { { 0xAC }, { } } };
        oplookup["lodsd"] = { { { 0xAD }, { } } };
        oplookup["loopne"] = { { { 0xE0 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup["loopnz"] = { { { 0xE0 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup["loope"] = { { { 0xE1 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup["loopz"] = { { { 0xE1 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup["loop"] = { { { 0xE2 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup["mov"] = {
            { { 0x88 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x89 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x89 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x8A }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x8B }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x8B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x8C }, { OpEncoding::r }, { Symbols::rm16, Symbols::sreg } },
            { { 0x8C }, { OpEncoding::r }, { Symbols::rm32, Symbols::sreg } },
            { { 0x8E }, { OpEncoding::r }, { Symbols::sreg, Symbols::rm16 } },
            { { 0x8E }, { OpEncoding::r }, { Symbols::sreg, Symbols::rm32 } },
            { { 0xA0 }, { }, { Symbols::al, Symbols::moffs8 } },
            { { 0xA1 }, { }, { Symbols::ax, Symbols::moffs16 } },
            { { 0xA1 }, { }, { Symbols::eax, Symbols::moffs32 } },
            { { 0xA2 }, { }, { Symbols::moffs8, Symbols::al } },
            { { 0xA3 }, { }, { Symbols::moffs16, Symbols::ax } },
            { { 0xA3 }, { }, { Symbols::moffs32, Symbols::eax } },
            { { 0xB0 }, { OpEncoding::rb }, { Symbols::r8, Symbols::imm8 } },
            { { 0xB8 }, { OpEncoding::rw }, { Symbols::r16, Symbols::imm16 } },
            { { 0xB8 }, { OpEncoding::rd }, { Symbols::r32, Symbols::imm32 } },
            { { 0xC6 }, { OpEncoding::m0 }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC7 }, { OpEncoding::m0 }, { Symbols::rm16, Symbols::imm16 } },
            { { 0xC7 }, { OpEncoding::m0 }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x0F, 0x20 }, { OpEncoding::r }, { Symbols::r32, Symbols::cri } },
            { { 0x0F, 0x21 }, { OpEncoding::r }, { Symbols::r32, Symbols::dri } },
            { { 0x0F, 0x22 }, { OpEncoding::r }, { Symbols::cri, Symbols::r32 } },
            { { 0x0F, 0x23 }, { OpEncoding::r }, { Symbols::dri, Symbols::r32 } }
        };
        oplookup["movs"] = {
            { { 0xA4 }, { }, { Symbols::m8, Symbols::m8 } },
            { { 0xA5 }, { }, { Symbols::m16, Symbols::m16 } },
            { { 0xA5 }, { }, { Symbols::m32, Symbols::m32 } },
        };
        oplookup["mul"] = {
            { { 0xF6 }, { OpEncoding::m4 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m4 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m4 }, { Symbols::rm32 } },
        };
        oplookup["neg"] = {
            { { 0xF6 }, { OpEncoding::m3 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m3 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m3 }, { Symbols::rm32 } },
        };
        oplookup["nop"] = {
            { { 0x90 }, { }, { } }
        };
        oplookup["not"] = {
            { { 0xF6 }, { OpEncoding::m2 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m2 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m2 }, { Symbols::rm32 } },
        };
        oplookup["out"] = {
            { { 0xE6 }, { OpEncoding::ib }, { Symbols::imm8, Symbols::al } },
            { { 0xE7 }, { OpEncoding::ib }, { Symbols::imm8, Symbols::ax } },
            { { 0xE7 }, { OpEncoding::ib }, { Symbols::imm8, Symbols::eax } },
            { { 0xEE }, { }, { Symbols::dx, Symbols::al } },
            { { 0xEF }, { }, { Symbols::dx, Symbols::ax } },
            { { 0xEF }, { }, { Symbols::dx, Symbols::eax } }
        };
        oplookup["outs"] = {
            { { 0x6E }, { }, { Symbols::m8, Symbols::dx } },
            { { 0x6F }, { }, { Symbols::m16, Symbols::dx } },
            { { 0x6F }, { }, { Symbols::m32, Symbols::dx } }
        };
        oplookup["pop"] = {
            { { 0x58 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0x8F }, { OpEncoding::m0 }, { Symbols::m32 } },
            { { 0x07 }, { }, { Symbols::es } },
            { { 0x17 }, { }, { Symbols::ss } },
            { { 0x1F }, { }, { Symbols::ds } }
        };
        oplookup["popf"] = { { { 0x9D }, { } } };
        oplookup["popfd"] = { { { 0x9D }, { } } };
        oplookup["push"] = {
            { { 0x68 }, { }, { Symbols::imm32 } },
            { { 0x6A }, { }, { Symbols::imm8 } },
            { { 0x50 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0x06 }, { }, { Symbols::es } },
            { { 0x0E }, { }, { Symbols::cs } },
            { { 0x16 }, { }, { Symbols::ss } },
            { { 0x1E }, { }, { Symbols::ds } },
            { { 0xFF }, { OpEncoding::m6 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m6 }, { Symbols::rm32 } },
        };
        oplookup["pushf"] = { { { 0x9C }, { } } };
        oplookup["pushfd"] = { { { 0x9C }, { } } };
        oplookup["ret"] = {
            { { 0xC2 }, { OpEncoding::iw }, { Symbols::imm16 } },
            { { 0xCA }, { OpEncoding::iw }, { Symbols::imm16 } },
            { { 0xCB }, { }, { } }
        };
        oplookup["retn"] = { { { 0xC3 }, { } } };
        oplookup["rcl"] = {
            { { 0xC0 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup["rcr"] = {
            { { 0xC0 }, { OpEncoding::m3, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m3, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup["rol"] = {
            { { 0xC0 }, { OpEncoding::m0, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m0, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup["ror"] = {
            { { 0xC0 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup["sahf"] = { { { 0x9E }, { } } };
        oplookup["sal"] = {
            { { 0xC0 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup["sar"] = {
            { { 0xC0 }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup["scasb"] = { { { 0xAE }, { } } };
        oplookup["scasd"] = { { { 0xAF }, { } } };
        oplookup["shr"] = {
            { { 0xC0 }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup["stosb"] = { { { 0xAA }, { } } };
        oplookup["stosd"] = { { { 0xAB }, { } } };
        oplookup["stc"] = { { { 0xF9 }, { } } };
        oplookup["std"] = { { { 0xFD }, { } } };
        oplookup["sti"] = { { { 0xFB }, { } } };
        oplookup["test"] = {
            { { 0xF6 }, { OpEncoding::m0, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xF7 }, { OpEncoding::m0, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0xF7 }, { OpEncoding::m0, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x84 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x85 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x85 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0xA8 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0xA9 }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0xA9 }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
        };
        oplookup["wait"] = {
            { { 0x9B }, { }, { } }
        };
        oplookup["xchg"] = {
            { { 0x86 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x86 }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x87 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x87 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x87 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x87 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x90 }, { OpEncoding::rw }, { Symbols::ax, Symbols::r16 } },
            { { 0x90 }, { OpEncoding::rw }, { Symbols::r16, Symbols::ax } },
            { { 0x90 }, { OpEncoding::rd }, { Symbols::eax, Symbols::r32 } },
            { { 0x90 }, { OpEncoding::rd }, { Symbols::r32, Symbols::eax } },
        };
        oplookup["xlatb"] = { { { 0xD7 }, { } } };

        // Extended SIMD instructions
        oplookup["sldt"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m0 }, { Symbols::rm16 } },
            { { 0x0F, 0x00 }, { OpEncoding::m0 }, { Symbols::rm32 } },
        };
        oplookup["str"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m1 }, { Symbols::rm16 } },
        };
        oplookup["lldt"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m2 }, { Symbols::rm16 } },
        };
        oplookup["ltr"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m3 }, { Symbols::rm16 } },
        };
        oplookup["verr"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m4 }, { Symbols::rm16 } },
        };
        oplookup["verw"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m5 }, { Symbols::rm16 } },
        };
        oplookup["sgdt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m0 }, { Symbols::m } },
        };
        oplookup["sidt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m1 }, { Symbols::m } },
        };
        oplookup["lgdt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m2 }, { Symbols::m16_32 } },
        };
        oplookup["lidt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m3 }, { Symbols::m16_32 } },
        };
        oplookup["smsw"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m4 }, { Symbols::rm16 } },
            { { 0x0F, 0x01 }, { OpEncoding::m5 }, { Symbols::rm32 } },
        };
        oplookup["lmsw"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m6 }, { Symbols::rm16 } },
        };
        oplookup["invlpg"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m7 }, { Symbols::m } },
        };
        oplookup["lar"] = {
            { { 0x0F, 0x02 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x02 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["lsl"] = {
            { { 0x0F, 0x03 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x03 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup["clts"] = { { { 0x0F, 0x06 }, { }, { } } };
        oplookup["invd"] = { { { 0x0F, 0x08 }, { }, { } } };
        oplookup["wbinvd"] = { { { 0x0F, 0x09 }, { }, { } } };
        oplookup["ud2"] = { { { 0x0F, 0x0B }, { }, { } } };
        oplookup["movups"] = {
            { { 0x0F, 0x10 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } },
            { { 0x0F, 0x11 }, { OpEncoding::r }, { Symbols::xmm_m128, Symbols::xmm } }
        };
        oplookup["movhlps"] = {
            { { 0x0F, 0x12 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm2 } }
        };
        oplookup["movlps"] = {
            { { 0x0F, 0x12 }, { OpEncoding::r }, { Symbols::xmm, Symbols::m64 } },
            { { 0x0F, 0x13 }, { OpEncoding::r }, { Symbols::m64, Symbols::xmm } }
        };
        oplookup["unpcklps"] = {
            { { 0x0F, 0x14 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup["unpckhps"] = {
            { { 0x0F, 0x15 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup["movhps"] = {
            { { 0x0F, 0x16 }, { OpEncoding::r }, { Symbols::xmm, Symbols::m64 } },
            { { 0x0F, 0x17 }, { OpEncoding::r }, { Symbols::m64, Symbols::xmm } }
        };
        oplookup["movlhps"] = {
            { { 0x0F, 0x16 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm2 } }
        };
        oplookup["prefetcht0"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m0 }, { Symbols::m8 } }
        };
        oplookup["prefetcht1"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m1 }, { Symbols::m8 } }
        };
        oplookup["prefetcht2"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m2 }, { Symbols::m8 } }
        };
        oplookup["prefetchnta"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m3 }, { Symbols::m8 } }
        };
        oplookup["movaps"] = {
            { { 0x0F, 0x28 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } },
            { { 0x0F, 0x29 }, { OpEncoding::r }, { Symbols::xmm_m128, Symbols::xmm } }
        };
        oplookup["cvtpi2ps"] = {
            { { 0x0F, 0x2A }, { OpEncoding::r }, { Symbols::xmm, Symbols::mm_m64 } },
        };
        oplookup["movntps"] = {
            { { 0x0F, 0x2B }, { OpEncoding::r }, { Symbols::m128, Symbols::xmm } },
        };

        // Used to identify the correct prefix bytecode to use
        std::unordered_map<std::string, uint8_t> prelookup;
        prelookup["lock"] = BaseSet_x86::B_LOCK;
        prelookup["repne"] = BaseSet_x86::B_REPNE;
        prelookup["repe"] = BaseSet_x86::B_REPE;
        prelookup["rep"] = BaseSet_x86::B_REPE;

        Parser::Scope scope = Parser::compile<TargetArchitecture::x86>(source);
        Parser::Body mainBody = scope.bodies.front();

        auto getLabels = [&mainBody]()
        {
            std::vector<Parser::Node*> labels = {};

            for (auto& node : mainBody.nodes)
            {
                switch (node.type)
                {
                case Parser::Node::NodeType::Label:
                    labels.push_back(&node);
                    break;
                }
            }

            return labels;
        };

        // Phase 2: Go through nodes and start 
        for (auto& node : mainBody.nodes)
        {
            switch (node.type)
            {
            case Parser::Node::NodeType::Label:
                node.streamIndex = stream.size();
                break;
            case Parser::Node::NodeType::AsmNode:
            {
                if (node.operands.size())
                {
                    // Go through each operand and determine
                    // its type and mode
                    // (to ultimately figure out what instruction this is)
                    for (size_t opIndex = 0; opIndex < node.operands.size(); opIndex++)
                    {
                        // Parse labels in this operand by replacing it with
                        // a corresponding address in memory
                        for (auto labelNode : getLabels())
                        {
                            std::string::size_type n = 0;
                            while ((n = node.operands[opIndex].find(labelNode->label, n)) != std::string::npos)
                            {
                                char str[10];
                                sprintf_s(str, "%08Xh", static_cast<uint32_t>(offset + labelNode->streamIndex));
                                node.operands[opIndex].replace(n, labelNode->label.size(), str);
                                n += strlen(str);
                            }
                        }

                        Operand operand;
                        std::vector<std::string>parts = {};
                        std::string r(node.operands[opIndex] + "........"); // padding for substr
                        size_t at = 0;

                        bool rm = false;

                        auto next = [&r](size_t& n)
                        {
                            if (n >= r.length())
                                return std::string();

                            switch (r[n])
                            {
                            case '.':
                                return std::string();
                            case '+':
                            case '-':
                            case '*':
                            case '[':
                            case ']':
                                return std::string(1, r[n++]);
                            default:
                            {
                                std::string label = "";

                                while (n < r.length() - 8)
                                {
                                    // a-z or A-Z or 0-9 and accepted characters for tokens ('(', ')')
                                    if ((r[n] >= 0x61 && r[n] <= 0x7A) || (r[n] >= 0x41 && r[n] <= 0x5A) || (r[n] >= 0x30 && r[n] <= 0x39) || r[n] == '(' || r[n] == ')' || r[n] == ':')
                                        label += r[n++];
                                    else
                                        break;
                                }

                                return label;
                            }
                            }
                            return std::string();
                        };

                        std::string token = "", prevToken = "";

                        while (token != "]")
                        {
                            prevToken = token;
                            token = next(at);

                            if (token.empty())
                                break;

                            switch (token.front())
                            {
                            case '+':
                            case '-':
                                parts.push_back(token);
                                break;
                            case '*':
                                parts.push_back(token);
                                token = next(at);
                                parts.push_back("mul");
                                operand.mul = std::atoi(token.c_str());
                                continue;
                            case '[':
                                node.hasMod = true;
                                node.modIndex = opIndex;
                                operand.flags |= BaseSet_x86::OP_RM;
                                operand.opmode = Symbols::rm32;
                                rm = true;
                                break;
                            default:
                            {
                                bool isReserved = false;

                                // Conveniently, there are always 8 registers
                                for (size_t i = 0; i < 8; i++)
                                {
                                    if (token == Mnemonics::R8[i])
                                    {
                                        operand.opmode = (rm) ? Symbols::rm8 : Symbols::r8;
                                        node.bitSize = (node.bitSize == 0) ? 8 : node.bitSize;
                                        parts.push_back("r8");
                                        operand.regs.push_back(i);
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::R16[i])
                                    {
                                        operand.opmode = (rm) ? Symbols::rm16 : Symbols::r16;
                                        node.bitSize = (node.bitSize == 0) ? 16 : node.bitSize;
                                        parts.push_back("r16");
                                        operand.regs.push_back(i);
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::R32[i])
                                    {
                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::r32;
                                        node.bitSize = (node.bitSize == 0) ? 32 : node.bitSize;
                                        parts.push_back("r32");
                                        operand.regs.push_back(i);
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::SREG[i])
                                    {
                                        operand.opmode = Symbols::sreg;
                                        node.bitSize = (node.bitSize == 0) ? 16 : node.bitSize;
                                        parts.push_back("sreg");
                                        operand.regs.push_back(i);
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::STI[i])
                                    {
                                        operand.opmode = Symbols::sti;
                                        parts.push_back("sti");
                                        operand.regs.push_back(i);
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::CRI[i])
                                    {
                                        operand.opmode = Symbols::cri;
                                        parts.push_back("cri");
                                        operand.regs.push_back(i);
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::DRI[i])
                                    {
                                        operand.opmode = Symbols::dri;
                                        parts.push_back("dri");
                                        operand.regs.push_back(i);
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::MM[i])
                                    {
                                        operand.opmode = (rm) ? Symbols::mm_m64 : Symbols::mm;
                                        parts.push_back("mm");
                                        operand.regs.push_back(i);
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::XMM[i])
                                    {
                                        operand.opmode = (rm) ? Symbols::xmm_m128 : Symbols::xmm;
                                        parts.push_back("xmm");
                                        operand.regs.push_back(i);
                                        isReserved = true;
                                    }
                                }

                                if (isReserved)
                                    continue;

                                bool isNumber = true;
                                bool isNumberHex = false;
                                size_t sizeNumber = 0; // calculate size

                                bool isSegment = (token.find(":") != std::string::npos);

                                if (token.length() <= 9 || isSegment)
                                {
                                    if (token.back() == 'h' || isSegment)
                                    {
                                        // Verify hex-encoded numbers (0-9, a-f, A-F)
                                        for (size_t i = 0; i < token.length() - 1; i++)
                                        {
                                            if (!((token[i] >= 0x30 && token[i] <= 0x39) || (token[i] >= 0x41 && token[i] <= 0x46) || (token[i] >= 0x61 && token[i] <= 0x66) || token[i] == ':'))
                                            {
                                                isNumber = false;
                                                break;
                                            }
                                        }

                                        if (isNumber)
                                        {
                                            isNumberHex = true;
                                            token.pop_back();
                                        }
                                    }
                                    else
                                    {
                                        // Verify standard numbers (0-9)
                                        for (size_t i = 0; i < token.length(); i++)
                                        {
                                            if (!(token[i] >= 0x30 && token[i] <= 0x39))
                                            {
                                                isNumber = false;
                                                break;
                                            }
                                        }
                                    }
                                }

                                if (isNumber)
                                {
                                    if (!isSegment)
                                    {
                                        if (token.length() <= 8) sizeNumber = 8;
                                        if (token.length() <= 4) sizeNumber = 4;
                                        if (token.length() <= 2) sizeNumber = 2;
                                    }

                                    if (isNumberHex)
                                    {
                                        switch (sizeNumber)
                                        {
                                        case 2:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm8;
                                            operand.imm8 = std::strtoul(token.c_str(), nullptr, 16);
                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm8 = UINT8_MAX - operand.imm8 + 1; // invert sign
                                            operand.flags |= BaseSet_x86::OP_IMM8;
                                            parts.push_back("imm8");
                                            break;
                                        case 4:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm16;
                                            operand.imm16 = std::strtoul(token.c_str(), nullptr, 16);
                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm16 = UINT16_MAX - operand.imm16 + 1; // invert sign
                                            operand.flags |= BaseSet_x86::OP_IMM16;
                                            parts.push_back("imm16");
                                            break;
                                        case 8:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm32;
                                            operand.imm32 = std::strtoul(token.c_str(), nullptr, 16);
                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm32 = UINT32_MAX - operand.imm32 + 1; // invert sign
                                            operand.flags |= BaseSet_x86::OP_IMM32;
                                            parts.push_back("imm32");
                                            break;
                                        default: // Segment/Pointer Offset (Only hex allowed)
                                        {
                                            const auto pos = token.find(":");
                                            operand.opmode = Symbols::ptr16_32;
                                            operand.disp16 = std::strtoul(token.substr(0, pos).c_str(), nullptr, 16);
                                            operand.imm32 = std::strtoul(token.substr(pos + 1, token.length() - (pos + 1)).c_str(), nullptr, 16);
                                            operand.flags |= BaseSet_x86::OP_IMM16 | BaseSet_x86::OP_IMM32;
                                            parts.push_back("ptr16_32");
                                            break;
                                        }
                                        }
                                    }
                                    else
                                    {
                                        switch (sizeNumber)
                                        {
                                        case 2:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm8;
                                            operand.imm8 = std::atoi(token.c_str());
                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm8 = UINT8_MAX - operand.imm8 + 1;
                                            operand.flags |= BaseSet_x86::OP_IMM8;
                                            parts.push_back("imm8");
                                            break;
                                        case 4:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm16;
                                            operand.imm16 = std::atoi(token.c_str());
                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm16 = UINT16_MAX - operand.imm16 + 1;
                                            operand.flags |= BaseSet_x86::OP_IMM16;
                                            parts.push_back("imm16");
                                            break;
                                        case 8:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm32;
                                            operand.imm32 = std::atoi(token.c_str());
                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm32 = UINT32_MAX - operand.imm32 + 1;
                                            operand.flags |= BaseSet_x86::OP_IMM32;
                                            parts.push_back("imm32");
                                            break;
                                        }
                                    }
                                }
                                else
                                {
                                    //printf("Unknown label: %s\n", token.c_str());
                                }

                                break;
                            }
                            }
                        };

                        //printf("(%s) operand pattern: ", node.opName.c_str());
                        //for (auto s : parts)
                        //    printf("%s ", s.c_str());
                        //printf("\n");

                        operand.pattern = parts;
                        node.opData.operands.push_back(operand);
                    }
                }

                // if both operands are a reg, then use an "rm" on the left or right
                // because then we can match it to the correct { r32, rm32 } opcode.
                // We determine the mode later.
                if (!node.hasMod && node.opData.operands.size() > 1)
                {
                    bool set = false;

                    for (auto op = node.opData.operands.rbegin(); op != node.opData.operands.rend() && !set; op++)
                    {
                        switch (op->opmode)
                        {
                        case Symbols::r8:
                            op->opmode = Symbols::rm8;
                            set = true;
                            break;
                        case Symbols::r16:
                            op->opmode = Symbols::rm16;
                            set = true;
                            break;
                        case Symbols::r32:
                            //auto operand1 = &node.opData.operands.front();
                            //auto operand2 = &node.opData.operands.back();

                            //if (operand1->opmode == operand2->opmode)
                            //    operand2->opmode = Symbols::rm32;

                            op->opmode = Symbols::rm32;
                            set = true;
                            break;
                        }
                    }
                }

                // Correct the bitsize of operand/opmodes so that they match.
                // Example:
                // If one operand is r8 and the other is rm32, the only thing we 
                // can do to make it line up with our (intel-correct) lookup table
                // is to correct the rm32 so that it is rm8.
                // It's tedious but this works
                //
                if (node.bitSize)
                {
                    for (size_t i = 0; i < node.opData.operands.size(); i++)
                    {
                        switch (node.opData.operands[i].opmode)
                        {
                        case Symbols::rm32:
                            switch (node.bitSize)
                            {
                            case 8:
                                node.opData.operands[i].opmode = Symbols::rm8;
                                break;
                            case 16:
                                node.opData.operands[i].opmode = Symbols::rm16;
                                break;
                            }
                            break;
                        }
                    }
                }

                break;
            }
            }

            bool reject, solved = false;

            // Look up the corresponding opcode information
            // for our parsed opcode
            for (auto lookup = oplookup.begin(); lookup != oplookup.end() && !solved; lookup++)
            {
                if (lookup->first == node.opName)
                {
                    for (const auto& opvariant : lookup->second)
                    {
                        std::vector<BaseSet_x86::Operand> userOperands(node.opData.operands);

                        reject = false;

                        // Test the operands tied to this opcode, if there are any
                        if (!userOperands.empty())
                        {
                            if (userOperands.size() != opvariant.symbols.size())
                                continue;
                            else
                            {
                                for (size_t i = 0; i < opvariant.symbols.size() && !reject; i++)
                                {
                                    bool regspec = false;
                                    bool forceValidate = false;
                                    auto op = userOperands[i];

                                    switch (op.opmode)
                                    {
                                    // in the case of imm8-imm32 values, these could
                                    // represent rel8-rel32 values instead, so we must
                                    // compare that with the opcode variant we looked up.
                                    // Similarly, this applies to many other operand types
                                    case Symbols::imm8:
                                        switch (opvariant.symbols[i])
                                        {
                                        case Symbols::rel8:
                                            forceValidate = true;
                                            break;
                                        }
                                    case Symbols::imm16: // To-do: optimize by enabling shorter (rel8) jump when necessary
                                        switch (opvariant.symbols[i])
                                        {
                                        case Symbols::rel16:
                                        case Symbols::rel32:
                                        case Symbols::imm32:
                                            forceValidate = true;
                                            break;
                                        }
                                    case Symbols::imm32:
                                        switch (opvariant.symbols[i])
                                        {
                                        case Symbols::rel32:
                                            forceValidate = true;
                                            break;
                                        }
                                        break;
                                    case Symbols::rm8:
                                    case Symbols::rm16:
                                    case Symbols::rm32:
                                        if (node.hasMod && op.regs.empty() && op.pattern.size() == 1)
                                        {
                                            if (op.pattern.front() == "imm32")
                                            {
                                                switch (opvariant.symbols[i])
                                                {
                                                case Symbols::moffs8:
                                                case Symbols::moffs16:
                                                case Symbols::moffs32:
                                                    forceValidate = true;
                                                    break;
                                                }
                                            }
                                        }

                                        if (op.opmode == Symbols::rm32)
                                        {
                                            switch (opvariant.symbols[i])
                                            {
                                            // If this opcode variation uses m or m32, we accept
                                            // it because our parser only stores it under rm32
                                            case Symbols::m:
                                            case Symbols::m8:
                                            case Symbols::m32:
                                            case Symbols::m64:
                                            case Symbols::m128:
                                            case Symbols::mm_m32:
                                            case Symbols::mm_m64:
                                            case Symbols::xmm_m32:
                                            case Symbols::xmm_m64:
                                            case Symbols::xmm_m128:
                                                forceValidate = true;
                                                break;
                                            }
                                        }
                                        break;
                                    // in the case of registers, we use a single label to denote
                                    // any of 8 registers. Some opcodes specify 1 particular register,
                                    // so we must check for those cases here (and allow them to pass)
                                    case Symbols::xmm:
                                        switch (opvariant.symbols[i])
                                        {
                                        case Symbols::xmm2:
                                            userOperands[i].opmode = Symbols::xmm2;
                                            forceValidate = true;
                                            break;
                                        case Symbols::mm_m32:
                                        case Symbols::mm_m64:
                                            forceValidate = true;
                                            break;
                                        case Symbols::m128:
                                        case Symbols::xmm_m32:
                                        case Symbols::xmm_m64:
                                            userOperands[i].opmode = Symbols::xmm_m128;
                                            forceValidate = true;
                                            break;
                                        }
                                    case Symbols::sti:
                                    case Symbols::sreg:
                                    case Symbols::r8:
                                    case Symbols::r16:
                                    case Symbols::r32:
                                        if (!op.regs.empty())
                                        {
                                            const auto reg = op.regs.front();

                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::es:
                                                forceValidate = (reg == 0);
                                                break;
                                            case Symbols::cs:
                                                forceValidate = (reg == 1);
                                                break;
                                            case Symbols::ss:
                                                forceValidate = (reg == 2);
                                                break;
                                            case Symbols::ds:
                                                forceValidate = (reg == 3);
                                                break;
                                            case Symbols::fs:
                                                forceValidate = (reg == 4);
                                                break;
                                            case Symbols::gs:
                                                forceValidate = (reg == 5);
                                                break;
                                            case Symbols::hs:
                                                forceValidate = (reg == 6);
                                                break;
                                            case Symbols::is:
                                                forceValidate = (reg == 7);
                                                break;
                                            case Symbols::st0:
                                            case Symbols::al:
                                            case Symbols::ax:
                                            case Symbols::eax:
                                                regspec = (reg == 0);
                                                break;
                                            case Symbols::cl:
                                            case Symbols::cx:
                                            case Symbols::ecx:
                                                regspec = (reg == 1);
                                                break;
                                            case Symbols::dl:
                                            case Symbols::dx:
                                            case Symbols::edx:
                                                regspec = (reg == 2);
                                                break;
                                            case Symbols::bl:
                                            case Symbols::bx:
                                            case Symbols::ebx:
                                                regspec = (reg == 3);
                                                break;
                                            case Symbols::ah:
                                            case Symbols::sp:
                                            case Symbols::esp:
                                                regspec = (reg == 4);
                                                break;
                                            case Symbols::ch:
                                            case Symbols::bp:
                                            case Symbols::ebp:
                                                regspec = (reg == 5);
                                                break;
                                            case Symbols::dh:
                                            case Symbols::si:
                                            case Symbols::esi:
                                                regspec = (reg == 6);
                                                break;
                                            case Symbols::bh:
                                            case Symbols::di:
                                            case Symbols::edi:
                                                regspec = (reg == 7);
                                                break;
                                            }
                                        }
                                        break;
                                    }

                                    if (forceValidate)
                                        break;
                                    else if (regspec)
                                    {
                                        // We won't be using this opmode. It only
                                        // enabled us to look up the correct opcode information
                                        userOperands[i].opmode = Symbols::not_set;
                                    }
                                    else if (!forceValidate)
                                    {
                                        // Reject this opcode comparison if the (other) opmodes do not match
                                        //printf("%i (%s) == %i?\n", userOperands[i].opmode, node.operands[i].c_str(), opvariant.symbols[i]);
                                        reject = (userOperands[i].opmode != opvariant.symbols[i]);
                                    }
                                }

                                if (reject)
                                    continue;
                            }
                        }

                        if (node.bitSize == 16 && node.hasMod) // node.hasMod?
                            stream.add(BaseSet_x86::B_66);

                        // Add the prefix flag
                        if (!node.opPrefix.empty())
                            if (prelookup.find(node.opPrefix) != prelookup.end())
                                stream.add(prelookup[node.opPrefix]);

                        uint8_t modbyte = 0;
                        uint8_t sibbyte = 0;

                        bool ignoreMode = false;
                        bool wroteCode = false;
                        bool hasSib = false;
                        bool hasImm8 = false, hasImm16 = false, hasImm32 = false;
                        bool hasDisp8 = false, hasDisp16 = false, hasDisp32 = false;
                        bool useModByte = false;

                        uint8_t imm8value = 0;
                        uint16_t imm16value = 0;
                        uint32_t imm32value = 0;

                        uint8_t disp8value = 0;
                        uint16_t disp16value = 0;
                        uint32_t disp32value = 0;

                        // Differentiate between relative32 values and imm32 values
                        // and the various sizes of imm values (by shifting them over).
                        // our check may allow these variants to pass.
                        for (size_t i = 0; i < opvariant.symbols.size(); i++)
                        {
                            Operand* op = &userOperands[i];
                            switch (opvariant.symbols[i])
                            {
                            case Symbols::rel8:
                                op->opmode = Symbols::rel8;
                                op->rel8 = op->imm8;
                                op->imm8 = 0;
                                break;
                            case Symbols::rel16:
                                op->opmode = Symbols::rel16;
                                op->rel16 = op->imm16;
                                op->imm16 = 0;
                                break;
                            case Symbols::rel32:
                                op->opmode = Symbols::rel32;
                                op->rel32 = op->imm32;
                                op->imm32 = 0;
                                break;
                            case Symbols::imm32:
                                switch (op->opmode)
                                {
                                // user passed imm8 but this look-up opcode specifies a 32-bit value...
                                case Symbols::imm8:
                                    op->imm32 = op->imm8;
                                    op->opmode = Symbols::imm32;
                                    op->imm8 = 0;
                                    break;
                                case Symbols::imm16:
                                    op->imm32 = op->imm16;
                                    op->opmode = Symbols::imm32;
                                    op->imm16 = 0;
                                    break;
                                }
                            }
                        }

                        const auto noperands = userOperands.size();
                        auto insCode = opvariant.code;

                        for (const auto entry : opvariant.entries)
                        {
                            // If the opcode format is "+rd", then the final opcode byte
                            // is used to denote the (8-32 bit) register
                            switch (entry)
                            {
                            case OpEncoding::m0:
                                break;
                            case OpEncoding::m1:
                                modbyte += 1 << 3;
                                break;
                            case OpEncoding::m2:
                                modbyte += 2 << 3;
                                break;
                            case OpEncoding::m3:
                                modbyte += 3 << 3;
                                break;
                            case OpEncoding::m4:
                                modbyte += 4 << 3;
                                break;
                            case OpEncoding::m5:
                                modbyte += 5 << 3;
                                break;
                            case OpEncoding::m6:
                                modbyte += 6 << 3;
                                break;
                            case OpEncoding::m7:
                                modbyte += 7 << 3;
                                break;
                            case OpEncoding::rb:
                            case OpEncoding::rw:
                            case OpEncoding::rd:
                                if (opvariant.code.size() > 1)
                                    for (size_t i = 0; i < opvariant.code.size() - 1; i++)
                                        stream.add(opvariant.code[i]);

                                stream.add(opvariant.code.back() + userOperands.front().regs.front());

                                // Remove the placeholder for this register -- it's a part of
                                // the instruction bytecode
                                if (noperands)
                                    userOperands.erase(userOperands.begin());

                                wroteCode = true;
                                break;
                            case OpEncoding::i:
                                // Write all bytes except for the one that i applies to
                                // (Which we presume is always the final byte)
                                for (size_t i = 0; i < opvariant.code.size() - 1; i++)
                                    stream.add(opvariant.code[i]);

                                modbyte += opvariant.code.back();
                                wroteCode = true;
                                break;
                            }
                        }

                        if (!wroteCode)
                            // append code for this instruction
                            for (const auto b : opvariant.code)
                                stream.add(b);

                        // Continue -- generate the rest of the code for this instruction
                        // 
                        if (noperands)
                        {
                            // Instruction format is as follows:
                            // 
                            // --> Finished:
                            // Prefix           (Up to 4, 1 byte each)  optional
                            // Opcode           (1-2 bytes)             required
                            // --> We are here:
                            // ModR/M           (1 byte)                optional
                            // SIB              (1 byte)                optional
                            // Displacement     (1, 2 or 4 bytes)       optional                     
                            // Immediate        (1, 2 or 4 bytes)       optional
                            // 

                            for (size_t i = 0; i < userOperands.size(); i++)
                            {
                                Operand op = userOperands[i];
                                switch (op.opmode)
                                {
                                case Symbols::imm8:
                                    disp8value = op.imm8;
                                    hasDisp8 = true;
                                    break;
                                case Symbols::imm16:
                                    disp16value = op.imm16;
                                    hasDisp16 = true;
                                    break;
                                case Symbols::imm32:
                                    disp32value = op.imm32;
                                    hasDisp32 = true;
                                    break;
                                case Symbols::rel8:
                                    imm8value = op.rel8 - (offset + stream.size() + 1);
                                    hasImm8 = true;
                                    break;
                                case Symbols::rel16:
                                    imm16value = op.rel16 - (offset + stream.size() + 2);
                                    hasImm16 = true;
                                    break;
                                case Symbols::rel32:
                                    imm32value = op.rel32 - (offset + stream.size() + 4);
                                    hasImm32 = true;
                                    break;
                                case Symbols::ptr16_32:
                                    disp16value = op.disp16;
                                    hasDisp16 = true;
                                    imm32value = op.imm32;
                                    hasImm32 = true;
                                    break;
                                case Symbols::sti:
                                    if (!opvariant.entries.empty())
                                    {
                                        if (opvariant.entries.front() == OpEncoding::i)
                                        {
                                            if (opvariant.symbols[i] == Symbols::st0)
                                                break;
                                            else
                                            {
                                                useModByte = true;
                                                modbyte += op.regs.front();
                                                break;
                                            }
                                        }
                                    }
                                case Symbols::cri:
                                case Symbols::dri:
                                case Symbols::sreg:
                                case Symbols::xmm:
                                case Symbols::r8:
                                case Symbols::r16:
                                case Symbols::r32:
                                    useModByte = true;
                                    modbyte += op.regs.front() << 3;
                                    break;
                                case Symbols::xmm2:
                                    useModByte = true;
                                    modbyte += 3 << 6;
                                    modbyte += +op.regs.front();
                                    break;
                                case Symbols::rm8:
                                case Symbols::rm16:
                                case Symbols::rm32:
                                case Symbols::mm_m32:
                                case Symbols::mm_m64:
                                case Symbols::xmm_m32:
                                case Symbols::xmm_m64:
                                case Symbols::xmm_m128:
                                    switch (opvariant.symbols[i])
                                    {
                                    // These can look just like a rm8/rm32 when parsing so we want
                                    // to differentiate between it and the opcode we looked up
                                    case Symbols::moffs8:
                                    case Symbols::moffs16:
                                    case Symbols::moffs32:
                                        imm32value = op.imm32;
                                        hasImm32 = true;
                                        ignoreMode = true;
                                        break;
                                    }

                                    if (ignoreMode)
                                        break;

                                    useModByte = true;
                                    if (op.flags & BaseSet_x86::OP_IMM8)
                                    {
                                        modbyte += 1 << 6;
                                        imm8value = op.imm8;
                                        hasImm8 = true;
                                    }
                                    else if (op.flags & BaseSet_x86::OP_IMM32)
                                    {
                                        if (op.regs.size() == 0)
                                        {
                                            modbyte += 5;
                                            imm32value = op.imm32;
                                            hasImm32 = true;
                                        }
                                        else
                                        {
                                            modbyte += 2 << 6;
                                            imm32value = op.imm32;
                                            hasImm32 = true;
                                        }
                                    }
                                    else if (op.regs.size() == 1 && !node.hasMod)
                                    {
                                        modbyte += 3 << 6;
                                        modbyte += op.regs.front();// << 3;
                                        break;
                                    }

                                    if (op.mul)
                                        sibbyte += (1 + (op.mul >> 2)) << 6;

                                    switch (op.regs.size())
                                    {
                                    case 1:
                                        if (op.regs.front() == static_cast<uint8_t>(BaseSet_x86::R32::ESP))
                                        {
                                            hasSib = true;
                                            sibbyte += 0x24;
                                        }

                                        modbyte += op.regs.front();
                                        break;
                                    case 2:
                                        hasSib = true;
                                        modbyte += 4;
                                        sibbyte += op.regs.front();
                                        sibbyte += op.regs.back() << 3;
                                        break;
                                    }
                                    break;
                                }
                            }

                            if (useModByte)
                                stream.add(modbyte);

                            if (hasSib)
                                stream.add(sibbyte);

                            if (hasImm8)
                                stream.add(imm8value);
                            
                            if (hasImm16)
                            {
                                std::vector<uint8_t> b = { 0, 0 };
                                memcpy(&b[0], &imm16value, 2);
                                stream.add(b);
                            }

                            if (hasImm32)
                            {
                                std::vector<uint8_t> b = { 0, 0, 0, 0 };
                                memcpy(&b[0], &imm32value, 4);
                                stream.add(b);
                            }

                            if (hasDisp8)
                                stream.add(disp8value);
                            
                            if (hasDisp16)
                            {
                                std::vector<uint8_t> b = { 0, 0 };
                                memcpy(&b[0], &disp16value, 2);
                                stream.add(b);
                            }

                            if (hasDisp32)
                            {
                                std::vector<uint8_t> b = { 0, 0, 0, 0 };
                                memcpy(&b[0], &disp32value, 4);
                                stream.add(b);
                            }
                        }

                        solved = true;
                        break;
                    }
                }
            }
        }



        return stream;
    }



    BaseSet_x64::Opcode Disassembler<TargetArchitecture::x64>::readNext()
    {
        BaseSet_x64::Opcode opcode;

        return opcode;
    }

    BaseSet_ARM::Opcode Disassembler<TargetArchitecture::ARM>::readNext()
    {
        BaseSet_ARM::Opcode opcode;

        return opcode;
    }


}

