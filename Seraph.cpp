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
        static const std::vector<std::string> SREG = { "es", "cx", "ss", "ds", "fs", "gs", "hs", "is" };
        static const std::vector<std::string> STI = { "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7" };
        static const std::vector<std::string> CRI = { "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7" };
        static const std::vector<std::string> DRI = { "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7" };
        static const std::vector<std::string> MM = { "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7" };
        static const std::vector<std::string> XMM = { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7" };
    };


    BaseSet_x86::Opcode Disassembler<TargetArchitecture::x86>::readNext()
    {
        BaseSet_x86::Opcode opcode;

        // Coming soon!

        return opcode;
    }

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

    Assembler<TargetArchitecture::x86>::Assembler()
    {
        using OpEncoding = BaseSet_x86::OpEncoding;
        using OpData = BaseSet_x86::OpData;
        using Symbols = BaseSet_x86::Symbols;

        prelookup_x86 = std::unordered_map<std::string, uint8_t>();

        prelookup_x86["lock"] = BaseSet_x86::B_LOCK;
        prelookup_x86["66"] = BaseSet_x86::B_66;
        prelookup_x86["67"] = BaseSet_x86::B_67;
        prelookup_x86["repne"] = BaseSet_x86::B_REPNE;
        prelookup_x86["repe"] = BaseSet_x86::B_REPE;
        prelookup_x86["rep"] = BaseSet_x86::B_REPE;

        oplookup_x86 = std::unordered_map<std::string, std::vector<BaseSet_x86::OpData>>();

        // To-do: this should be reorganized. I will probably 
        // sort it by just opcode number rather than alphabetically
        oplookup_x86["aaa"] = { { { 0x37 }, { } } };
        oplookup_x86["aad"] = { { { 0xD5, 0x0A }, { }, { } } };
        oplookup_x86["aam"] = { { { 0xD4, 0x0A }, { }, { } } };
        oplookup_x86["aas"] = { { { 0x3F }, { } } };
        oplookup_x86["add"] = {
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
        oplookup_x86["or"] = {
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
        oplookup_x86["adc"] = {
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
        oplookup_x86["sbb"] = {
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
        oplookup_x86["and"] = {
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
        oplookup_x86["sub"] = {
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
        oplookup_x86["xor"] = {
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
        oplookup_x86["cmp"] = {
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
        oplookup_x86["cmps"] = {
            { { 0xA6 }, { }, { Symbols::m8, Symbols::m8 } },
            { { 0xA7 }, { }, { Symbols::m16, Symbols::m16 } },
            { { 0xA7 }, { }, { Symbols::m32, Symbols::m32 } },
        };
        oplookup_x86["arpl"] = {
            { { 0x63 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
        };
        oplookup_x86["bound"] = {
            { { 0x62 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x62 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["call"] = {
            { { 0xE8 }, { OpEncoding::cw }, { Symbols::rel16 } },
            { { 0xE8 }, { OpEncoding::cd }, { Symbols::rel32 } },
            { { 0x9A }, { OpEncoding::cd }, { Symbols::ptr16_16 } },
            { { 0x9A }, { OpEncoding::cp }, { Symbols::ptr16_32 } },
            { { 0xFF }, { OpEncoding::m2 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m2 }, { Symbols::rm32 } },
            { { 0xFF }, { OpEncoding::m3 }, { Symbols::m16_16 } },
            { { 0xFF }, { OpEncoding::m3 }, { Symbols::m16_32 } },
        };
        oplookup_x86["cbw"] = { { { 0x98 }, { }, { } } };
        oplookup_x86["clc"] = { { { 0xF8 }, { } } };
        oplookup_x86["cld"] = { { { 0xFC }, { } } };
        oplookup_x86["cli"] = { { { 0xFA }, { } } };
        oplookup_x86["cmc"] = { { { 0xF5 }, { }, { } } };
        oplookup_x86["cmovo"] = {
            { { 0x0F, 0x40 }, { OpEncoding::m0, OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x40 }, { OpEncoding::m0, OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovno"] = {
            { { 0x0F, 0x41 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x41 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovb"] = {
            { { 0x0F, 0x42 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x42 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovnb"] = {
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovae"] = {
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmove"] = {
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovz"] = {
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovne"] = {
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovnz"] = {
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovbe"] = {
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovna"] = {
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmova"] = {
            { { 0x0F, 0x47 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x47 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovs"] = {
            { { 0x0F, 0x48 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x48 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovns"] = {
            { { 0x0F, 0x49 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x49 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovp"] = {
            { { 0x0F, 0x4A }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4A }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovnp"] = {
            { { 0x0F, 0x4B }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovl"] = {
            { { 0x0F, 0x4C }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4C }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovnl"] = {
            { { 0x0F, 0x4D }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4D }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovng"] = {
            { { 0x0F, 0x4E }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4E }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cmovg"] = {
            { { 0x0F, 0x4F }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4F }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["cwd"] = { { { 0x99 }, { }, { } } };
        oplookup_x86["daa"] = { { { 0x27 }, { } } };
        oplookup_x86["das"] = { { { 0x2F }, { } } };
        oplookup_x86["dec"] = {
            { { 0x48 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0xFE }, { OpEncoding::m1 }, { Symbols::rm8 } },
            { { 0xFF }, { OpEncoding::m1 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m1 }, { Symbols::rm32 } },
        };
        oplookup_x86["div"] = {
            { { 0xF6 }, { OpEncoding::m6 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m6 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m6 }, { Symbols::rm32 } },
        };
        oplookup_x86["enter"] = {
            { { 0xC8 }, { OpEncoding::iw }, { Symbols::imm16, Symbols::imm8 } }
        };
        oplookup_x86["fcmovb"] = {
            { { 0xDA, 0xC0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fcmove"] = {
            { { 0xDA, 0xC8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fcmovbe"] = {
            { { 0xDA, 0xD0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fcmovu"] = {
            { { 0xDA, 0xD8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fild"] = {
            { { 0xDF }, { OpEncoding::m0 }, { Symbols::m16int } },
            { { 0xDB }, { OpEncoding::m0 }, { Symbols::m32int } },
            { { 0xDF }, { OpEncoding::m5 }, { Symbols::m64int } }
        };
        oplookup_x86["fist"] = {
            { { 0xDF }, { OpEncoding::m2 }, { Symbols::m16int } },
            { { 0xDB }, { OpEncoding::m2 }, { Symbols::m32int } }
        };
        oplookup_x86["fistp"] = {
            { { 0xDF }, { OpEncoding::m3 }, { Symbols::m16int } },
            { { 0xDB }, { OpEncoding::m3 }, { Symbols::m32int } },
            { { 0xDF }, { OpEncoding::m7 }, { Symbols::m64int } }
        };
        oplookup_x86["fbld"] = {
            { { 0xDF }, { OpEncoding::m4 }, { Symbols::m80dec } }
        };
        oplookup_x86["fbstp"] = {
            { { 0xDF }, { OpEncoding::m6 }, { Symbols::m80bcd } }
        };

        oplookup_x86["fcmovnb"] = {
            { { 0xDB, 0xC0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fcmovne"] = {
            { { 0xDB, 0xC8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fcmovnbe"] = {
            { { 0xDB, 0xD0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fcmovnu"] = {
            { { 0xDB, 0xD8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fnclex"] = { { { 0xDB, 0xE2 }, { }, { } } };
        oplookup_x86["fninit"] = { { { 0xDB, 0xE3 }, { }, { } } };
        oplookup_x86["fucompp"] = { { { 0xDA, 0xE9 }, { }, { } } };
        oplookup_x86["fucom"] = {
            { { 0xDD, 0xE0 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xDD, 0xE1 }, { }, { } }
        };
        oplookup_x86["fucomi"] = {
            { { 0xDB, 0xE8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fucomip"] = {
            { { 0xDF, 0xE8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fcomip"] = {
            { { 0xDF, 0xF0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fucomp"] = {
            { { 0xDD, 0xE8 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xDD, 0xE9 }, { }, { } }
        };
        oplookup_x86["fcomi"] = {
            { { 0xDB, 0xF0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86["fstenv"] = {
            { { 0x9B, 0xD9 }, { OpEncoding::m6 }, { Symbols::m14_28byte } }
        };
        oplookup_x86["fstcw"] = {
            { { 0x9B, 0xD9 }, { OpEncoding::m7 }, { Symbols::m2byte } }
        };
        oplookup_x86["fclex"] = { { { 0x9B, 0xDB, 0xE2 }, { }, { } } };
        oplookup_x86["finit"] = { { { 0x9B, 0xDB, 0xE3 }, { }, { } } };
        oplookup_x86["fsave"] = {
            { { 0x9B, 0xDD }, { OpEncoding::m6 }, { Symbols::m94_108byte } }
        };
        oplookup_x86["fstsw"] = {
            { { 0x9B, 0xDD }, { OpEncoding::m7 }, { Symbols::m2byte } },
            { { 0x9B, 0xDF, 0xE0 }, { }, { Symbols::ax } }
        };
        oplookup_x86["fadd"] = {
            { { 0xD8 }, { OpEncoding::m0 }, { Symbols::m32real } },
            { { 0xD8, 0xC0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC }, { OpEncoding::m0 }, { Symbols::m64real } },
            { { 0xDC, 0xC0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86["faddp"] = {
            { { 0xDE, 0xC0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xC1 }, { }, { } }
        };
        oplookup_x86["fmulp"] = {
            { { 0xDE, 0xC8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xC9 }, { }, { } }
        };
        oplookup_x86["fcompp"] = {
            { { 0xDE, 0xD9 }, { }, { } }
        };
        oplookup_x86["fsubrp"] = {
            { { 0xDE, 0xE0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xE1 }, { }, { } }
        };
        oplookup_x86["fsubp"] = {
            { { 0xDE, 0xE8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xE9 }, { }, { } }
        };
        oplookup_x86["fdivrp"] = {
            { { 0xDE, 0xF0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xF1 }, { }, { } }
        };
        oplookup_x86["fdivp"] = {
            { { 0xDE, 0xF8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xF9 }, { }, { } }
        };
        oplookup_x86["fiadd"] = {
            { { 0xDE }, { OpEncoding::m0 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m0 }, { Symbols::m32int } },
        };
        oplookup_x86["fmul"] = {
            { { 0xD8 }, { OpEncoding::m1 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m1 }, { Symbols::m64real } },
            { { 0xD8, 0xC8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xC8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86["fimul"] = {
            { { 0xDE }, { OpEncoding::m1 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m1 }, { Symbols::m32int } }
        };
        oplookup_x86["fcom"] = {
            { { 0xD8 }, { OpEncoding::m2 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m2 }, { Symbols::m64real } },
            { { 0xD8, 0xD0 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xD8, 0xD1 }, { }, { } }
        };
        oplookup_x86["ficom"] = {
            { { 0xDE }, { OpEncoding::m2 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m2 }, { Symbols::m32int } }
        };
        oplookup_x86["fcomp"] = {
            { { 0xD8 }, { OpEncoding::m3 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m3 }, { Symbols::m64real } },
            { { 0xD8, 0xD8 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xD8, 0xD9 }, { }, { } }
        };
        oplookup_x86["ficomp"] = {
            { { 0xDE }, { OpEncoding::m3 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m3 }, { Symbols::m32int } }
        };
        oplookup_x86["fsub"] = {
            { { 0xD8 }, { OpEncoding::m4 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m4 }, { Symbols::m64real } },
            { { 0xD8, 0xE0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xE0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86["fisub"] = {
            { { 0xDE }, { OpEncoding::m4 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m4 }, { Symbols::m32int } }
        };
        oplookup_x86["fsubr"] = {
            { { 0xD8 }, { OpEncoding::m5 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m5 }, { Symbols::m64real } },
            { { 0xD8, 0xE8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xE8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86["fisubr"] = {
            { { 0xDE }, { OpEncoding::m5 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m5 }, { Symbols::m32int } }
        };
        oplookup_x86["fdiv"] = {
            { { 0xD8 }, { OpEncoding::m6 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m6 }, { Symbols::m64real } },
            { { 0xD8, 0xF0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xF0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86["fidiv"] = {
            { { 0xDE }, { OpEncoding::m6 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m6 }, { Symbols::m32int } }
        };
        oplookup_x86["fdivr"] = {
            { { 0xD8 }, { OpEncoding::m7 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m7 }, { Symbols::m64real } },
            { { 0xD8, 0xF8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xF8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86["fidivr"] = {
            { { 0xDE }, { OpEncoding::m7 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m7 }, { Symbols::m32int } }
        };
        oplookup_x86["fld"] = {
            { { 0xD9 }, { OpEncoding::m0 }, { Symbols::m32real } },
            { { 0xDD }, { OpEncoding::m0 }, { Symbols::m64real } },
            { { 0xD9, 0xC0 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xDB }, { OpEncoding::m5 }, { Symbols::m80real } }
        };
        oplookup_x86["fst"] = {
            { { 0xD9 }, { OpEncoding::m2 }, { Symbols::m32real } },
            { { 0xDD }, { OpEncoding::m2 }, { Symbols::m64real } },
            { { 0xDD, 0xD0 }, { OpEncoding::i }, { Symbols::sti } }
        };
        oplookup_x86["fstp"] = {
            { { 0xD9 }, { OpEncoding::m3 }, { Symbols::m32real } },
            { { 0xDB }, { OpEncoding::m7 }, { Symbols::m80real } },
            { { 0xDD }, { OpEncoding::m3 }, { Symbols::m64real } },
            { { 0xDD, 0xD8 }, { OpEncoding::i }, { Symbols::sti } }
        };
        oplookup_x86["frstor"] = {
            { { 0xDD }, { OpEncoding::m4 }, { Symbols::m94_108byte } }
        };
        oplookup_x86["fnsave"] = {
            { { 0xDD }, { OpEncoding::m6 }, { Symbols::m94_108byte } }
        };
        oplookup_x86["fnstsw"] = {
            { { 0xDD }, { OpEncoding::m7 }, { Symbols::m2byte } },
            { { 0xDF, 0xE0 }, { }, { Symbols::ax } }
        };
        oplookup_x86["ffree"] = {
            { { 0xDD, 0xC0 }, { OpEncoding::i }, { Symbols::sti } }
        };
        oplookup_x86["fldenv"] = {
            { { 0xD9 }, { OpEncoding::m4 }, { Symbols::m14_28byte } }
        };
        oplookup_x86["fldcw"] = {
            { { 0xD9 }, { OpEncoding::m5 }, { Symbols::m2byte } }
        };
        oplookup_x86["fnstenv"] = {
            { { 0xD9 }, { OpEncoding::m6 }, { Symbols::m14_28byte } }
        };
        oplookup_x86["fnstcw"] = {
            { { 0xD9 }, { OpEncoding::m7 }, { Symbols::m2byte } }
        };
        oplookup_x86["fxch"] = {
            { { 0xD9, 0xC8 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xD9, 0xC9 }, { }, { } }
        };
        oplookup_x86["fnop"] = { { { 0xD9, 0xD0 }, { }, { } } };
        oplookup_x86["fchs"] = { { { 0xD9, 0xE0 }, { }, { } } };
        oplookup_x86["fabs"] = { { { 0xD9, 0xE1 }, { }, { } } };
        oplookup_x86["ftst"] = { { { 0xD9, 0xE4 }, { }, { } } };
        oplookup_x86["fxam"] = { { { 0xD9, 0xE5 }, { }, { } } };
        oplookup_x86["fld1"] = { { { 0xD9, 0xE8 }, { }, { } } };
        oplookup_x86["fldl2t"] = { { { 0xD9, 0xE9 }, { }, { } } };
        oplookup_x86["fldl2e"] = { { { 0xD9, 0xEA }, { }, { } } };
        oplookup_x86["fldpi"] = { { { 0xD9, 0xEB }, { }, { } } };
        oplookup_x86["fldlg2"] = { { { 0xD9, 0xEC }, { }, { } } };
        oplookup_x86["fldln2"] = { { { 0xD9, 0xED }, { }, { } } };
        oplookup_x86["fldz"] = { { { 0xD9, 0xEE }, { }, { } } };
        oplookup_x86["f2xm1"] = { { { 0xD9, 0xF0 }, { }, { } } };
        oplookup_x86["fyl2x"] = { { { 0xD9, 0xF1 }, { }, { } } };
        oplookup_x86["fptan"] = { { { 0xD9, 0xF2 }, { }, { } } };
        oplookup_x86["fpatan"] = { { { 0xD9, 0xF3 }, { }, { } } };
        oplookup_x86["fxtract"] = { { { 0xD9, 0xF4 }, { }, { } } };
        oplookup_x86["fprem1"] = { { { 0xD9, 0xF5 }, { }, { } } };
        oplookup_x86["fdecstp"] = { { { 0xD9, 0xF6 }, { }, { } } };
        oplookup_x86["fincstp"] = { { { 0xD9, 0xF7 }, { }, { } } };
        oplookup_x86["fprem"] = { { { 0xD9, 0xF8 }, { }, { } } };
        oplookup_x86["fyl2xp1"] = { { { 0xD9, 0xF9 }, { }, { } } };
        oplookup_x86["fsqrt"] = { { { 0xD9, 0xFA }, { }, { } } };
        oplookup_x86["fsincos"] = { { { 0xD9, 0xFB }, { }, { } } };
        oplookup_x86["frndint"] = { { { 0xD9, 0xFC }, { }, { } } };
        oplookup_x86["fscale"] = { { { 0xD9, 0xFD }, { }, { } } };
        oplookup_x86["fsin"] = { { { 0xD9, 0xFE }, { }, { } } };
        oplookup_x86["fcos"] = { { { 0xD9, 0xFF }, { }, { } } };
        oplookup_x86["hlt"] = { { { 0xF4 }, { }, { } } };
        oplookup_x86["inc"] = {
            { { 0x40 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0xFE }, { OpEncoding::m0 }, { Symbols::rm8 } },
            { { 0xFF }, { OpEncoding::m0 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m0 }, { Symbols::rm32 } },
        };
        oplookup_x86["in"] = {
            { { 0xE4 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0xE5 }, { OpEncoding::ib }, { Symbols::ax, Symbols::imm8 } },
            { { 0xE5 }, { OpEncoding::ib }, { Symbols::eax, Symbols::imm8 } },
            { { 0xEC }, { }, { Symbols::al, Symbols::dx } },
            { { 0xED }, { }, { Symbols::ax, Symbols::dx } },
            { { 0xED }, { }, { Symbols::eax, Symbols::dx } }
        };
        oplookup_x86["ins"] = {
            { { 0x6C }, { }, { Symbols::m8, Symbols::dx } },
            { { 0x6D }, { }, { Symbols::m16, Symbols::dx } },
            { { 0x6D }, { }, { Symbols::m32, Symbols::dx } }
        };
        oplookup_x86["int3"] = { { { 0xCC }, { }, { } } };
        oplookup_x86["int"] = {
            { { 0xCD }, { OpEncoding::ib }, { Symbols::imm8 } }
        };
        oplookup_x86["into"] = { { { 0xCE }, { }, { } } };
        oplookup_x86["iret"] = { { { 0xCF }, { }, { } } };
        oplookup_x86["iretd"] = { { { 0xCF }, { }, { } } };
        oplookup_x86["idiv"] = {
            { { 0xF6 }, { OpEncoding::m7 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m7 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m7 }, { Symbols::rm32 } },
        };
        oplookup_x86["imul"] = {
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
            { { 0x0F, 0xAF }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0xAF }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } }
        };
        oplookup_x86["jmp"] = {
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
        oplookup_x86["jo"] = {
            { { 0x70 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x80 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jno"] = {
            { { 0x71 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x81 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jb"] = {
            { { 0x72 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x82 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jae"] = {
            { { 0x73 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x83 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jnb"] = {
            { { 0x73 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x83 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["je"] = {
            { { 0x74 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x84 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jz"] = {
            { { 0x74 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x84 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jne"] = {
            { { 0x75 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x85 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jnz"] = {
            { { 0x75 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x85 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jbe"] = {
            { { 0x76 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x86 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jna"] = {
            { { 0x76 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x86 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["ja"] = {
            { { 0x77 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x87 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["js"] = {
            { { 0x78 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x88 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jns"] = {
            { { 0x79 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x89 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jp"] = {
            { { 0x7A }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8A }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jpo"] = {
            { { 0x7B }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8B }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jl"] = {
            { { 0x7C }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8C }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jnl"] = {
            { { 0x7D }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8D }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jle"] = {
            { { 0x7E }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8E }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jng"] = {
            { { 0x7E }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8E }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["jg"] = {
            { { 0x7F }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8F }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86["lahf"] = { { { 0x9F }, { } } };
        oplookup_x86["leave"] = { { { 0xC9 }, { } } };
        oplookup_x86["lea"] = {
            { { 0x8D }, { OpEncoding::r }, { Symbols::r16, Symbols::m } },
            { { 0x8D }, { OpEncoding::r }, { Symbols::r32, Symbols::m } },
        };
        oplookup_x86["les"] = {
            { { 0xC4 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0xC4 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } }
        };
        oplookup_x86["lds"] = {
            { { 0xC5 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0xC5 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } }
        };
        oplookup_x86["lodsb"] = { { { 0xAC }, { } } };
        oplookup_x86["lodsd"] = { { { 0xAD }, { } } };
        oplookup_x86["loopne"] = { { { 0xE0 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86["loopnz"] = { { { 0xE0 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86["loope"] = { { { 0xE1 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86["loopz"] = { { { 0xE1 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86["loop"] = { { { 0xE2 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86["mov"] = {
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
        oplookup_x86["movs"] = {
            { { 0xA4 }, { }, { Symbols::m8, Symbols::m8 } },
            { { 0xA5 }, { }, { Symbols::m16, Symbols::m16 } },
            { { 0xA5 }, { }, { Symbols::m32, Symbols::m32 } },
        };
        oplookup_x86["mul"] = {
            { { 0xF6 }, { OpEncoding::m4 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m4 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m4 }, { Symbols::rm32 } },
        };
        oplookup_x86["neg"] = {
            { { 0xF6 }, { OpEncoding::m3 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m3 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m3 }, { Symbols::rm32 } },
        };
        oplookup_x86["nop"] = {
            { { 0x90 }, { }, { } }
        };
        oplookup_x86["not"] = {
            { { 0xF6 }, { OpEncoding::m2 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m2 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m2 }, { Symbols::rm32 } },
        };
        oplookup_x86["out"] = {
            { { 0xE6 }, { OpEncoding::ib }, { Symbols::imm8, Symbols::al } },
            { { 0xE7 }, { OpEncoding::ib }, { Symbols::imm8, Symbols::ax } },
            { { 0xE7 }, { OpEncoding::ib }, { Symbols::imm8, Symbols::eax } },
            { { 0xEE }, { }, { Symbols::dx, Symbols::al } },
            { { 0xEF }, { }, { Symbols::dx, Symbols::ax } },
            { { 0xEF }, { }, { Symbols::dx, Symbols::eax } }
        };
        oplookup_x86["outs"] = {
            { { 0x6E }, { }, { Symbols::m8, Symbols::dx } },
            { { 0x6F }, { }, { Symbols::m16, Symbols::dx } },
            { { 0x6F }, { }, { Symbols::m32, Symbols::dx } }
        };
        oplookup_x86["pop"] = {
            { { 0x58 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0x8F }, { OpEncoding::m0 }, { Symbols::m32 } },
            { { 0x07 }, { }, { Symbols::es } },
            { { 0x17 }, { }, { Symbols::ss } },
            { { 0x1F }, { }, { Symbols::ds } },
            { { 0x0F, 0xA1 }, { }, { Symbols::fs } },
            { { 0x0F, 0xA9 }, { }, { Symbols::gs } }
        };
        oplookup_x86["popf"] = { { { 0x9D }, { } } };
        oplookup_x86["popfd"] = { { { 0x9D }, { } } };
        oplookup_x86["push"] = {
            { { 0x68 }, { }, { Symbols::imm32 } },
            { { 0x6A }, { }, { Symbols::imm8 } },
            { { 0x50 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0x06 }, { }, { Symbols::es } },
            { { 0x0E }, { }, { Symbols::cs } },
            { { 0x16 }, { }, { Symbols::ss } },
            { { 0x1E }, { }, { Symbols::ds } },
            { { 0x0F, 0xA0 }, { }, { Symbols::fs } },
            { { 0x0F, 0xA8 }, { }, { Symbols::gs } },
            { { 0xFF }, { OpEncoding::m6 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m6 }, { Symbols::rm32 } },
        };
        oplookup_x86["pushf"] = { { { 0x9C }, { } } };
        oplookup_x86["pushfd"] = { { { 0x9C }, { } } };
        oplookup_x86["ret"] = {
            { { 0xC2 }, { OpEncoding::iw }, { Symbols::imm16 } },
            { { 0xCA }, { OpEncoding::iw }, { Symbols::imm16 } },
            { { 0xCB }, { }, { } }
        };
        oplookup_x86["retn"] = { { { 0xC3 }, { } } };
        oplookup_x86["rcl"] = {
            { { 0xC0 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86["rcr"] = {
            { { 0xC0 }, { OpEncoding::m3, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m3, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86["rol"] = {
            { { 0xC0 }, { OpEncoding::m0, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m0, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86["ror"] = {
            { { 0xC0 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86["sahf"] = { { { 0x9E }, { } } };
        oplookup_x86["sal"] = {
            { { 0xC0 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86["sar"] = {
            { { 0xC0 }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86["scasb"] = { { { 0xAE }, { } } };
        oplookup_x86["scasd"] = { { { 0xAF }, { } } };
        oplookup_x86["shr"] = {
            { { 0xC0 }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86["stosb"] = { { { 0xAA }, { } } };
        oplookup_x86["stosd"] = { { { 0xAB }, { } } };
        oplookup_x86["stc"] = { { { 0xF9 }, { } } };
        oplookup_x86["std"] = { { { 0xFD }, { } } };
        oplookup_x86["sti"] = { { { 0xFB }, { } } };
        oplookup_x86["test"] = {
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
        oplookup_x86["wait"] = {
            { { 0x9B }, { }, { } }
        };
        oplookup_x86["xchg"] = {
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
        oplookup_x86["xlatb"] = { { { 0xD7 }, { } } };

        // Extended SIMD instructions
        oplookup_x86["sldt"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m0 }, { Symbols::rm16 } },
            { { 0x0F, 0x00 }, { OpEncoding::m0 }, { Symbols::rm32 } },
        };
        oplookup_x86["str"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m1 }, { Symbols::rm16 } },
        };
        oplookup_x86["lldt"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m2 }, { Symbols::rm16 } },
        };
        oplookup_x86["ltr"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m3 }, { Symbols::rm16 } },
        };
        oplookup_x86["verr"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m4 }, { Symbols::rm16 } },
        };
        oplookup_x86["verw"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m5 }, { Symbols::rm16 } },
        };
        oplookup_x86["sgdt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m0 }, { Symbols::m } },
        };
        oplookup_x86["sidt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m1 }, { Symbols::m } },
        };
        oplookup_x86["lgdt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m2 }, { Symbols::m16_32 } },
        };
        oplookup_x86["lidt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m3 }, { Symbols::m16_32 } },
        };
        oplookup_x86["smsw"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m4 }, { Symbols::rm16 } },
            { { 0x0F, 0x01 }, { OpEncoding::m5 }, { Symbols::rm32 } },
        };
        oplookup_x86["lmsw"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m6 }, { Symbols::rm16 } },
        };
        oplookup_x86["invlpg"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m7 }, { Symbols::m } },
        };
        oplookup_x86["lar"] = {
            { { 0x0F, 0x02 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x02 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["lsl"] = {
            { { 0x0F, 0x03 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x03 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["clts"] = { { { 0x0F, 0x06 }, { }, { } } };
        oplookup_x86["invd"] = { { { 0x0F, 0x08 }, { }, { } } };
        oplookup_x86["wbinvd"] = { { { 0x0F, 0x09 }, { }, { } } };
        oplookup_x86["ud2"] = { { { 0x0F, 0x0B }, { }, { } } };
        oplookup_x86["movups"] = {
            { { 0x0F, 0x10 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } },
            { { 0x0F, 0x11 }, { OpEncoding::r }, { Symbols::xmm_m128, Symbols::xmm } }
        };
        oplookup_x86["movhlps"] = {
            { { 0x0F, 0x12 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm2 } }
        };
        oplookup_x86["movlps"] = {
            { { 0x0F, 0x12 }, { OpEncoding::r }, { Symbols::xmm, Symbols::m64 } },
            { { 0x0F, 0x13 }, { OpEncoding::r }, { Symbols::m64, Symbols::xmm } }
        };
        oplookup_x86["unpcklps"] = {
            { { 0x0F, 0x14 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["unpckhps"] = {
            { { 0x0F, 0x15 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["movhps"] = {
            { { 0x0F, 0x16 }, { OpEncoding::r }, { Symbols::xmm, Symbols::m64 } },
            { { 0x0F, 0x17 }, { OpEncoding::r }, { Symbols::m64, Symbols::xmm } }
        };
        oplookup_x86["movlhps"] = {
            { { 0x0F, 0x16 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm2 } }
        };
        oplookup_x86["prefetcht0"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m0 }, { Symbols::m8 } }
        };
        oplookup_x86["prefetcht1"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m1 }, { Symbols::m8 } }
        };
        oplookup_x86["prefetcht2"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m2 }, { Symbols::m8 } }
        };
        oplookup_x86["prefetchnta"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m3 }, { Symbols::m8 } }
        };
        oplookup_x86["movaps"] = {
            { { 0x0F, 0x28 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } },
            { { 0x0F, 0x29 }, { OpEncoding::r }, { Symbols::xmm_m128, Symbols::xmm } }
        };
        oplookup_x86["cvtpi2ps"] = {
            { { 0x0F, 0x2A }, { OpEncoding::r }, { Symbols::xmm, Symbols::mm_m64 } },
        };
        oplookup_x86["movntps"] = {
            { { 0x0F, 0x2B }, { OpEncoding::r }, { Symbols::m128, Symbols::xmm } },
        };
        oplookup_x86["cvttps2pi"] = {
            { { 0x0F, 0x2C }, { OpEncoding::r }, { Symbols::mm, Symbols::xmm_m64 } },
        };
        oplookup_x86["cvtps2pi"] = {
            { { 0x0F, 0x2D }, { OpEncoding::r }, { Symbols::mm, Symbols::xmm_m64 } },
        };
        oplookup_x86["ucomiss"] = {
            { { 0x0F, 0x2E }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } },
        };
        oplookup_x86["comiss"] = {
            { { 0x0F, 0x2F }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } },
        };
        oplookup_x86["wrmsr"] = { { { 0x0F, 0x30 }, { }, { } } };
        oplookup_x86["rdtsc"] = { { { 0x0F, 0x31 }, { }, { } } };
        oplookup_x86["rdmsr"] = { { { 0x0F, 0x32 }, { }, { } } };
        oplookup_x86["rdpmc"] = { { { 0x0F, 0x33 }, { }, { } } };
        oplookup_x86["sysenter"] = { { { 0x0F, 0x34 }, { }, { } } };
        oplookup_x86["sysexit"] = { { { 0x0F, 0x35 }, { }, { } } };
        oplookup_x86["movmskps"] = {
            { { 0x0F, 0x50 }, { OpEncoding::r }, { Symbols::r32, Symbols::xmm } }
        };
        oplookup_x86["sqrtps"] = {
            { { 0x0F, 0x51 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["rsqrtps"] = {
            { { 0x0F, 0x52 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["rcpps"] = {
            { { 0x0F, 0x53 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["andps"] = {
            { { 0x0F, 0x54 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["andnps"] = {
            { { 0x0F, 0x55 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["orps"] = {
            { { 0x0F, 0x56 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["xorps"] = {
            { { 0x0F, 0x57 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["addps"] = {
            { { 0x0F, 0x58 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["mulps"] = {
            { { 0x0F, 0x59 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["subps"] = {
            { { 0x0F, 0x5C }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["minps"] = {
            { { 0x0F, 0x5D }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["divps"] = {
            { { 0x0F, 0x5E }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["maxps"] = {
            { { 0x0F, 0x5F }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86["punpcklbw"] = {
            { { 0x0F, 0x60 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m32 } }
        };
        oplookup_x86["punpcklbd"] = {
            { { 0x0F, 0x61 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m32 } }
        };
        oplookup_x86["punpcklbq"] = {
            { { 0x0F, 0x62 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m32 } }
        };
        oplookup_x86["packsswb"] = {
            { { 0x0F, 0x63 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["pcmpgtb"] = {
            { { 0x0F, 0x64 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["pcmpgtw"] = {
            { { 0x0F, 0x65 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["pcmpgtd"] = {
            { { 0x0F, 0x66 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["packuswb"] = {
            { { 0x0F, 0x67 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["punpckhbw"] = {
            { { 0x0F, 0x68 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["punpckhbd"] = {
            { { 0x0F, 0x69 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["punpckhbq"] = {
            { { 0x0F, 0x6A }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["packssdw"] = {
            { { 0x0F, 0x6B }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["movd"] = {
            { { 0x0F, 0x6E }, { OpEncoding::r }, { Symbols::mm, Symbols::rm32 } },
            { { 0x0F, 0x7E }, { OpEncoding::r }, { Symbols::rm32, Symbols::mm } }
        };
        oplookup_x86["movq"] = {
            { { 0x0F, 0x6F }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } },
            { { 0x0F, 0x7F }, { OpEncoding::r }, { Symbols::mm_m64, Symbols::mm } }
        };
        oplookup_x86["pshufw"] = {
            { { 0x0F, 0x70 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::mm, Symbols::mm_m64, Symbols::imm8 } }
        };
        oplookup_x86["psrlw"] = {
            { { 0x0F, 0x71 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } }
        };
        oplookup_x86["psraw"] = {
            { { 0x0F, 0x71 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } }
        };
        oplookup_x86["psllw"] = {
            { { 0x0F, 0x71 }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } }
        };
        oplookup_x86["psrld"] = {
            { { 0x0F, 0x72 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } }
        };
        oplookup_x86["psrad"] = {
            { { 0x0F, 0x72 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } }
        };
        oplookup_x86["pslld"] = {
            { { 0x0F, 0x72 }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } }
        };
        oplookup_x86["psrlq"] = {
            { { 0x0F, 0x73 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } }
        };
        oplookup_x86["psllq"] = {
            { { 0x0F, 0x73 }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } }
        };
        oplookup_x86["pcmpeqb"] = {
            { { 0x0F, 0x74 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["pcmpeqw"] = {
            { { 0x0F, 0x75 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["pcmpeqd"] = {
            { { 0x0F, 0x76 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86["emms"] = { { { 0x0F, 0x77 }, { }, { } } };
        oplookup_x86["seto"] = { { { 0x0F, 0x90 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setno"] = { { { 0x0F, 0x91 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setb"] = { { { 0x0F, 0x92 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setae"] = { { { 0x0F, 0x93 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setnb"] = { { { 0x0F, 0x93 }, { }, { Symbols::rm8 } } };
        oplookup_x86["sete"] = { { { 0x0F, 0x94 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setz"] = { { { 0x0F, 0x94 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setne"] = { { { 0x0F, 0x95 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setnz"] = { { { 0x0F, 0x95 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setbe"] = { { { 0x0F, 0x96 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setna"] = { { { 0x0F, 0x96 }, { }, { Symbols::rm8 } } };
        oplookup_x86["seta"] = { { { 0x0F, 0x97 }, { }, { Symbols::rm8 } } };
        oplookup_x86["sets"] = { { { 0x0F, 0x98 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setns"] = { { { 0x0F, 0x99 }, { }, { Symbols::rm8 } } };
        oplookup_x86["setp"] = { { { 0x0F, 0x9A }, { }, { Symbols::rm8 } } };
        oplookup_x86["setpo"] = { { { 0x0F, 0x9B }, { }, { Symbols::rm8 } } };
        oplookup_x86["setl"] = { { { 0x0F, 0x9C }, { }, { Symbols::rm8 } } };
        oplookup_x86["setnl"] = { { { 0x0F, 0x9D }, { }, { Symbols::rm8 } } };
        oplookup_x86["setle"] = { { { 0x0F, 0x9E }, { }, { Symbols::rm8 } } };
        oplookup_x86["setng"] = { { { 0x0F, 0x9E }, { }, { Symbols::rm8 } } };
        oplookup_x86["setg"] = { { { 0x0F, 0x9F }, { }, { Symbols::rm8 } } };
        oplookup_x86["cpuid"] = { { { 0x0F, 0xA2 }, { }, { } } };
        oplookup_x86["bt"] = {
            { { 0x0F, 0xA3 }, { }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xA3 }, { }, { Symbols::rm32, Symbols::r32 } },
            { { 0x0F, 0xBA }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm16, Symbols::imm8 } },
            { { 0x0F, 0xBA }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup_x86["btc"] = {
            { { 0x0F, 0xBA }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm16, Symbols::imm8 } },
            { { 0x0F, 0xBA }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
            { { 0x0F, 0xBB }, { }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xBB }, { }, { Symbols::rm32, Symbols::r32 } },
        };
        oplookup_x86["bsf"] = { 
            { { 0x0F, 0xBC }, { }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0xBC }, { }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["bsr"] = { 
            { { 0x0F, 0xBD }, { }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0xBD }, { }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86["shld"] = {
            { { 0x0F, 0xA4 }, { }, { Symbols::rm16, Symbols::r16, Symbols::imm8 } },
            { { 0x0F, 0xA4 }, { }, { Symbols::rm32, Symbols::r32, Symbols::imm8 } },
            { { 0x0F, 0xA5 }, { }, { Symbols::rm16, Symbols::r16, Symbols::cl } },
            { { 0x0F, 0xA5 }, { }, { Symbols::rm32, Symbols::r32, Symbols::cl } },
        };
        oplookup_x86["rsm"] = { { { 0x0F, 0xAA }, { }, { } } };
        oplookup_x86["bts"] = {
            { { 0x0F, 0xAB }, { }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xAB }, { }, { Symbols::rm32, Symbols::r32 } },
            { { 0x0F, 0xBA }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm16, Symbols::imm8 } },
            { { 0x0F, 0xBA }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup_x86["shrd"] = {
            { { 0x0F, 0xAC }, { }, { Symbols::rm16, Symbols::r16, Symbols::imm8 } },
            { { 0x0F, 0xAC }, { }, { Symbols::rm32, Symbols::r32, Symbols::imm8 } },
            { { 0x0F, 0xAD }, { }, { Symbols::rm16, Symbols::r16, Symbols::cl } },
            { { 0x0F, 0xAD }, { }, { Symbols::rm32, Symbols::r32, Symbols::cl } },
        };
        oplookup_x86["fxsave"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m0 }, { Symbols::m512byte } }
        };
        oplookup_x86["fxrstor"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m1 }, { Symbols::m512byte } }
        };
        oplookup_x86["ldmxcsr"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m2 }, { Symbols::m32 } }
        };
        oplookup_x86["stmxcsr"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m3 }, { Symbols::m32 } }
        };
        oplookup_x86["sfence"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m7 }, { } }
        };
        oplookup_x86["cmpxchg"] = {
            { { 0x0F, 0xB0 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x0F, 0xB1 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xB1 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } }
        };
        oplookup_x86["lss"] = {
            { { 0x0F, 0xB2 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0x0F, 0xB2 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } },
        };
        oplookup_x86["btr"] = {
            { { 0x0F, 0xB3 }, { }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xB3 }, { }, { Symbols::rm32, Symbols::r32 } },
            { { 0x0F, 0xBA }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::rm16, Symbols::imm8 } },
            { { 0x0F, 0xBA }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup_x86["lfs"] = {
            { { 0x0F, 0xB4 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0x0F, 0xB4 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } },
        };
        oplookup_x86["lgs"] = {
            { { 0x0F, 0xB5 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0x0F, 0xB5 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } },
        };
        oplookup_x86["movzx"] = {
            { { 0x0F, 0xB6 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm8 } },
            { { 0x0F, 0xB6 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm8 } },
            { { 0x0F, 0xB7 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm16 } }
        };
        oplookup_x86["movsx"] = {
            { { 0x0F, 0xBE }, { OpEncoding::r }, { Symbols::r16, Symbols::rm8 } },
            { { 0x0F, 0xBE }, { OpEncoding::r }, { Symbols::r32, Symbols::rm8 } },
            { { 0x0F, 0xBF }, { OpEncoding::r }, { Symbols::r32, Symbols::rm16 } }
        };
        oplookup_x86["xadd"] = {
            { { 0x0F, 0xC0 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x0F, 0xC1 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xC1 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } }
        };
        oplookup_x86["cmpps"] = {
            { { 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::xmm, Symbols::xmm_m128, Symbols::imm8 } }
        };
        // test these ones out:
        oplookup_x86["pinsrw"] = {
            { { 0x0F, 0xC4 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::mm, Symbols::rm16, Symbols::imm8 } }
        };
        oplookup_x86["pextrw"] = {
            { { 0x0F, 0xC5 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::r32, Symbols::mm, Symbols::imm8 } }
        };

    }

    // Parses and converts assembly code string directly to
    // a stream of bytes
    ByteStream Assembler<TargetArchitecture::x86>::compile(const std::string& source, const uintptr_t offset)
    {
        ByteStream stream;

        using Symbols = BaseSet_x86::Symbols;
        using Operand = BaseSet_x86::Operand;
        using OpEncoding = BaseSet_x86::OpEncoding;
        using OpData = BaseSet_x86::OpData;

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

        // Go through the parsed nodes
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
                                        default: // Segment/Pointer Offset (Only supports hex)
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

                        //printf("(%s) (%i) operand pattern: ", node.opName.c_str(), operand.opmode);
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
            for (auto lookup = oplookup_x86.begin(); lookup != oplookup_x86.end() && !solved; lookup++)
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
                                        break;
                                    case Symbols::imm16: // To-do: optimize by enabling shorter (rel8) jump when necessary
                                        switch (opvariant.symbols[i])
                                        {
                                        case Symbols::rel16:
                                        case Symbols::rel32:
                                        case Symbols::imm32:
                                            forceValidate = true;
                                            break;
                                        }
                                        break;
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
                                            if (op.pattern.front() == "imm8" && opvariant.symbols[i] == Symbols::moffs8)
                                            {
                                                userOperands[i].opmode = Symbols::moffs8;
                                                forceValidate = true;
                                                break;
                                            }
                                            else if (op.pattern.front() == "imm16" && opvariant.symbols[i] == Symbols::moffs16)
                                            {
                                                userOperands[i].opmode = Symbols::moffs16;
                                                forceValidate = true;
                                                break;
                                            }
                                            else if (op.pattern.front() == "imm32" && opvariant.symbols[i] == Symbols::moffs32)
                                            {
                                                userOperands[i].opmode = Symbols::moffs32;
                                                forceValidate = true;
                                                break;
                                            }
                                        }

                                        if (op.opmode == Symbols::rm16)
                                        {
                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::m16_16:
                                                node.opPrefix = "66";
                                                forceValidate = true;
                                                break;
                                            }
                                        }
                                        else if (op.opmode == Symbols::rm32)
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
                                            case Symbols::m16_32:
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
                                        case Symbols::mm:
                                            userOperands[i].opmode = Symbols::mm;
                                            node.opPrefix = "66";
                                            forceValidate = true;
                                            break;
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
                                        break;
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
                            node.opPrefix = "66";

                        // Add the prefix flag
                        if (!node.opPrefix.empty())
                            if (prelookup_x86.find(node.opPrefix) != prelookup_x86.end())
                                stream.add(prelookup_x86[node.opPrefix]);

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
                                break;
                            }
                        }

                        const auto noperands = userOperands.size();
                        auto insCode = opvariant.code;
                        bool wroteCode = false;

                        uint8_t modenc = 0;

                        for (const auto entry : opvariant.entries)
                        {
                            // If the opcode format is "+rd", then the final opcode byte
                            // is used to denote the (8-32 bit) register
                            switch (entry)
                            {
                            case OpEncoding::m0:
                                modenc += 0 << 3;
                                break;
                            case OpEncoding::m1:
                                modenc += 1 << 3;
                                break;
                            case OpEncoding::m2:
                                modenc += 2 << 3;
                                break;
                            case OpEncoding::m3:
                                modenc += 3 << 3;
                                break;
                            case OpEncoding::m4:
                                modenc += 4 << 3;
                                break;
                            case OpEncoding::m5:
                                modenc += 5 << 3;
                                break;
                            case OpEncoding::m6:
                                modenc += 6 << 3;
                                break;
                            case OpEncoding::m7:
                                modenc += 7 << 3;
                                break;
                            case OpEncoding::r:
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

                                modenc += opvariant.code.back();
                                wroteCode = true;
                                break;
                            default:
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

                            uint8_t modbyte = modenc;
                            uint8_t sibbyte = 0;

                            for (size_t i = 0; i < userOperands.size(); i++)
                            {
                                const auto op = userOperands[i];

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
                                    break;
                               case Symbols::moffs8:
                                   imm8value = op.imm8;
                                   hasImm8 = true;
                                   break;
                               case Symbols::moffs16:
                                   imm16value = op.imm16;
                                   hasImm16 = true;
                                   break;
                               case Symbols::moffs32:
                                   imm32value = op.imm32;
                                   hasImm32 = true;
                                   break;
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
                                case Symbols::mm:
                                    useModByte = true;
                                    modbyte += op.regs.front();
                                    break;
                                case Symbols::xmm2:
                                    useModByte = true;
                                    modbyte += 3 << 6;
                                    modbyte += op.regs.front();
                                    break;
                                case Symbols::rm8:
                                case Symbols::rm16:
                                case Symbols::rm32:
                                case Symbols::mm_m32:
                                case Symbols::mm_m64:
                                case Symbols::xmm_m32:
                                case Symbols::xmm_m64:
                                case Symbols::xmm_m128:
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
                                        modbyte += op.regs.front();
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

