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

        struct Node
        {
            enum class NodeType {
                Label,
                AsmNode
            } type;

            std::string opPrefix = "";
            std::string opName = "";
            std::string label = "";

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

        Scope scope = Scope();
        Body body = Body();
        Node currentNode = Node();

        if (source.empty())
            return stream;
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
                case ',': // asm node, moving to next operand
                case ' ':
                    if (!label.empty())
                    {
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
                            const std::vector<std::string> prefixes = { "lock" };
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
                    // if we wanted to expand the scope in some way
                    //scope.bodies.push_back(body); // redundant?
                    //body = Body();

                    currentNode.type = Node::NodeType::Label;
                    currentNode.label = label;
                    body.nodes.push_back(currentNode);
                    //body.label = label;
                    currentNode = Node();
                    label = "";
                    break;
                case '[':
                case ']':
                case '+':
                case '-':
                case '*':
                    label += c;
                    break;
                default:
                    // a-z or A-Z or 0-9 and accepted characters for operands ('[', ']', '+', '-', '*')
                    if ((c >= 0x61 && c <= 0x7A) || (c >= 0x41 && c <= 0x5A) || (c >= 0x30 && c <= 0x39))
                        label += c;
                    break;
                }

                at++;
            }

            scope.bodies.push_back(body); // redundant?
            scopes.push_back(scope);
        }

        Body mainBody = scope.bodies.front();

        auto getLabels = [&mainBody]()
        {
            std::vector<Node*> labels = {};

            for (auto& node : mainBody.nodes)
            {
                switch (node.type)
                {
                case Node::NodeType::Label:
                    labels.push_back(&node);
                    break;
                }
            }

            return labels;
        };

        /*
        //printf("body label: %s\n", body.label.c_str());
        // const std::vector<std::pair<std::string, void*>>& locations
        // 
        // Phase 1: Initial set up; Go through and parse LABELS
        for (auto& node : mainBody.nodes)
        {
            switch (node.type)
            {
            case Node::NodeType::AsmNode:
                // If the label is a location specified by the user, then we
                // replace any occurrences of the label with its corresponding
                // location, as a hex-string -- which is easy to parse later on
                for (auto& l : locations)
                {
                    for (auto& op : node.operands)
                    {
                        std::string::size_type n = 0;
                        while ((n = op.find(l.first, n)) != std::string::npos)
                        {
                            char str[10];
                            sprintf_s(str, "%08Xh", reinterpret_cast<uint32_t>(l.second));
                            op.replace(n, l.first.size(), str);
                            n += strlen(str);
                        }
                    }
                }
                break;
            }
        }
        */

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
        oplookup["add"] = {
            { { 0x00 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x01 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x02 }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
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
            { { 0x09 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x0A }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
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
            { { 0x11 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x12 }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x13 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x14 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x15 }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x15 }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["sbb"] = {
            { { 0x18 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x19 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x1A }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x1B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x1C }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x1D }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x1D }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["and"] = {
            { { 0x20 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x21 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x22 }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x23 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x24 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x25 }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x25 }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["sub"] = {
            { { 0x28 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x29 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x2A }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x2B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x2C }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x2D }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x2D }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["xor"] = {
            { { 0x30 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x31 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x32 }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x33 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x34 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x35 }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x35 }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["cmp"] = {
            { { 0x38 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x39 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x3A }, { OpEncoding::r }, { Symbols::r8, Symbols::rm8 } },
            { { 0x3B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x3C }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0x3D }, { OpEncoding::iw }, { Symbols::ax, Symbols::imm16 } },
            { { 0x3D }, { OpEncoding::id }, { Symbols::eax, Symbols::imm32 } },
            { { 0x80 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::iw }, { Symbols::rm16, Symbols::imm16 } },
            { { 0x81 }, { OpEncoding::m1, OpEncoding::id }, { Symbols::rm32, Symbols::imm32 } },
            { { 0x83 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup["inc"] = {
            { { 0x40 }, { OpEncoding::rd }, { Symbols::r32 } }
        };
        oplookup["dec"] = {
            { { 0x48 }, { OpEncoding::rd }, { Symbols::r32 } }
        };
        oplookup["push"] = {
            { { 0x50 }, { OpEncoding::rd }, { Symbols::r32 } }
        };
        oplookup["pop"] = {
            { { 0x58 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0x8F }, { OpEncoding::m0 }, { Symbols::m32 } }
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
        oplookup["mov"] = {
            { { 0x88 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x89 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x89 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x8B }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x8B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
            { { 0x8C }, { OpEncoding::r }, { Symbols::rm16, Symbols::sreg } },
            { { 0x8C }, { OpEncoding::r }, { Symbols::rm32, Symbols::sreg } },
            { { 0xB0 }, { OpEncoding::rb }, { Symbols::r8, Symbols::imm8 } },
            { { 0xB8 }, { OpEncoding::rw }, { Symbols::r16, Symbols::imm16 } },
            { { 0xB8 }, { OpEncoding::rd }, { Symbols::r32, Symbols::imm32 } },
            { { 0xC6 }, { OpEncoding::m0 }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC7 }, { OpEncoding::m0 }, { Symbols::rm16, Symbols::imm16 } },
            { { 0xC7 }, { OpEncoding::m0 }, { Symbols::rm32, Symbols::imm32 } },
        };
        oplookup["lea"] = {
            { { 0x8D }, { OpEncoding::r }, { Symbols::r16, Symbols::m } },
            { { 0x8D }, { OpEncoding::r }, { Symbols::r32, Symbols::m } },
        };
        oplookup["nop"] = { { { 0x90 }, { } } };
        oplookup["pushf"] = { { { 0x9C }, { } } };
        oplookup["pushfd"] = { { { 0x9C }, { } } };
        oplookup["popf"] = { { { 0x9D }, { } } };
        oplookup["popfd"] = { { { 0x9D }, { } } };
        oplookup["sahf"] = { { { 0x9E }, { } } };
        oplookup["lahf"] = { { { 0x9F }, { } } };
        oplookup["call"] = { { { 0xE8 }, { OpEncoding::cd }, { Symbols::rel32 } } };
        oplookup["jmp"] = { { { 0xE9 }, { OpEncoding::cd }, { Symbols::rel32 } }};
        oplookup["ret"] = { { { 0xC2 }, { OpEncoding::iw }, { Symbols::imm16 } } };
        oplookup["retn"] = { { { 0xC3 }, { } } };

        // Used to identify the correct prefix bytecode to use
        std::unordered_map<std::string, uint8_t> prelookup;
        prelookup["lock"] = BaseSet_x86::B_LOCK;
        prelookup["repne"] = BaseSet_x86::B_REPNE;
        prelookup["repe"] = BaseSet_x86::B_REPE;

        // Phase 2: Go through nodes and start 
        for (auto& node : mainBody.nodes)
        {
            switch (node.type)
            {
            case Node::NodeType::Label:
                node.streamIndex = stream.size();
                break;
            case Node::NodeType::AsmNode:
            {
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
                                // a-z or A-Z or 0-9 and accepted characters for operands ('[', ']', '+', '-', '*')
                                if ((r[n] >= 0x61 && r[n] <= 0x7A) || (r[n] >= 0x41 && r[n] <= 0x5A) || (r[n] >= 0x30 && r[n] <= 0x39))
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
                            }

                            if (isReserved)
                                continue;

                            bool isNumber = true;
                            bool isNumberHex = false;
                            size_t sizeNumber = 0; // calculate size

                            if (token.back() == 'h' && token.length() <= 9)
                            {
                                // Verify hex-encoded numbers (0-9, a-f, A-F)
                                for (size_t i = 0; i < token.length() - 1; i++)
                                {
                                    if (!((token[i] >= 0x30 && token[i] <= 0x39) || (token[i] >= 0x41 && token[i] <= 0x46) || (token[i] >= 0x61 && token[i] <= 0x66)))
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
                            else if (token.length() <= 9)
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

                            if (isNumber)
                            {
                                if (token.length() <= 8) sizeNumber = 8;
                                if (token.length() <= 4) sizeNumber = 4;
                                if (token.length() <= 2) sizeNumber = 2;

                                if (isNumberHex)
                                {
                                    switch (sizeNumber)
                                    {
                                    case 2:
                                        operand.opmode = (rm) ? operand.opmode : Symbols::imm8;
                                        operand.imm8 = std::strtoul(token.c_str(), nullptr, 16);
                                        operand.flags |= BaseSet_x86::OP_IMM8;
                                        parts.push_back("imm8");
                                        break;
                                    case 4:
                                        operand.opmode = (rm) ? operand.opmode : Symbols::imm16;
                                        operand.imm16 = std::strtoul(token.c_str(), nullptr, 16);
                                        operand.flags |= BaseSet_x86::OP_IMM16;
                                        parts.push_back("imm16");
                                        break;
                                    case 8:
                                        operand.opmode = (rm) ? operand.opmode : Symbols::imm32;
                                        operand.imm32 = std::strtoul(token.c_str(), nullptr, 16);
                                        operand.flags |= BaseSet_x86::OP_IMM32;
                                        parts.push_back("imm32");
                                        break;
                                    }
                                }
                                else
                                {
                                    switch (sizeNumber)
                                    {
                                    case 2:
                                        operand.opmode = (rm) ? operand.opmode : Symbols::imm8;
                                        operand.imm8 = std::atoi(token.c_str());
                                        operand.flags |= BaseSet_x86::OP_IMM8;
                                        parts.push_back("imm8");
                                        break;
                                    case 4:
                                        operand.opmode = (rm) ? operand.opmode : Symbols::imm16;
                                        operand.imm16 = std::atoi(token.c_str());
                                        operand.flags |= BaseSet_x86::OP_IMM16;
                                        parts.push_back("imm16");
                                        break;
                                    case 8:
                                        operand.opmode = (rm) ? operand.opmode : Symbols::imm32;
                                        operand.imm32 = std::atoi(token.c_str());
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

                    // Differentiate between relative32 values and imm32 values
                    // which we cant do without some sort of context
                    // and update the operands, directly
                    if (oplookup.find(node.opName) != oplookup.end())
                    {
                        for (auto& opvariant : oplookup[node.opName])
                        {
                            if (parts.size() == 1)
                            {
                                if (opvariant.symbols.size() - 1 >= opIndex)
                                {
                                    if (opvariant.symbols[opIndex] == Symbols::imm16 && parts.back() == "imm8")
                                    {
                                        operand.imm16 = operand.imm8;
                                        operand.imm8 = 0;
                                        operand.opmode = Symbols::imm16;
                                    }
                                    else if (opvariant.symbols[opIndex] == Symbols::imm32)
                                    {
                                        if (parts.back() == "imm8")
                                        {
                                            operand.imm32 = operand.imm8;
                                            operand.imm8 = 0;
                                            operand.opmode = Symbols::imm32;
                                        }
                                        else if (parts.back() == "imm16")
                                        {
                                            operand.imm32 = operand.imm16;
                                            operand.imm16 = 0;
                                            operand.opmode = Symbols::imm32;
                                        }
                                    }
                                    else if (opvariant.symbols[opIndex] == Symbols::rel8 && parts.back() == "imm8")
                                    {
                                        operand.rel8 = operand.imm8;
                                        operand.imm8 = 0;
                                        operand.opmode = Symbols::rel8;
                                    }
                                    else if (opvariant.symbols[opIndex] == Symbols::rel16 && parts.back() == "imm16")
                                    {
                                        operand.rel16 = operand.imm16;
                                        operand.imm16 = 0;
                                        operand.opmode = Symbols::rel16;
                                    }
                                    else if (opvariant.symbols[opIndex] == Symbols::rel32 && parts.back() == "imm16")
                                    {
                                        operand.rel32 = operand.imm16;
                                        operand.imm16 = 0;
                                        operand.opmode = Symbols::rel32;
                                    }
                                    else if (opvariant.symbols[opIndex] == Symbols::rel32 && parts.back() == "imm32")
                                    {
                                        operand.rel32 = operand.imm32;
                                        operand.imm32 = 0;
                                        operand.opmode = Symbols::rel32;
                                    }
                                }
                            }
                        }
                    }

                    operand.pattern = parts;
                    node.opData.operands.push_back(operand);
                }

                // if both operands are a reg, then use an "rm" on the left or right
                // because then we can match it to the correct { r32, rm32 } opcode.
                // We determine the mode later.
                if (!node.hasMod && node.opData.operands.size() > 1)
                {
                    for (auto op = node.opData.operands.begin(); op != node.opData.operands.end(); op++)
                    {
                        switch (op->opmode)
                        {
                        case Symbols::r8:
                            op->opmode = Symbols::rm8;
                            break;
                        case Symbols::r16:
                            op->opmode = Symbols::rm16;
                            break;
                        case Symbols::r32:
                            auto operand1 = &node.opData.operands.front();
                            auto operand2 = &node.opData.operands.back();

                            if (operand1->opmode == operand2->opmode)
                                operand2->opmode = Symbols::rm32;
                            
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

            // Look up the corresponding opcode information
            // for our parsed opcode
            for (const auto& lookup : oplookup)
            {
                if (lookup.first == node.opName)
                {
                    for (auto& opvariant : lookup.second)
                    {
                        bool reject = false;

                        // Test the operands tied to this opcode, if there are any
                        if (!node.opData.operands.empty())
                        {
                            if (node.opData.operands.size() != opvariant.symbols.size())
                                continue;
                            else
                            {
                                for (size_t i = 0; i < opvariant.symbols.size() && !reject; i++)
                                {
                                    bool regspec = false;
                                    bool forceValidate = false;
                                    auto op = node.opData.operands[i];

                                    switch (op.opmode)
                                    {
                                    case Symbols::rm32:
                                        switch (opvariant.symbols[i])
                                        {
                                        // If this opcode variation uses m or m32, we accept
                                        // it because our parser only stores it under rm32
                                        case Symbols::m:
                                            forceValidate = true;
                                            break;
                                        case Symbols::m32:
                                            forceValidate = true;
                                            break;
                                        }
                                        break;
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
                                        node.opData.operands[i].opmode = Symbols::not_set;
                                    }
                                    else if (!forceValidate)
                                    {
                                        // Reject this opcode comparison if the (other) opmodes do not match
                                        //printf("%i (%s) == %i?\n", node.opData.operands[i].opmode, node.operands[i].c_str(), opvariant.symbols[i]);
                                        reject = (node.opData.operands[i].opmode != opvariant.symbols[i]);
                                    }
                                }

                                if (reject)
                                    continue;
                            }
                        }

                        if (node.bitSize == 16)
                            stream.add(BaseSet_x86::B_66);

                        // Add the prefix flag
                        if (!node.opPrefix.empty())
                            if (prelookup.find(node.opPrefix) != prelookup.end())
                                stream.add(prelookup[node.opPrefix]);

                        uint8_t modbyte = 0;
                        uint8_t sibbyte = 0;

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

                        const auto noperands = node.opData.operands.size();

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

                                stream.add(opvariant.code.back() + node.opData.operands.front().regs.front());

                                // Remove the placeholder for this register -- it's a part of
                                // the instruction bytecode
                                if (noperands)
                                    node.opData.operands.erase(node.opData.operands.begin());

                                wroteCode = true;
                                break;
                            }
                        }

                        if (!wroteCode)
                        {
                            // append code for this instruction
                            for (const auto b : opvariant.code)
                                stream.add(b);
                        }

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

                            for (auto iter = node.opData.operands.begin(); iter != node.opData.operands.end(); iter++)
                            {
                                Operand op = *iter;
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
                                case Symbols::sreg:
                                case Symbols::r8:
                                case Symbols::r16:
                                case Symbols::r32:
                                    useModByte = true;
                                    modbyte += op.regs.front() << 3;
                                    break;
                                case Symbols::rm8:
                                case Symbols::rm16:
                                case Symbols::rm32:
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

