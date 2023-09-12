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
        static const std::vector<std::string> R8 = { "ah", "al", "ch", "cl", "dh", "dl", "bh", "bl" };
        static const std::vector<std::string> R16 = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
        static const std::vector<std::string> R32 = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
    };

    BaseSet_x86::Opcode Disassembler<TargetArchitecture::x86>::readNext()
    {
        BaseSet_x86::Opcode opcode;

        // Coming soon!

        return opcode;
    }

    // Parses and converts assembly code string directly to
    // a stream of bytes
    ByteStream Assembler<TargetArchitecture::x86>::compile(const std::string& source, const std::vector<std::pair<std::string, void*>>& locations)
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

            std::vector<std::string> operands = {};

            BaseSet_x86::Opcode opData;

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

                    currentNode.opName = label;
                    currentNode.type = Node::NodeType::Label;
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

        //printf("body label: %s\n", body.label.c_str());

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
        oplookup["inc"] = { { { 0x40 }, { OpEncoding::rd }, { Symbols::r32 } } };
        oplookup["dec"] = { { { 0x48 }, { OpEncoding::rd }, { Symbols::r32 } } };
        oplookup["push"] = { { { 0x50 }, { OpEncoding::rd }, { Symbols::r32 } } };
        oplookup["pop"] = { { { 0x58 }, { OpEncoding::rd }, { Symbols::r32 } } };
        oplookup["add"] = {
            { { 0x01 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x03 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } }
        };
        oplookup["mov"] = {
            { { 0x89 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } },
            { { 0x8B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } }
        };
        oplookup["call"] = { { { 0xE8 }, { OpEncoding::cd }, { Symbols::rel32 } } };
        oplookup["jmp"] = { { { 0xE9 }, { OpEncoding::cd }, { Symbols::rel32 } } };
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

                break;
            case Node::NodeType::AsmNode:
            {
                for (size_t opIndex = 0; opIndex < node.operands.size(); opIndex++)
                {
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
                            operand.opmode = Symbols::rm32;
                            parts.push_back(token);
                            token = next(at);
                            parts.push_back("mul");
                            operand.mul = std::atoi(token.c_str());
                            continue;
                        case '[':
                            node.hasMod = true;
                            node.modIndex = opIndex;
                            operand.flags |= BaseSet_x86::OP_RM;
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
                                    //printf("8-bit reg match: %s\n", token.c_str());
                                    parts.push_back("r8");
                                    operand.regs.push_back(i);
                                    isReserved = true;
                                }
                                else if (token == Mnemonics::R16[i])
                                {
                                    operand.opmode = (rm) ? Symbols::rm16 : Symbols::r16;
                                    //printf("16-bit reg match: %s\n", token.c_str());
                                    parts.push_back("r16");
                                    operand.regs.push_back(i);
                                    isReserved = true;
                                }
                                else if (token == Mnemonics::R32[i])
                                {
                                    operand.opmode = (rm) ? Symbols::rm32 : Symbols::r32;
                                    //printf("32-bit reg match: %s\n", token.c_str());
                                    parts.push_back("r32");
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
                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::moffs8;
                                        operand.imm8 = std::strtoul(token.c_str(), nullptr, 16);
                                        operand.flags |= BaseSet_x86::OP_IMM8;
                                        parts.push_back("imm8");
                                        break;
                                    case 4:
                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::moffs16;
                                        operand.imm16 = std::strtoul(token.c_str(), nullptr, 16);
                                        operand.flags |= BaseSet_x86::OP_IMM16;
                                        parts.push_back("imm16");
                                        break;
                                    case 8:
                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::moffs32;
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
                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::moffs8;
                                        operand.imm8 = std::atoi(token.c_str());
                                        operand.flags |= BaseSet_x86::OP_IMM8;
                                        parts.push_back("imm8");
                                        break;
                                    case 4:
                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::moffs16;
                                        operand.imm16 = std::atoi(token.c_str());
                                        operand.flags |= BaseSet_x86::OP_IMM16;
                                        parts.push_back("imm16");
                                        break;
                                    case 8:
                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::moffs32;
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
                    if (oplookup.find(node.opName) != oplookup.end())
                    {
                        for (auto& opvariant : oplookup[node.opName])
                        {
                            if (opvariant.symbols.size() - 1 >= opIndex)
                            {
                                if (opvariant.symbols[opIndex] == Symbols::rel8 && token == "imm8")
                                {
                                    operand.rel8 = operand.imm8;
                                    operand.imm8 = 0;
                                    operand.opmode = Symbols::rel8;
                                }
                                else if (opvariant.symbols[opIndex] == Symbols::rel16 && token == "imm16")
                                {
                                    operand.rel16 = operand.imm16;
                                    operand.imm16 = 0;
                                    operand.opmode = Symbols::rel16;
                                }
                                else if (opvariant.symbols[opIndex] == Symbols::rel32 && token == "imm32")
                                {
                                    operand.rel32 = operand.imm32;
                                    operand.imm32 = 0;
                                    operand.opmode = Symbols::rel32;
                                }
                            }
                        }
                    }

                    operand.pattern = parts;
                    node.opData.operands.push_back(operand);
                }

                // if both operands are a reg, then use an "rm" on the left or right
                // because then we can match it to the correct { r32, rm32 } opcode.
                // We determine rm information later
                if (node.opData.operands.size() == 2)
                {
                    auto operand1 = &node.opData.operands.front();
                    auto operand2 = &node.opData.operands.back();

                    if (operand1->opmode == operand2->opmode)
                    {
                        switch (operand2->opmode)
                        {
                        case Symbols::r8:
                            operand2->opmode = Symbols::rm8;
                            break;
                        case Symbols::r16:
                            operand2->opmode = Symbols::rm16;
                            break;
                        case Symbols::r32:
                            operand2->opmode = Symbols::rm32;
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
                            if (node.opData.operands.size() == opvariant.symbols.size())
                            {
                                for (size_t i = 0; i < opvariant.symbols.size() && !reject; i++)
                                    //printf("%i (%s) == %i?\n", node.opData.operands[i].opmode, node.operands[i].c_str(), opvariant.symbols[i]);
                                    reject = (node.opData.operands[i].opmode != opvariant.symbols[i]);

                                if (reject)
                                    continue;
                            }
                            else
                                break;
                        }

                        // Add the prefix flag
                        if (prelookup.find(node.opPrefix) != prelookup.end())
                            stream.add(prelookup[node.opPrefix]);

                        // If the opcode format is "+rd", then the final opcode byte
                        // is used to denote the (8-32 bit) register
                        auto firstEntry = (!opvariant.entries.empty()) ? opvariant.entries.front() : OpEncoding::none;
                        if (firstEntry == OpEncoding::rb || firstEntry == OpEncoding::rw || firstEntry == OpEncoding::rd)
                        {
                            if (opvariant.code.size() > 1)
                                for (size_t i = 0; i < opvariant.code.size() - 1; i++)
                                    stream.add(opvariant.code[i]);

                            stream.add(opvariant.code.back() + node.opData.operands.front().regs.front());

                            reject = true;
                        }

                        if (reject)
                            break;

                        if (!node.opPrefix.empty())
                            if (prelookup.find(node.opPrefix) != prelookup.end())
                                stream.add(prelookup[node.opPrefix]);

                        for (const auto b : opvariant.code)
                            stream.add(b);

                        // Continue -- generate the rest of the code for this instruction
                        // 
                        const auto noperands = node.opData.operands.size();

                        if (noperands)
                        {
                            uint8_t modbyte = 0;
                            uint8_t sibbyte = 0;

                            bool hasSib = false;
                            bool hasImm8 = false, hasImm16 = false, hasImm32 = false;
                            bool useModByte = false;

                            // We will use these also for displacement values
                            uint8_t imm8value = 0;
                            uint16_t imm16value = 0;
                            uint32_t imm32value = 0;

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
                                case Symbols::rel8:
                                    imm8value = op.rel8;
                                    hasImm8 = true;
                                    break;
                                case Symbols::rel16:
                                    imm16value = op.rel16;
                                    hasImm16 = true;
                                    break;
                                case Symbols::rel32:
                                    imm32value = op.rel32;
                                    hasImm32 = true;
                                    break;
                                case Symbols::r8:
                                case Symbols::r16:
                                case Symbols::r32:
                                    useModByte = true;
                                    if (node.hasMod)
                                        modbyte += op.regs.front() * 8;
                                    else
                                        modbyte += op.regs.front();
                                    break;
                                case Symbols::rm16:
                                case Symbols::rm32:
                                    useModByte = true;
                                    if (op.flags & BaseSet_x86::OP_IMM8)
                                    {
                                        modbyte += 0x40;
                                        imm8value = op.imm8;
                                        hasImm8 = true;
                                    }
                                    else if (op.flags & BaseSet_x86::OP_IMM32)
                                    {
                                        modbyte += 0x80;
                                        imm32value = op.imm32;
                                        hasImm32 = true;
                                    }
                                    else if (op.regs.size() == 1 && !node.hasMod)
                                    {
                                        modbyte += 0xC0 + (op.regs.front() * 8);
                                        break;
                                    }
                                    switch (op.regs.size())
                                    {
                                    case 1:
                                        modbyte += op.regs.front();
                                        break;
                                    case 2:
                                        hasSib = true;
                                        modbyte += 4;
                                        sibbyte += op.regs.front();
                                        sibbyte += op.regs.back() * 8;
                                        switch (op.mul)
                                        {
                                        case 2:
                                            sibbyte += 0x40;
                                            break;
                                        case 4:
                                            sibbyte += 0x80;
                                            break;
                                        case 8:
                                            sibbyte += 0xC0;
                                            break;
                                        }
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
                        }
                    }
                }
            }

            //printf("type %i --> %s ", node.type, node.opName.c_str());
            //for (auto& op : node.operands)
            //{
            //    printf("%s ", op.c_str());
            //}
            //printf("\n");
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

