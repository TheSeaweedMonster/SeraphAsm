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
        static const std::vector<std::string> R8ext = { "r8l", "r9l", "r10l", "r11l", "r12l", "r13l", "r14l", "r15l" };
        static const std::vector<std::string> R16 = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
        static const std::vector<std::string> R16ext = { "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" };
        static const std::vector<std::string> R32 = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
        static const std::vector<std::string> R32ext = { "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };
        static const std::vector<std::string> R64 = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" };
        static const std::vector<std::string> R64ext = { "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
        static const std::vector<std::string> SREG = { "es", "cx", "ss", "ds", "fs", "gs", "hs", "is" };
        static const std::vector<std::string> STI = { "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7" };
        static const std::vector<std::string> STIext = { "st8", "st9", "st10", "st11", "st12", "st13", "st14", "st15" };
        static const std::vector<std::string> CRI = { "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7" };
        static const std::vector<std::string> CRIext = { "cr8", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15" };
        static const std::vector<std::string> DRI = { "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7" };
        static const std::vector<std::string> DRIext = { "dr8", "dr9", "dr10", "dr11", "dr12", "dr13", "dr14", "dr15" };
        static const std::vector<std::string> MM = { "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7" };
        static const std::vector<std::string> MMext = { "mm8", "mm9", "mm10", "mm11", "mm12", "mm13", "mm14", "mm15" };
        static const std::vector<std::string> XMM = { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7" };
        static const std::vector<std::string> XMMext = { "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15" };
        static const std::vector<std::string> YMM = { "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7" };
        static const std::vector<std::string> YMMext = { "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15" };
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
            } type = NodeType::Label;

            enum class Specifier {
                None,
                BytePtr,
                WordPtr,
                DwordPtr,
                QwordPtr,
                TwordPtr
            };

            std::vector<uint8_t> prefixes = {};
            std::string opName = "";
            std::string label = "";

            uint8_t segment = 0;
            Specifier sizeIndicator = Specifier::None;

            std::vector<std::string> operands = {};

            BaseSet_x86_64::Opcode opData;

            size_t streamIndex = INT_MAX;

            // These markers are to determine the relative offset to a label
            // if the label's memory offset has not yet been determined
            bool marked = false;
            size_t markedOffset = 0;
            size_t markedOperand = 0;
            std::string markedLabel = "";

            int32_t bitSize = 0;
            bool mmx = false;
            uint8_t hasMod = 0;
            int32_t modIndex = 0xFF;

            void addPrefix(const uint8_t prefix)
            {
                for (const uint8_t found : prefixes)
                    if (found == prefix)
                        break;

                prefixes.push_back(prefix);
            }
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
        static Scope compile(const std::string& source, std::unordered_map<std::string, uint8_t>& prelookup_x86_64)
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
                    bool isNewLine = true;
                    bool isOperand = false;

                    // Begin parsing...
                    size_t at = 0;
                    while (at < source.length())
                    {
                        const auto c = source[at];

                        switch (c)
                        {
                        case ';':
                            break;
                        case '/': // Ignore basic comments ('//')
                            if (at + 1 < source.length())
                            {
                                if (source[at + 1] == '/')
                                {
                                    while (at < source.length())
                                    {
                                        if (source[at] == '\n' || source[at] == '\r') break;
                                        at++;
                                    }
                                    at--;
                                }
                            }
                            break;
                        case ',': // ',' = asm node; push previous operand and move to next operand
                            if (!label.empty())
                            {
                                // asm node, moving to (next) operand
                                if (currentNode.type == Node::NodeType::AsmNode)
                                    currentNode.operands.push_back(label);

                                label = "";
                            }
                            break;
                        case ' ': // space = push previous operand if present
                        case '\t':
                            if (label.empty())
                                break;

                            if (isOperand)
                            {
                                // Check for keywords used (at the operands)
                                const std::vector<std::string> keywords = { "none", "byte", "word", "dword", "qword", "dqword", "tword" };

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
                                }

                                break;
                            }

                            // Is this the first word on a new line ?
                            if (isNewLine)
                            {
                                bool isPrefix = false;

                                // Check prefixes...In the case of a prefix there
                                // is more than one space character in the instruction
                                for (const auto& prefix : prelookup_x86_64)
                                {
                                    if (label == prefix.first)
                                    {
                                        isPrefix = true;

                                        // Set the prefix first
                                        currentNode.type = Node::NodeType::AsmNode;
                                        currentNode.addPrefix(prelookup_x86_64[label]);
                                        break;
                                    }
                                }

                                if (!isPrefix && currentNode.opName.empty())
                                {
                                    // asm node, moving to operand(s) 
                                    currentNode.type = Node::NodeType::AsmNode;
                                    currentNode.opName = label;
                                    label = "";
                                    isNewLine = false;
                                    isOperand = true;
                                }
                            }

                            // The label has been used; start the next one
                            label = "";
                            break;
                        case '\n':
                        case '\r': // asm node is finished.
                            // First append opName in case of single opcodes
                            if (currentNode.opName.empty() && !label.empty())
                            {
                                currentNode.type = Node::NodeType::AsmNode;
                                currentNode.opName = label;
                                body.nodes.push_back(currentNode);
                                currentNode = Node();

                                label = "";

                                isNewLine = true;
                                isOperand = false;
                                break;
                            }

                            // Otherwise let's append this as an operand
                            if (isOperand && !label.empty())
                            {
                                if (currentNode.type == Node::NodeType::AsmNode)
                                {
                                    currentNode.operands.push_back(label);
                                    label = "";
                                }
                            }

                            if (!currentNode.opName.empty() || !currentNode.label.empty())
                            {
                                // append this node to the body's nodes
                                body.nodes.push_back(currentNode);
                                currentNode = Node();
                                label = "";
                            }

                            isNewLine = true;
                            isOperand = false;
                            break;
                        case ':': // initializing a label, or segment/ptr offset
                            if (isOperand)
                            {
                                if (prelookup_x86_64.find(label) != prelookup_x86_64.end())
                                {
                                    currentNode.segment = prelookup_x86_64[label];
                                    currentNode.addPrefix(currentNode.segment);
                                    label = "";
                                }
                                else
                                {
                                    label += c;
                                }
                            }
                            else if (!label.empty())
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
                            }

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

    static void initTable1(std::unordered_map<std::string, uint8_t>& prelookup_x86_64)
    {
        prelookup_x86_64 = std::unordered_map<std::string, uint8_t>();

        prelookup_x86_64["cs"] = 0x2E;
        prelookup_x86_64["ss"] = 0x36;
        prelookup_x86_64["ds"] = 0x3E;
        prelookup_x86_64["es"] = 0x26;
        prelookup_x86_64["fs"] = 0x64;
        prelookup_x86_64["gs"] = 0x65;
        prelookup_x86_64["lock"] = 0xF0;
        prelookup_x86_64["repnz"] = 0xF2;
        prelookup_x86_64["repne"] = 0xF2;
        prelookup_x86_64["repz"] = 0xF3;
        prelookup_x86_64["repe"] = 0xF3;
        prelookup_x86_64["rep"] = 0xF3;
    }
    
    static void initTable2(std::vector<std::vector<BaseSet_x86_64::OpRef>>& oplookup_x86_64)
    {
        using OpEncoding = BaseSet_x86_64::OpEncoding;
        using OpRef = BaseSet_x86_64::OpRef;
        using Symbols = BaseSet_x86_64::Symbols;

        oplookup_x86_64 = {
            /* 00 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "add", "Add r8 to rm8"}},
            /* 01 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "add", "Add r16 to rm16"},
            /* 01 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "add", "Add r32 to rm32"}},
            /* 02 */ {{{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "add", "Add rm8 to r8"}},
            /* 03 */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "add", "Add rm16 to r16"},
            /* 03 */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "add", "Add rm32 to r32"}},
            /* 04 */ {{{{}, {OpEncoding::ib}, {Symbols::al, Symbols::imm8}}, "add", "Add imm8 to AL"}},
            /* 05 */ {{{{}, {OpEncoding::iw}, {Symbols::ax, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "add", "Add imm16 to AX"},
            /* 05 */  {{{}, {OpEncoding::id}, {Symbols::eax, Symbols::imm32}}, "add", "Add imm32 to EAX"}},
            /* 06 */ {{{{}, {}, {Symbols::es}}, "push", "Push ES"}},
            /* 07 */ {{{{}, {}, {Symbols::es}}, "pop", "Pop top of stack into ES; increment stack pointer"}},
            /* 08 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "or", "rm8 OR r8"}},
            /* 09 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "or", "rm16 OR r16"},
            /* 09 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "or", "rm32 OR r32"}},
            /* 0A */ {{{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "or", "r8 OR rm8"}},
            /* 0B */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "or", "r16 OR rm16"},
            /* 0B */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "or", "r32 OR rm32"}},
            /* 0C */ {{{{}, {OpEncoding::ib}, {Symbols::al, Symbols::imm8}}, "or", "AL OR imm8"}},
            /* 0D */ {{{{}, {OpEncoding::iw}, {Symbols::ax, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "or", "AX OR imm16"},
            /* 0D */  {{{}, {OpEncoding::id}, {Symbols::eax, Symbols::imm32}}, "or", "EAX OR imm32"}},
            /* 0E */ {{{{}, {}, {Symbols::cs}}, "push", "Push CS"}},
            /* 0F */ {{{{}, {}, {}, BaseSet_x86_64::OPS_IS_PREFIX}, "", "*SIMD Extended Instructions*"},
                {}
            },
            /* 10 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "adc", "Add with carry byte register to rm8"}},
            /* 11 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "adc", "Add with carry r16 to rm16"},
            /* 11 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "adc", "Add with CF r32 to rm32"}},
            /* 12 */ {{{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "adc", "Add with carry rm8 to byte register"}},
            /* 13 */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "adc", "Add with carry rm16 to r16"},
            /* 13 */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "adc", "Add with CF rm32 to r32"}},
            /* 14 */ {{{{}, {OpEncoding::ib}, {Symbols::al, Symbols::imm8}}, "adc", "Add with carry imm8 to AL"}},
            /* 15 */ {{{{}, {OpEncoding::iw}, {Symbols::ax, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "adc", "Add with carry imm16 to AX"},
            /* 15 */  {{{}, {OpEncoding::id}, {Symbols::eax, Symbols::imm32}}, "adc", "Add with carry imm32 to EAX"}},
            /* 16 */ {{{{}, {}, {Symbols::ss}}, "push", "Push SS"}},
            /* 17 */ {{{{}, {}, {Symbols::ss}}, "pop", "Pop top of stack into SS; increment stack pointer"}},
            /* 18 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "sbb", "Subtract with borrow r8 from rm8"}},
            /* 19 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "sbb", "Subtract with borrow r16 from rm16"},
            /* 19 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "sbb", "Subtract with borrow r32 from rm32"}},
            /* 1A */ {{{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "sbb", "Subtract with borrow rm8 from r8"}},
            /* 1B */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "sbb", "Subtract with borrow rm16 from r16"},
            /* 1B */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "sbb", "Subtract with borrow rm32 from r32"}},
            /* 1C */ {{{{}, {OpEncoding::ib}, {Symbols::al, Symbols::imm8}}, "sbb", "Subtract with borrow imm8 from AL"}},
            /* 1D */ {{{{}, {OpEncoding::iw}, {Symbols::ax, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "sbb", "Subtract with borrow imm16 from AX"},
            /* 1D */  {{{}, {OpEncoding::id}, {Symbols::eax, Symbols::imm32}}, "sbb", "Subtract with borrow imm32 from EAX"}},
            /* 1E */ {{{{}, {}, {Symbols::ds}}, "push", "Push DS"}},
            /* 1F */ {{{{}, {}, {Symbols::ds}}, "pop", "Pop top of stack into DS; increment stack pointer"}},
            /* 20 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "and", "rm8 AND r8"}},
            /* 21 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "and", "rm16 AND r16"},
            /* 21 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "and", "rm32 AND r32"}},
            /* 22 */ {{{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "and", "r8 AND rm8"}},
            /* 23 */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "and", "r16 AND rm16"},
            /* 23 */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "and", "r32 AND rm32"}},
            /* 24 */ {{{{}, {OpEncoding::ib}, {Symbols::al, Symbols::imm8}}, "and", "AL AND imm8"}},
            /* 25 */ {{{{}, {OpEncoding::iw}, {Symbols::ax, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "and", "AX AND imm16"},
            /* 25 */  {{{}, {OpEncoding::id}, {Symbols::eax, Symbols::imm32}}, "and", "EAX AND imm32"}},
            /* 26 */ {{{{}, {}, {}, BaseSet_x86_64::OPS_IS_PREFIX}, "???", "Unregistered opcode"}},
            /* 27 */ {{{{}, {}, {}}, "daa", "Decimal adjust AL after addition"}},
            /* 28 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "sub", "Subtract r8 from rm8"}},
            /* 29 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "sub", "Subtract r16 from rm16"},
            /* 29 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "sub", "Subtract r32 from rm32"}},
            /* 2A */ {{{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "sub", "Subtract rm8 from r8"}},
            /* 2B */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "sub", "Subtract rm16 from r16"},
            /* 2B */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "sub", "Subtract rm32 from r32"}},
            /* 2C */ {{{{}, {OpEncoding::ib}, {Symbols::al, Symbols::imm8}}, "sub", "Subtract imm8 from AL"}},
            /* 2D */ {{{{}, {OpEncoding::iw}, {Symbols::ax, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "sub", "Subtract imm16 from AX"},
            /* 2D */  {{{}, {OpEncoding::id}, {Symbols::eax, Symbols::imm32}}, "sub", "Subtract imm32 from EAX"}},
            /* 2E */ {{{{}, {}, {}, BaseSet_x86_64::OPS_IS_PREFIX}, "???", "Unregistered opcode"}},
            /* 2F */ {{{{}, {}, {}}, "das", "Decimal adjust AL after subtraction"}},
            /* 30 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "xor", "rm8 XOR r8"}},
            /* 31 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "xor", "rm16 XOR r16"},
            /* 31 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "xor", "rm32 XOR r32"}},
            /* 32 */ {{{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "xor", "r8 XOR rm8"}},
            /* 33 */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "xor", "r16 XOR rm16"},
            /* 33 */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "xor", "r32 XOR rm32"}},
            /* 34 */ {{{{}, {OpEncoding::ib}, {Symbols::al, Symbols::imm8}}, "xor", "AL XOR imm8"}},
            /* 35 */ {{{{}, {OpEncoding::iw}, {Symbols::ax, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "xor", "AX XOR imm16"},
            /* 35 */  {{{}, {OpEncoding::id}, {Symbols::eax, Symbols::imm32}}, "xor", "EAX XOR imm32"}},
            /* 36 */ {{{{}, {}, {}, BaseSet_x86_64::OPS_IS_PREFIX}, "???", "Unregistered opcode"}},
            /* 37 */ {{{{}, {}, {}}, "aaa", "ASCII adjust AL after addition"}},
            /* 38 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "cmp", "Compare r8 with rm8"}},
            /* 39 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "cmp", "Compare r16 with rm16"},
            /* 39 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "cmp", "Compare r32 with rm32"}},
            /* 3A */ {{{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "cmp", "Compare rm8 with r8"}},
            /* 3B */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "cmp", "Compare rm16 with r16"},
            /* 3B */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "cmp", "Compare rm32 with r32"}},
            /* 3C */ {{{{}, {OpEncoding::ib}, {Symbols::al, Symbols::imm8}}, "cmp", "Compare imm8 with AL"}},
            /* 3D */ {{{{}, {OpEncoding::iw}, {Symbols::ax, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "cmp", "Compare imm16 with AX"},
            /* 3D */  {{{}, {OpEncoding::id}, {Symbols::eax, Symbols::imm32}}, "cmp", "Compare imm32 with EAX"}},
            /* 3E */ {{{{}, {}, {}, BaseSet_x86_64::OPS_IS_PREFIX}, "???", "Unregistered opcode"}},
            /* 3F */ {{{{}, {}, {}}, "aas", "ASCII adjust AL after subtraction"}},
            /* 40 */ {{{{}, {}, {Symbols::eax}}, "inc", "Increment doubleword register by 1"}},
            /* 41 */ {{{{}, {}, {Symbols::ecx}}, "inc", "Increment doubleword register by 1"}},
            /* 42 */ {{{{}, {}, {Symbols::edx}}, "inc", "Increment doubleword register by 1"}},
            /* 43 */ {{{{}, {}, {Symbols::ebx}}, "inc", "Increment doubleword register by 1"}},
            /* 44 */ {{{{}, {}, {Symbols::esp}}, "inc", "Increment doubleword register by 1"}},
            /* 45 */ {{{{}, {}, {Symbols::ebp}}, "inc", "Increment doubleword register by 1"}},
            /* 46 */ {{{{}, {}, {Symbols::esi}}, "inc", "Increment doubleword register by 1"}},
            /* 47 */ {{{{}, {}, {Symbols::edi}}, "inc", "Increment doubleword register by 1"}},
            /* 48 */ {{{{}, {}, {Symbols::eax}}, "dec", "Decrement doubleword register by 1"}},
            /* 49 */ {{{{}, {}, {Symbols::ecx}}, "dec", "Decrement doubleword register by 1"}},
            /* 4A */ {{{{}, {}, {Symbols::edx}}, "dec", "Decrement doubleword register by 1"}},
            /* 4B */ {{{{}, {}, {Symbols::ebx}}, "dec", "Decrement doubleword register by 1"}},
            /* 4C */ {{{{}, {}, {Symbols::esp}}, "dec", "Decrement doubleword register by 1"}},
            /* 4D */ {{{{}, {}, {Symbols::ebp}}, "dec", "Decrement doubleword register by 1"}},
            /* 4E */ {{{{}, {}, {Symbols::esi}}, "dec", "Decrement doubleword register by 1"}},
            /* 4F */ {{{{}, {}, {Symbols::edi}}, "dec", "Decrement doubleword register by 1"}},
            /* 50 */ {{{{}, {}, {Symbols::eax}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "push", "Push doubleword register"}},
            /* 51 */ {{{{}, {}, {Symbols::ecx}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "push", "Push doubleword register"}},
            /* 52 */ {{{{}, {}, {Symbols::edx}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "push", "Push doubleword register"}},
            /* 53 */ {{{{}, {}, {Symbols::ebx}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "push", "Push doubleword register"}},
            /* 54 */ {{{{}, {}, {Symbols::esp}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "push", "Push doubleword register"}},
            /* 55 */ {{{{}, {}, {Symbols::ebp}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "push", "Push doubleword register"}},
            /* 56 */ {{{{}, {}, {Symbols::esi}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "push", "Push doubleword register"}},
            /* 57 */ {{{{}, {}, {Symbols::edi}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "push", "Push doubleword register"}},
            /* 58 */ {{{{}, {}, {Symbols::eax}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "pop", "Pop doubleword register"}},
            /* 59 */ {{{{}, {}, {Symbols::ecx}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "pop", "Pop doubleword register"}},
            /* 5A */ {{{{}, {}, {Symbols::edx}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "pop", "Pop doubleword register"}},
            /* 5B */ {{{{}, {}, {Symbols::ebx}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "pop", "Pop doubleword register"}},
            /* 5C */ {{{{}, {}, {Symbols::esp}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "pop", "Pop doubleword register"}},
            /* 5D */ {{{{}, {}, {Symbols::ebp}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "pop", "Pop doubleword register"}},
            /* 5E */ {{{{}, {}, {Symbols::esi}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "pop", "Pop doubleword register"}},
            /* 5F */ {{{{}, {}, {Symbols::edi}, BaseSet_x86_64::OPS_DEFAULT_64_BITS}, "pop", "Pop doubleword register"}},
            /* 60 */ {{{{}, {}, {}}, "pushad", "Push all doubleword registers"}},
            /* 61 */ {{{{}, {}, {}}, "popad", "Pop all doubleword registers"}},
            /* 62 */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::m16and16}, BaseSet_x86_64::OPS_16MODE}, "bound", "Check if r16 (array index) is within bounds specified by m16&16"},
            /* 62 */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::m32and32}}, "bound", "Check if r32 (array index) is within bounds specified by m32&32"}},
            /* 63 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}}, "arpl", "Adjust RPL of rm16 to not less than RPL of r16"}},
            /* 64 */ {{{{}, {}, {}, BaseSet_x86_64::OPS_IS_PREFIX}, "???", "Unrecognized opcode"}},
            /* 65 */ {{{{}, {}, {}, BaseSet_x86_64::OPS_IS_PREFIX}, "???", "Unrecognized opcode"}},
            /* 66 */ {{{{}, {}, {}, BaseSet_x86_64::OPS_IS_PREFIX}, "???", "Unrecognized opcode"}},
            /* 67 */ {{{{}, {}, {}, BaseSet_x86_64::OPS_IS_PREFIX}, "???", "Unrecognized opcode"}},
            /* 68 */ {{{{}, {}, {Symbols::imm32}}, "push", "Push imm32 value onto the stack"}},
            /* 69 */ {{{{}, {OpEncoding::r, OpEncoding::iw}, {Symbols::r16, Symbols::rm16, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "imul", "word register < rm16 * immediate word"},
            /* 69 */  {{{}, {OpEncoding::r, OpEncoding::id}, {Symbols::r32, Symbols::rm32, Symbols::imm32}}, "imul", "doubleword register < rm32 * immediate doubleword"},
            /* 69 */  {{{}, {OpEncoding::r, OpEncoding::iw}, {Symbols::r16, Symbols::imm16}, BaseSet_x86_64::OPS_16MODE}, "imul", "word register < rm16 * immediate word"},
            /* 69 */  {{{}, {OpEncoding::r, OpEncoding::id}, {Symbols::r32, Symbols::imm32}}, "imul", "doubleword register < rm32 * immediate doubleword"}},
            /* 6A */ {{{{}, {}, {Symbols::imm8}}, "push", "Push imm8 value onto the stack"}},
            /* 6B */ {{{{}, {OpEncoding::r, OpEncoding::ib}, {Symbols::r16, Symbols::rm16, Symbols::imm8}, BaseSet_x86_64::OPS_16MODE}, "imul", "word register < rm16 * sign-extended immediate byte"},
            /* 6B */  {{{}, {OpEncoding::r, OpEncoding::ib}, {Symbols::r32, Symbols::rm32, Symbols::imm8}}, "imul", "doubleword register < rm32 * sign-extended immediate byte"},
            /* 6B */  {{{}, {OpEncoding::r, OpEncoding::ib}, {Symbols::r16, Symbols::imm8}, BaseSet_x86_64::OPS_16MODE}, "imul", "word register < rm16 * sign-extended immediate byte"},
            /* 6B */  {{{}, {OpEncoding::r, OpEncoding::ib}, {Symbols::r32, Symbols::imm8}}, "imul", "doubleword register < rm32 * sign-extended immediate byte"}},
            /* 6C */ {{{{}, {}, {}}, "insb", "Input byte from I/O port specified in DX into memory location specified with ES:(E)DI"} },
            /* 6D */ {{{{}, {}, {}}, "insd", "Input doubleword from I/O port specified in DX into memory location specified in ES:(E)DI"} },
            /* 6E */ {{{{}, {}, {}}, "outsb", "Output byte from memory location specified in DS:(E)SI to I/O port specified in DX"} },
            /* 6F */ {{{{}, {}, {}}, "outsd", "Output doubleword from memory location specified in DS:(E)SI to I/O port specified in DX"} },
            /* 70 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jo", "Jump short if overflow (OF=1)"} },
            /* 71 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jno", "Jump short if not overflow (OF=0)"} },
            /* 72 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jb", "Jump short if below/carry (CF=1)"} },
            /* 73 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jnb", "Jump short if not below/carry (if above or equal) (CF=0)"} },
            /* 74 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "je", "Jump short if equal/zero (ZF=1)"} },
            /* 75 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jne", "Jump short if not equal/zero (ZF=0)"} },
            /* 76 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jna", "Jump short if below or equal (if not above) (CF=1 or ZF=1)"} },
            /* 77 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "ja", "Jump short if above (CF=0 and ZF=0)"} },
            /* 78 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "js", "Jump short if sign (SF=1)"} },
            /* 79 */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jns", "Jump short if not sign (SF=0)"} },
            /* 7A */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jp", "Jump short if parity (PF=1)"} },
            /* 7B */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jpo", "Jump short if parity odd (PF=0)"} },
            /* 7C */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jl", "Jump short if less (not greater or equal) (SF<>OF)"} },
            /* 7D */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jnl", "Jump short if not less (if greater or equal) (SF=OF)"} },
            /* 7E */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jng", "Jump short if not greater (if less or equal) (ZF=1 or SF<>OF)"} },
            /* 7F */ {{{{}, {OpEncoding::cb}, {Symbols::rel8}}, "jg", "Jump short if greater (ZF=0 and SF=OF)"} },
            /* 80 */ {{{{}, {OpEncoding::m0, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "add", "Add imm8 to rm8"},
            /* 80 */  {{{}, {OpEncoding::m1, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "or", "rm8 OR imm8"},
            /* 80 */  {{{}, {OpEncoding::m2, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "adc", "Add with carry imm8 to rm8"},
            /* 80 */  {{{}, {OpEncoding::m3, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "sbb", "Subtract with borrow imm8 from rm8"},
            /* 80 */  {{{}, {OpEncoding::m4, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "and", "rm8 AND imm8"},
            /* 80 */  {{{}, {OpEncoding::m5, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "sub", "Subtract imm8 from rm8"},
            /* 80 */  {{{}, {OpEncoding::m6, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "xor", "rm8 XOR imm8"},
            /* 80 */  {{{}, {OpEncoding::m7, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "cmp", "Compare imm8 with rm8"}},
            /* 81 */ {{{{}, {OpEncoding::m0, OpEncoding::id}, {Symbols::rm32, Symbols::imm32}}, "add", "Add imm32 to rm32"},
            /* 81 */  {{{}, {OpEncoding::m1, OpEncoding::id}, {Symbols::rm32, Symbols::imm32}}, "or", "rm32 OR imm32"},
            /* 81 */  {{{}, {OpEncoding::m2, OpEncoding::id}, {Symbols::rm32, Symbols::imm32}}, "adc", "Add with carry imm32 to rm32"},
            /* 81 */  {{{}, {OpEncoding::m3, OpEncoding::id}, {Symbols::rm32, Symbols::imm32}}, "sbb", "Subtract with borrow imm32 from rm32"},
            /* 81 */  {{{}, {OpEncoding::m4, OpEncoding::id}, {Symbols::rm32, Symbols::imm32}}, "and", "rm32 AND imm32"}, // ***
            /* 81 */  {{{}, {OpEncoding::m5, OpEncoding::id}, {Symbols::rm32, Symbols::imm32}}, "sub", "Subtract imm32 from rm32"},
            /* 81 */  {{{}, {OpEncoding::m6, OpEncoding::id}, {Symbols::rm32, Symbols::imm32}}, "xor", "rm32 XOR imm32"},
            /* 81 */  {{{}, {OpEncoding::m7, OpEncoding::id}, {Symbols::rm32, Symbols::imm32}}, "cmp", "Compare imm32 with rm32"}},
            /* 82 */ {{{{}, {}, {}}, "???", "Unregistered opcode"}},
            /* 83 */ {{{{}, {OpEncoding::m0, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "add", "Add sign-extended imm8 to rm32"},
            /* 83 */  {{{}, {OpEncoding::m1, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "or", "rm32 OR imm8 (sign-extended)"},
            /* 83 */  {{{}, {OpEncoding::m2, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "adc", "Add with CF sign-extended imm8 into rm32"},
            /* 83 */  {{{}, {OpEncoding::m3, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "sbb", "Subtract with borrow sign-extended imm8 from rm32"},
            /* 83 */  {{{}, {OpEncoding::m4, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "and", "rm32 AND imm8 (sign-extended)"},
            /* 83 */  {{{}, {OpEncoding::m5, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "sub", "Subtract sign-extended imm8 from rm32"},
            /* 83 */  {{{}, {OpEncoding::m6, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "xor", "rm32 XOR imm8 (sign-extended)"},
            /* 83 */  {{{}, {OpEncoding::m7, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "cmp", "Compare imm8 with rm32"} },
            /* 84 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "test", "AND r8 with rm8; set SF, ZF, PF according to result"}},
            /* 85 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "test", "AND r16 with rm16; set SF, ZF, PF according to result"},
            /* 85 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "test", "AND r32 with rm32; set SF, ZF, PF according to result"}},
            /* 86 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "xchg", "Exchange r8 (byte register) with byte from rm8"},
            /* 86 */  {{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "xchg", "Exchange byte from rm8 with r8 (byte register)"}},
            /* 87 */ {{{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "xchg", "Exchange r32 with doubleword from rm32"},
            /* 87 */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "xchg", "Exchange doubleword from rm32 with r32"}},
            /* 88 */ {{{{}, {OpEncoding::r}, {Symbols::rm8, Symbols::r8}}, "mov", "Move r8 to rm8"}},
            /* 89 */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::r16}, BaseSet_x86_64::OPS_16MODE}, "mov", "Move r16 to rm16"},
            /* 89 */  {{{}, {OpEncoding::r}, {Symbols::rm32, Symbols::r32}}, "mov", "Move r32 to rm32"}},
            /* 8A */ {{{{}, {OpEncoding::r}, {Symbols::r8, Symbols::rm8}}, "mov", "Move rm8 to r8"}},
            /* 8B */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "mov", "Move rm16 to r16"},
            /* 8B */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "mov", "Move rm32 to r32"}},
            /* 8C */ {{{{}, {OpEncoding::r}, {Symbols::rm16, Symbols::sreg}}, "mov", "Move segment register to rm16"}},
            /* 8D */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::rm16}, BaseSet_x86_64::OPS_16MODE}, "lea", "Store effective address for m in register r16"},
            /* 8D */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::rm32}}, "lea", "Store effective address for m in register r32"}},
            /* 8E */ {{{{}, {OpEncoding::r}, {Symbols::sreg, Symbols::rm16}}, "mov", "Move rm16 to segment register"}},
            /* 8F */ {{{{}, {OpEncoding::m0}, {Symbols::m16}, BaseSet_x86_64::OPS_16MODE}, "pop", "Pop top of stack into m16; increment stack pointer"},
            /* 8F */  {{{}, {OpEncoding::m0}, {Symbols::m32}}, "pop", "Pop top of stack into m32; increment stack pointer"}},
            /* 90 */ {{{{}, {}, {}}, "nop", "No operation"}},
            /* 91 */ {{{{}, {}, {Symbols::eax, Symbols::ecx}}, "xchg", "Exchange r32 with EAX"}},
            /* 92 */ {{{{}, {}, {Symbols::eax, Symbols::edx}}, "xchg", "Exchange r32 with EAX"}},
            /* 93 */ {{{{}, {}, {Symbols::eax, Symbols::ebx}}, "xchg", "Exchange r32 with EAX"}},
            /* 94 */ {{{{}, {}, {Symbols::eax, Symbols::esp}}, "xchg", "Exchange r32 with EAX"}},
            /* 95 */ {{{{}, {}, {Symbols::eax, Symbols::ebp}}, "xchg", "Exchange r32 with EAX"}},
            /* 96 */ {{{{}, {}, {Symbols::eax, Symbols::esi}}, "xchg", "Exchange r32 with EAX"}},
            /* 97 */ {{{{}, {}, {Symbols::eax, Symbols::edi}}, "xchg", "Exchange r32 with EAX"}},
            /* 98 */ {{{{}, {}, {}}, "cwde", "EAX <- sign-extend of AX"}},
            /* 99 */ {{{{}, {}, {}}, "cdq", "EDX:EAX <- sign-extend of EAX"}},
            /* 9A */ {{{{}, {OpEncoding::cd}, {Symbols::ptr16_16}}, "call", "Call far, absolute, address given in operand"},
            /* 9A */  {{{}, {OpEncoding::cp}, {Symbols::ptr16_32}}, "call", "Call far, absolute, address given in operand"}},
            /* 9B */ {{{{0xD9}, {OpEncoding::m6}, {Symbols::m14_28byte}}, "fstenv", "Store FPU environment to m14byte or m28byte after checking for pending unmasked floating-point exceptions. Then mask all floating-point exceptions."},
            /* 9B */  {{{0xD9}, {OpEncoding::m7}, {Symbols::m2byte}}, "fstcw", "Store FPU control word to m2byte after checking for pending unmasked floating-point exceptions"},
            /* 9B */  {{{0xDB, 0xE2}, {}, {}}, "fclex", "Clear floating-point exception flags after checking forpending unmasked floating-point exceptions."},
            /* 9B */  {{{0xDB, 0xE3}, {}, {}}, "finit", "Initialize FPU after checking for pending unmasked floating-point exceptions."},
            /* 9B */  {{{0xDD}, {OpEncoding::m6}, {Symbols::m94_108byte}}, "fsave", "Store FPU state to m94byte or m108byte after checking for pending unmasked floating-point exceptions. Then re- initialize the FPU."},
            /* 9B */  {{{0xDD}, {OpEncoding::m7}, {Symbols::m2byte}}, "fstsw", "Store FPU status word at m2byte after checking for pending unmasked floating-point exceptions."},
            /* 9B */  {{{0xDF, 0xE0}, {}, {Symbols::ax}}, "fstsw", "Store FPU status word in AX register after checking for pending unmasked floating-point exceptions."},
            /* 9B */  {{{}, {}, {}}, "fwait", "Check pending unmasked floating-point exceptions"}},
            /* 9C */ {{{{}, {}, {}}, "pushfd", "Push EFLAGS"}},
            /* 9D */ {{{{}, {}, {}}, "popfd", "Pop top of stack into EFLAGS"}},
            /* 9E */ {{{{}, {}, {}}, "sahf", "Loads SF, ZF, AF, PF, and CF from AH into EFLAGS register"}},
            /* 9F */ {{{{}, {}, {}}, "lahf", "Load: AH = EFLAGS(SF:ZF:0:AF:0:PF:1:CF)"}},
            /* A0 */ {{{{}, {}, {Symbols::al, Symbols::moffs8}}, "mov", "Move byte at (seg:offset) to AL"}},
            /* A1 */ {{{{}, {}, {Symbols::ax, Symbols::moffs16}}, "mov", "Move word at (seg:offset) to AX"},
            /* A1 */  {{{}, {}, {Symbols::eax, Symbols::moffs32}}, "mov", "Move doubleword at (seg:offset) to EAX"}},
            /* A2 */ {{{{}, {}, {Symbols::moffs8, Symbols::al}}, "mov", "Move AL to (seg:offset)"}},
            /* A3 */ {{{{}, {}, {Symbols::moffs16, Symbols::ax}}, "mov", "Move AX to (seg:offset)"},
            /* A3 */  {{{}, {}, {Symbols::moffs32, Symbols::eax}}, "mov", "Move EAX to (seg:offset)"}},
            /* A4 */ {{{{}, {}, {}}, "movsb", "Move byte at address DS:(E)SI to address ES:(E)DI"}},
            /* A5 */ {{{{}, {}, {}}, "movsd", "Move doubleword at address DS:(E)SI to address ES:(E)DI"}},
            /* A6 */ {{{{}, {}, {}}, "cmpsb", "Compares byte at address DS:(E)SI with byte at address ES:(E)DI and sets the status flags accordingly"}},
            /* A7 */ {{{{}, {}, {}}, "cmpsd", "Compares doubleword at address DS:(E)SI with doubleword at address ES:(E)DI and sets the status flags accordingly"}},
            /* A8 */ {{{{}, {OpEncoding::ib}, {Symbols::al, Symbols::imm8}}, "test", "AND imm8 with AL; set SF, ZF, PF according to result"}},
            /* A9 */ {{{{}, {OpEncoding::iw}, {Symbols::ax, Symbols::imm16}}, "test", "AND imm16 with AX; set SF, ZF, PF according to result"},
            /* A9 */  {{{}, {OpEncoding::id}, {Symbols::eax, Symbols::imm32}}, "test", "AND imm32 with EAX; set SF, ZF, PF according to result"}},
            /* AA */ {{{{}, {}, {}}, "stosb", "Store AL at address ES:(E)DI"}},
            /* AB */ {{{{}, {}, {}}, "stosd", "Store EAX at address ES:(E)DI"}},
            /* AC */ {{{{}, {}, {}}, "lodsb", "Load byte at address DS:(E)SI into AL"}},
            /* AD */ {{{{}, {}, {}}, "lodsd", "Load doubleword at address DS:(E)SI into EAX"}},
            /* AE */ {{{{}, {}, {}}, "scasb", "Compare AL with byte at ES:(E)DI and set status flags"}},
            /* AF */ {{{{}, {}, {}}, "scasd", "Compare EAX with doubleword at ES:(E)DI and set status flags"}},
            /* B0 */ {{{{}, {}, {Symbols::al, Symbols::imm8}}, "mov", "Move imm8 to r8"}},
            /* B1 */ {{{{}, {}, {Symbols::bl, Symbols::imm8}}, "mov", "Move imm8 to r8"}},
            /* B2 */ {{{{}, {}, {Symbols::cl, Symbols::imm8}}, "mov", "Move imm8 to r8"}},
            /* B3 */ {{{{}, {}, {Symbols::dl, Symbols::imm8}}, "mov", "Move imm8 to r8"}},
            /* B4 */ {{{{}, {}, {Symbols::ah, Symbols::imm8}}, "mov", "Move imm8 to r8"}},
            /* B5 */ {{{{}, {}, {Symbols::bh, Symbols::imm8}}, "mov", "Move imm8 to r8"}},
            /* B6 */ {{{{}, {}, {Symbols::ch, Symbols::imm8}}, "mov", "Move imm8 to r8"}},
            /* B7 */ {{{{}, {}, {Symbols::dh, Symbols::imm8}}, "mov", "Move imm8 to r8"}},
            /* B8 */ {{{{}, {}, {Symbols::eax, Symbols::imm32}}, "mov", "Move imm32 to r32"}},
            /* B9 */ {{{{}, {}, {Symbols::ecx, Symbols::imm32}}, "mov", "Move imm32 to r32"}},
            /* BA */ {{{{}, {}, {Symbols::edx, Symbols::imm32}}, "mov", "Move imm32 to r32"}},
            /* BB */ {{{{}, {}, {Symbols::ebx, Symbols::imm32}}, "mov", "Move imm32 to r32"}},
            /* BC */ {{{{}, {}, {Symbols::esp, Symbols::imm32}}, "mov", "Move imm32 to r32"}},
            /* BD */ {{{{}, {}, {Symbols::ebp, Symbols::imm32}}, "mov", "Move imm32 to r32"}},
            /* BE */ {{{{}, {}, {Symbols::esi, Symbols::imm32}}, "mov", "Move imm32 to r32"}},
            /* BF */ {{{{}, {}, {Symbols::edi, Symbols::imm32}}, "mov", "Move imm32 to r32"}},
            /* C0 */ {{{{}, {OpEncoding::m0, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "rol", "Rotate eight bits rm8 left imm8 times"},
            /* C0 */  {{{}, {OpEncoding::m1, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "ror", "Rotate eight bits rm16 right imm8 times"},
            /* C0 */  {{{}, {OpEncoding::m2, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "rcl", "Rotate nine bits (CF, rm8) left imm8 times"},
            /* C0 */  {{{}, {OpEncoding::m3, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "rcr", "Rotate nine bits (CF, rm8) right imm8 times"},
            /* C0 */  {{{}, {OpEncoding::m4, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "sal", "Multiply rm8 by 2, imm8 times"},
            /* C0 */  {{{}, {OpEncoding::m5, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "shr", "Unsigned divide rm8 by 2, imm8 times"},
            /* C0 */  {{{}, {OpEncoding::m7, OpEncoding::ib}, {Symbols::rm8, Symbols::imm8}}, "sar", "Signed divide* rm8 by 2, imm8 times"}},
            /* C1 */ {{{{}, {OpEncoding::m0, OpEncoding::ib}, {Symbols::rm16, Symbols::imm8}}, "rol", "Rotate 16 bits rm16 left imm8 times"},
            /* C1 */  {{{}, {OpEncoding::m1, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "ror", "Rotate 32 bits rm32 right imm8 times"},
            /* C1 */  {{{}, {OpEncoding::m2, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "rcl", "Rotate 17 bits (CF, rm16) left imm8 times"},
            /* C1 */  {{{}, {OpEncoding::m3, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "rcr", "Rotate 33 bits (CF, rm32) right imm8 times"},
            /* C1 */  {{{}, {OpEncoding::m4, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "sal", "Multiply rm32 by 2, imm8 times"},
            /* C1 */  {{{}, {OpEncoding::m5, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "shr", "Unsigned divide rm32 by 2, imm8 times"},
            /* C1 */  {{{}, {OpEncoding::m7, OpEncoding::ib}, {Symbols::rm32, Symbols::imm8}}, "sar", "Signed divide* rm32 by 2, imm8 times"}},
            /* C2 */ {{{{}, {OpEncoding::iw}, {Symbols::imm16}}, "ret", "Near return to calling procedure and pop imm16 bytes from stack"}},
            /* C3 */ {{{{}, {}, {}}, "retn", "Near return to calling procedure"}},
            /* C4 */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::m16_16}}, "les", "Load ES: r16 with far pointer from memory"},
            /* C4 */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::m16_32}}, "les", "Load ES: r32 with far pointer from memory"}},
            /* C5 */ {{{{}, {OpEncoding::r}, {Symbols::r16, Symbols::m16_16}}, "lds", "Load DS: r16 with far pointer from memory"},
            /* C5 */  {{{}, {OpEncoding::r}, {Symbols::r32, Symbols::m16_32}}, "lds", "Load DS: r32 with far pointer from memory"}},
            /* C6 */ {{{{}, {OpEncoding::m0}, {Symbols::rm8, Symbols::imm8}}, "mov", "Move imm8 to rm8"}},
            /* C7 */ {{{{}, {OpEncoding::m0}, {Symbols::rm16, Symbols::imm16}}, "mov", "Move imm16 to rm16"},
            /* C7 */  {{{}, {OpEncoding::m0}, {Symbols::rm32, Symbols::imm32}}, "mov", "Move imm32 to rm32"}},
            /* C8 */ {{{{}, {OpEncoding::iw, OpEncoding::ib}, {Symbols::imm16, Symbols::imm8}}, "enter", "Create a nested (if imm8 > 0) stack frame for a procedure"}},
            /* C9 */ {{{{}, {}, {}}, "leave", "Set ESP to EBP, then pop EBP"}},
            /* CA */ {{{{}, {OpEncoding::iw}, {Symbols::imm16}}, "ret", "Far return to calling procedure and pop imm16 bytes from stack"}},
            /* CB */ {{{{}, {}, {}}, "ret", "Far return to calling procedure"}},
            /* CC */ {{{{}, {}, {}}, "int 3", "Interrupt 3—trap to debugger"}},
            /* CD */ {{{{}, {OpEncoding::ib}, {Symbols::imm8}}, "int", "Interrupt vector number specified by immediate byte"}},
            /* CE */ {{{{}, {}, {}}, "into", "Interrupt 4—if overflow flag is 1"}},
            /* CF */ {{{{}, {}, {}}, "iretd", "Interrupt return (32-bit operand size)"}},
            /* D0 */ {{{{}, {OpEncoding::m0}, {Symbols::rm8, Symbols::one}}, "rol", "Rotate eight bits rm8 left once"},
            /* D0 */  {{{}, {OpEncoding::m1}, {Symbols::rm8, Symbols::one}}, "ror", "Rotate eight bits rm8 right once"},
            /* D0 */  {{{}, {OpEncoding::m2}, {Symbols::rm8, Symbols::one}}, "rcl", "Rotate nine bits (CF, rm8) left once"},
            /* D0 */  {{{}, {OpEncoding::m3}, {Symbols::rm8, Symbols::one}}, "rcr", "Rotate nine bits (CF, rm8) right once"},
            /* D0 */  {{{}, {OpEncoding::m4}, {Symbols::rm8, Symbols::one}}, "sal", "Multiply rm8 by 2, once"},
            /* D0 */  {{{}, {OpEncoding::m5}, {Symbols::rm8, Symbols::one}}, "shr", "Unsigned divide rm8 by 2, once"},
            /* D0 */  {{{}, {OpEncoding::m7}, {Symbols::rm8, Symbols::one}}, "sar", "Signed divide* rm8 by 2, once"}},
            /* D1 */ {{{{}, {OpEncoding::m0}, {Symbols::rm32, Symbols::one}}, "rol", "Rotate 32 bits rm32 left once"},
            /* D1 */  {{{}, {OpEncoding::m1}, {Symbols::rm32, Symbols::one}}, "ror", "Rotate 32 bits rm32 right once"},
            /* D1 */  {{{}, {OpEncoding::m2}, {Symbols::rm32, Symbols::one}}, "rcl", "Rotate 33 bits (CF, rm32) left once"},
            /* D1 */  {{{}, {OpEncoding::m3}, {Symbols::rm32, Symbols::one}}, "rcr", "Rotate 33 bits (CF, rm32) right once"},
            /* D1 */  {{{}, {OpEncoding::m4}, {Symbols::rm32, Symbols::one}}, "shl", "Multiply rm16 by 2, once"},
            /* D1 */  {{{}, {OpEncoding::m5}, {Symbols::rm32, Symbols::one}}, "shr", "Unsigned divide rm16 by 2, once"},
            /* D1 */  {{{}, {OpEncoding::m7}, {Symbols::rm32, Symbols::one}}, "sar", "Signed divide* rm16 by 2, once"}},
            /* D2 */ {{{{}, {OpEncoding::m0}, {Symbols::rm8, Symbols::cl}}, "rol", "Rotate eight bits rm8 left CL times"},
            /* D2 */  {{{}, {OpEncoding::m1}, {Symbols::rm8, Symbols::cl}}, "ror", "Rotate eight bits rm8 right CL times"},
            /* D2 */  {{{}, {OpEncoding::m2}, {Symbols::rm8, Symbols::cl}}, "rcl", "Rotate nine bits (CF, rm8) left CL times"},
            /* D2 */  {{{}, {OpEncoding::m3}, {Symbols::rm8, Symbols::cl}}, "rcr", "Rotate nine bits (CF, rm8) right CL times"},
            /* D2 */  {{{}, {OpEncoding::m4}, {Symbols::rm8, Symbols::cl}}, "shl", "Multiply rm8 by 2, CL times"},
            /* D2 */  {{{}, {OpEncoding::m5}, {Symbols::rm8, Symbols::cl}}, "shr", "Unsigned divide rm8 by 2, CL times"},
            /* D2 */  {{{}, {OpEncoding::m7}, {Symbols::rm8, Symbols::cl}}, "sar", "Signed divide* rm8 by 2, CL times"}},
            /* D3 */ {{{{}, {OpEncoding::m0}, {Symbols::rm16, Symbols::cl}}, "rol", "Rotate 16 bits rm16 left CL times"},
            /* D3 */  {{{}, {OpEncoding::m1}, {Symbols::rm16, Symbols::cl}}, "ror", "Rotate 16 bits rm16 right CL times"},
            /* D3 */  {{{}, {OpEncoding::m2}, {Symbols::rm32, Symbols::cl}}, "rcl", "Rotate 33 bits (CF, rm32) left CL times"},
            /* D3 */  {{{}, {OpEncoding::m3}, {Symbols::rm32, Symbols::cl}}, "rcr", "Rotate 33 bits (CF, rm32) right CL times"},
            /* D3 */  {{{}, {OpEncoding::m4}, {Symbols::rm16, Symbols::cl}}, "shl", "Multiply rm16 by 2, CL times"},
            /* D3 */  {{{}, {OpEncoding::m5}, {Symbols::rm16, Symbols::cl}}, "shr", "Unsigned divide rm16 by 2, CL times"},
            /* D3 */  {{{}, {OpEncoding::m7}, {Symbols::rm16, Symbols::cl}}, "sar", "Signed divide* rm16 by 2, CL times"}},
            /* D4 */ {{{{0x0A}, {}, {}}, "aam", "ASCII adjust AX after multiply"}},
            /* D5 */ {{{{0x0A}, {}, {}}, "aad", "ASCII adjust AX before division"}},
            /* D6 */ {{{{}, {}, {}}, "???", "Unrecognized opcode"}},
            /* D7 */ {{{{}, {}, {}}, "xlatb", "Set AL to memory byte DS:[(E)BX + unsigned AL]"}},
            /* D8 */ {{{{0xC0}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fadd", "Add ST(0) to ST(i) and store result in ST(0)"},
            /* D8 */  {{{0xC8}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fmul", "Multiply ST(0) by ST(i) and store result in ST(0)"},
            /* D8 */  {{{0xD0}, {OpEncoding::i}, {Symbols::sti}}, "fcom", "Compare ST(0) with ST(i)."},
            /* D8 */  {{{0xD8}, {OpEncoding::i}, {Symbols::sti}}, "fcomp", "Compare ST(0) with ST(i) and pop register stack."},
            /* D8 */  {{{0xE0}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fsub", "Subtract ST(i) from ST(0) and store result in ST(0)"},
            /* D8 */  {{{0xE8}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fsubr", "Subtract ST(0) from ST(i) and store result in ST(0)"},
            /* D8 */  {{{0xF0}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fdiv", "Divide ST(0) by ST(i) and store result in ST(0)"},
            /* D8 */  {{{0xF8}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fdivr", "Divide ST(i) by ST(0) and store result in ST(0)"},
            /* D8 */  {{{}, {OpEncoding::m0}, {Symbols::m32real}}, "fadd", "Add m32real to ST(0) and store result in ST(0)"},
            /* D8 */  {{{}, {OpEncoding::m1}, {Symbols::m32real}}, "fmul", "Multiply ST(0) by m32real and store result in ST(0)"},
            /* D8 */  {{{}, {OpEncoding::m2}, {Symbols::m32real}}, "fcom", "Compare ST(0) with m32real."},
            /* D8 */  {{{}, {OpEncoding::m3}, {Symbols::m32real}}, "fcomp", "Compare ST(0) with m32real and pop register stack."},
            /* D8 */  {{{}, {OpEncoding::m4}, {Symbols::m32real}}, "fsub", "Subtract m32real from ST(0) and store result in ST(0)"},
            /* D8 */  {{{}, {OpEncoding::m5}, {Symbols::m32real}}, "fsubr", "Subtract ST(0) from m32real and store result in ST(0)"},
            /* D8 */  {{{}, {OpEncoding::m6}, {Symbols::m32real}}, "fdiv", "Divide ST(0) by m32real and store result in ST(0)"},
            /* D8 */  {{{}, {OpEncoding::m7}, {Symbols::m32real}}, "fdivr", "Divide m32real by ST(0) and store result in ST(0)"}},
            /* D9 */ {{{{0xC0}, {OpEncoding::i}, {Symbols::sti}}, "fld", "Push ST(i) onto the FPU register stack."},
            /* D9 */  {{{0xC8}, {OpEncoding::i}, {Symbols::sti}}, "fxch", "Exchange the contents of ST(0) and ST(i)"},
            /* D9 */  {{{0xC9}, {}, {}}, "fxch", "Exchange the contents of ST(0) and ST(1)"},
            /* D9 */  {{{0xD0}, {}, {}}, "fnop", "No operation is performed"},
            /* D9 */  {{{0xE0}, {}, {}}, "fchs", "Complements sign of ST(0)"},
            /* D9 */  {{{0xE1}, {}, {}}, "fabs", "Replace ST with its absolute value"},
            /* D9 */  {{{0xE4}, {}, {}}, "ftst", "Compare ST(0) with 0.0"},
            /* D9 */  {{{0xE5}, {}, {}}, "fxam", "Classify value or number in ST(0)"},
            /* D9 */  {{{0xE8}, {}, {}}, "fld1", "Push +1.0 onto the FPU register stack"},
            /* D9 */  {{{0xE9}, {}, {}}, "fldl2t", "Push log 210 onto the FPU register stack"},
            /* D9 */  {{{0xEA}, {}, {}}, "fltl2e", "Push log 2e onto the FPU register stack"},
            /* D9 */  {{{0xEB}, {}, {}}, "fldpi", "Push PI onto the FPU register stack"},
            /* D9 */  {{{0xEC}, {}, {}}, "fldlg2", "Push log 102 onto the FPU register stack"},
            /* D9 */  {{{0xED}, {}, {}}, "fldln2", "Push log e2 onto the FPU register stack"},
            /* D9 */  {{{0xEE}, {}, {}}, "fldz", "Push +0.0 onto the FPU register stack"},
            /* D9 */  {{{0xF0}, {}, {}}, "f2xm1", "Replace ST(0) with (2 ST(0) – 1)"},
            /* D9 */  {{{0xF1}, {}, {}}, "fyl2x", "Replace ST(1) with (ST(1) * log 2ST(0)) and pop the register stack"},
            /* D9 */  {{{0xF2}, {}, {}}, "fptan", "Replace ST(0) with its tangent and push 1 onto the FPU stack"},
            /* D9 */  {{{0xF3}, {}, {}}, "fpatan", "Replace ST(1) with arctan(ST(1)/ST(0)) and pop the register stack"},
            /* D9 */  {{{0xF4}, {}, {}}, "fxtract", "Separate value in ST(0) into exponent and significand, store exponent in ST(0), and push the significand onto the register stack."},
            /* D9 */  {{{0xF5}, {}, {}}, "fprem1", "Replace ST(0) with the IEEE remainder obtained from dividing ST(0) by ST(1)"},
            /* D9 */  {{{0xF6}, {}, {}}, "fdecstp", "Decrement TOP field in FPU status word"},
            /* D9 */  {{{0xF7}, {}, {}}, "fincstp", "Increment the TOP field in the FPU status register"},
            /* D9 */  {{{0xF8}, {}, {}}, "fprem", "Replace ST(0) with the remainder obtained from dividing ST(0) by ST(1)"},
            /* D9 */  {{{0xF9}, {}, {}}, "fyl2xp1", "Replace ST(1) with ST(1) * log 2 (ST(0) + 1.0) and pop the register stack"},
            /* D9 */  {{{0xFA}, {}, {}}, "fsqrt", "Calculates square root of ST(0) and stores the result in ST(0)"},
            /* D9 */  {{{0xFB}, {}, {}}, "fsincos", "Compute the sine and cosine of ST(0); replace ST(0) with the sine, and push the cosine onto the register stack"},
            /* D9 */  {{{0xFC}, {}, {}}, "frndint", "Round ST(0) to an integer"},
            /* D9 */  {{{0xFD}, {}, {}}, "fscale", "Scale ST(0) by ST(1)"},
            /* D9 */  {{{0xFE}, {}, {}}, "fsin", "Replace ST(0) with its sine"},
            /* D9 */  {{{0xFF}, {}, {}}, "fcos", "Replace ST(0) with its cosine"},
            /* D9 */  {{{}, {OpEncoding::m0}, {Symbols::m32real}}, "fld", "Push m32real onto the FPU register stack"},
            /* D9 */  {{{}, {OpEncoding::m2}, {Symbols::m32real}}, "fst", "Copy ST(0) to m32real"},
            /* D9 */  {{{}, {OpEncoding::m3}, {Symbols::m32real}}, "fstp", "Copy ST(0) to m32real and pop register stack"},
            /* D9 */  {{{}, {OpEncoding::m4}, {Symbols::m14_28byte}}, "fldenv", "Load FPU environment from m14byte or m28byte"},
            /* D9 */  {{{}, {OpEncoding::m5}, {Symbols::m2byte}}, "fldcw", "Load FPU control word from m2byte"},
            /* D9 */  {{{}, {OpEncoding::m6}, {Symbols::m14_28byte}}, "fnstenv", "Store FPU environment to m14byte or m28byte without checking for pending unmasked floating-point exceptions. Then mask all floating-point exceptions."},
            /* D9 */  {{{}, {OpEncoding::m7}, {Symbols::m2byte}}, "fnstcw", "Store FPU control word to m2byte without checking for pending unmasked floating-point exceptions"}},
            /* DA */ {{{{0xC0}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fcmovb", "Move if below (CF=1)"},
            /* DA */  {{{0xC8}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fcmove", "Move if equal (ZF=1)"},
            /* DA */  {{{0xD0}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fcmovbe", "Move if below or equal (CF=1 or ZF=1)"},
            /* DA */  {{{0xD8}, {OpEncoding::i}, {Symbols::st0, Symbols::sti}}, "fcmovu", "Move if unordered (PF=1)"},
            /* DA */  {{{}, {OpEncoding::m0}, {Symbols::m32int}}, "fiadd", "Add m32int to ST(0) and store result in ST(0)"},
            /* DA */  {{{}, {OpEncoding::m1}, {Symbols::m32int}}, "fimul", "Multiply ST(0) by m32int and store result in ST(0)"},
            /* DA */  {{{}, {OpEncoding::m2}, {Symbols::m32int}}, "ficom", "Compare ST(0) with m32int."},
            /* DA */  {{{}, {OpEncoding::m3}, {Symbols::m32int}}, "ficomp", "Compare ST(0) with m32int and pop register stack."},
            /* DA */  {{{}, {OpEncoding::m4}, {Symbols::m32int}}, "fisub", "Subtract m32int from ST(0) and store result in ST(0)"},
            /* DA */  {{{}, {OpEncoding::m5}, {Symbols::m32int}}, "fisubr", "Subtract ST(0) from m32int and store result in ST(0)"},
            /* DA */  {{{}, {OpEncoding::m6}, {Symbols::m32int}}, "fidiv", "Divide ST(0) by m32int and store result in ST(0)"},
            /* DA */  {{{}, {OpEncoding::m7}, {Symbols::m32int}}, "fidivr", "Divide m32int by ST(0) and store result in ST(0)"}},



        };
    }
        
    
    static void initTable3(std::unordered_map<std::string, std::vector<BaseSet_x86_64::OpData>>& oplookup_x86_64)
    {
        using OpEncoding = BaseSet_x86_64::OpEncoding;
        using OpData = BaseSet_x86_64::OpData;
        using Symbols = BaseSet_x86_64::Symbols;

        oplookup_x86_64 = std::unordered_map<std::string, std::vector<BaseSet_x86_64::OpData>>();

        // To-do: this should be reorganized. I will probably 
        // sort it by just opcode number rather than alphabetically
        oplookup_x86_64["aaa"] = { { { 0x37 }, { } } };
        oplookup_x86_64["aad"] = { { { 0xD5, 0x0A }, { }, { } } };
        oplookup_x86_64["aam"] = { { { 0xD4, 0x0A }, { }, { } } };
        oplookup_x86_64["aas"] = { { { 0x3F }, { } } };
        oplookup_x86_64["add"] = {
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
        oplookup_x86_64["or"] = {
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
        oplookup_x86_64["adc"] = {
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
        oplookup_x86_64["sbb"] = {
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
        oplookup_x86_64["and"] = {
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
        oplookup_x86_64["sub"] = {
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
        oplookup_x86_64["xor"] = {
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
        oplookup_x86_64["cmp"] = {
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
        oplookup_x86_64["cmps"] = {
            { { 0xA6 }, { }, { Symbols::m8, Symbols::m8 } },
            { { 0xA7 }, { }, { Symbols::m16, Symbols::m16 } },
            { { 0xA7 }, { }, { Symbols::m32, Symbols::m32 } },
        };
        oplookup_x86_64["arpl"] = {
            { { 0x63 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
        };
        oplookup_x86_64["bound"] = {
            { { 0x62 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x62 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["call"] = {
            { { 0xE8 }, { OpEncoding::cw }, { Symbols::rel16 } },
            { { 0xE8 }, { OpEncoding::cd }, { Symbols::rel32 } },
            { { 0x9A }, { OpEncoding::cd }, { Symbols::ptr16_16 } },
            { { 0x9A }, { OpEncoding::cp }, { Symbols::ptr16_32 } },
            { { 0xFF }, { OpEncoding::m2 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m2 }, { Symbols::rm32 }, BaseSet_x86_64::OPS_DEFAULT_64_BITS },
            { { 0xFF }, { OpEncoding::m3 }, { Symbols::m16_16 } },
            { { 0xFF }, { OpEncoding::m3 }, { Symbols::m16_32 }, BaseSet_x86_64::OPS_DEFAULT_64_BITS },
        };
        oplookup_x86_64["cbw"] = { { { 0x98 }, { }, { } } };
        oplookup_x86_64["clc"] = { { { 0xF8 }, { } } };
        oplookup_x86_64["cld"] = { { { 0xFC }, { } } };
        oplookup_x86_64["cli"] = { { { 0xFA }, { } } };
        oplookup_x86_64["cmc"] = { { { 0xF5 }, { }, { } } };
        oplookup_x86_64["cmovo"] = {
            { { 0x0F, 0x40 }, { OpEncoding::m0, OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x40 }, { OpEncoding::m0, OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovno"] = {
            { { 0x0F, 0x41 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x41 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovb"] = {
            { { 0x0F, 0x42 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x42 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovnb"] = {
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovae"] = {
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x43 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmove"] = {
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovz"] = {
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x44 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovne"] = {
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovnz"] = {
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x45 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovbe"] = {
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovna"] = {
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x46 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmova"] = {
            { { 0x0F, 0x47 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x47 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovs"] = {
            { { 0x0F, 0x48 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x48 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovns"] = {
            { { 0x0F, 0x49 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x49 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovp"] = {
            { { 0x0F, 0x4A }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4A }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovnp"] = {
            { { 0x0F, 0x4B }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4B }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovl"] = {
            { { 0x0F, 0x4C }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4C }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovnl"] = {
            { { 0x0F, 0x4D }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4D }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovng"] = {
            { { 0x0F, 0x4E }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4E }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cmovg"] = {
            { { 0x0F, 0x4F }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x4F }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["cwd"] = { { { 0x99 }, { }, { } } };
        oplookup_x86_64["daa"] = { { { 0x27 }, { } } };
        oplookup_x86_64["das"] = { { { 0x2F }, { } } };
        oplookup_x86_64["dec"] = {
            { { 0x48 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0xFE }, { OpEncoding::m1 }, { Symbols::rm8 } },
            { { 0xFF }, { OpEncoding::m1 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m1 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["div"] = {
            { { 0xF6 }, { OpEncoding::m6 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m6 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m6 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["enter"] = {
            { { 0xC8 }, { OpEncoding::iw }, { Symbols::imm16, Symbols::imm8 } }
        };
        oplookup_x86_64["fcmovb"] = {
            { { 0xDA, 0xC0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fcmove"] = {
            { { 0xDA, 0xC8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fcmovbe"] = {
            { { 0xDA, 0xD0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fcmovu"] = {
            { { 0xDA, 0xD8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fild"] = {
            { { 0xDF }, { OpEncoding::m0 }, { Symbols::m16int } },
            { { 0xDB }, { OpEncoding::m0 }, { Symbols::m32int } },
            { { 0xDF }, { OpEncoding::m5 }, { Symbols::m64int } }
        };
        oplookup_x86_64["fist"] = {
            { { 0xDF }, { OpEncoding::m2 }, { Symbols::m16int } },
            { { 0xDB }, { OpEncoding::m2 }, { Symbols::m32int } }
        };
        oplookup_x86_64["fistp"] = {
            { { 0xDF }, { OpEncoding::m3 }, { Symbols::m16int } },
            { { 0xDB }, { OpEncoding::m3 }, { Symbols::m32int } },
            { { 0xDF }, { OpEncoding::m7 }, { Symbols::m64int } }
        };
        oplookup_x86_64["fbld"] = {
            { { 0xDF }, { OpEncoding::m4 }, { Symbols::m80dec } }
        };
        oplookup_x86_64["fbstp"] = {
            { { 0xDF }, { OpEncoding::m6 }, { Symbols::m80bcd } }
        };

        oplookup_x86_64["fcmovnb"] = {
            { { 0xDB, 0xC0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fcmovne"] = {
            { { 0xDB, 0xC8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fcmovnbe"] = {
            { { 0xDB, 0xD0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fcmovnu"] = {
            { { 0xDB, 0xD8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fnclex"] = { { { 0xDB, 0xE2 }, { }, { } } };
        oplookup_x86_64["fninit"] = { { { 0xDB, 0xE3 }, { }, { } } };
        oplookup_x86_64["fucompp"] = { { { 0xDA, 0xE9 }, { }, { } } };
        oplookup_x86_64["fucom"] = {
            { { 0xDD, 0xE0 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xDD, 0xE1 }, { }, { } }
        };
        oplookup_x86_64["fucomi"] = {
            { { 0xDB, 0xE8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fucomip"] = {
            { { 0xDF, 0xE8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fcomip"] = {
            { { 0xDF, 0xF0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fucomp"] = {
            { { 0xDD, 0xE8 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xDD, 0xE9 }, { }, { } }
        };
        oplookup_x86_64["fcomi"] = {
            { { 0xDB, 0xF0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } }
        };
        oplookup_x86_64["fstenv"] = {
            { { 0x9B, 0xD9 }, { OpEncoding::m6 }, { Symbols::m14_28byte } }
        };
        oplookup_x86_64["fstcw"] = {
            { { 0x9B, 0xD9 }, { OpEncoding::m7 }, { Symbols::m2byte } }
        };
        oplookup_x86_64["fclex"] = { { { 0x9B, 0xDB, 0xE2 }, { }, { } } };
        oplookup_x86_64["finit"] = { { { 0x9B, 0xDB, 0xE3 }, { }, { } } };
        oplookup_x86_64["fsave"] = {
            { { 0x9B, 0xDD }, { OpEncoding::m6 }, { Symbols::m94_108byte } }
        };
        oplookup_x86_64["fstsw"] = {
            { { 0x9B, 0xDD }, { OpEncoding::m7 }, { Symbols::m2byte } },
            { { 0x9B, 0xDF, 0xE0 }, { }, { Symbols::ax } }
        };
        oplookup_x86_64["fadd"] = {
            { { 0xD8 }, { OpEncoding::m0 }, { Symbols::m32real } },
            { { 0xD8, 0xC0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC }, { OpEncoding::m0 }, { Symbols::m64real } },
            { { 0xDC, 0xC0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86_64["faddp"] = {
            { { 0xDE, 0xC0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xC1 }, { }, { } }
        };
        oplookup_x86_64["fmulp"] = {
            { { 0xDE, 0xC8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xC9 }, { }, { } }
        };
        oplookup_x86_64["fcompp"] = {
            { { 0xDE, 0xD9 }, { }, { } }
        };
        oplookup_x86_64["fsubrp"] = {
            { { 0xDE, 0xE0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xE1 }, { }, { } }
        };
        oplookup_x86_64["fsubp"] = {
            { { 0xDE, 0xE8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xE9 }, { }, { } }
        };
        oplookup_x86_64["fdivrp"] = {
            { { 0xDE, 0xF0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xF1 }, { }, { } }
        };
        oplookup_x86_64["fdivp"] = {
            { { 0xDE, 0xF8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } },
            { { 0xDE, 0xF9 }, { }, { } }
        };
        oplookup_x86_64["fiadd"] = {
            { { 0xDE }, { OpEncoding::m0 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m0 }, { Symbols::m32int } },
        };
        oplookup_x86_64["fmul"] = {
            { { 0xD8 }, { OpEncoding::m1 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m1 }, { Symbols::m64real } },
            { { 0xD8, 0xC8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xC8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86_64["fimul"] = {
            { { 0xDE }, { OpEncoding::m1 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m1 }, { Symbols::m32int } }
        };
        oplookup_x86_64["fcom"] = {
            { { 0xD8 }, { OpEncoding::m2 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m2 }, { Symbols::m64real } },
            { { 0xD8, 0xD0 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xD8, 0xD1 }, { }, { } }
        };
        oplookup_x86_64["ficom"] = {
            { { 0xDE }, { OpEncoding::m2 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m2 }, { Symbols::m32int } }
        };
        oplookup_x86_64["fcomp"] = {
            { { 0xD8 }, { OpEncoding::m3 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m3 }, { Symbols::m64real } },
            { { 0xD8, 0xD8 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xD8, 0xD9 }, { }, { } }
        };
        oplookup_x86_64["ficomp"] = {
            { { 0xDE }, { OpEncoding::m3 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m3 }, { Symbols::m32int } }
        };
        oplookup_x86_64["fsub"] = {
            { { 0xD8 }, { OpEncoding::m4 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m4 }, { Symbols::m64real } },
            { { 0xD8, 0xE0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xE0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86_64["fisub"] = {
            { { 0xDE }, { OpEncoding::m4 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m4 }, { Symbols::m32int } }
        };
        oplookup_x86_64["fsubr"] = {
            { { 0xD8 }, { OpEncoding::m5 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m5 }, { Symbols::m64real } },
            { { 0xD8, 0xE8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xE8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86_64["fisubr"] = {
            { { 0xDE }, { OpEncoding::m5 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m5 }, { Symbols::m32int } }
        };
        oplookup_x86_64["fdiv"] = {
            { { 0xD8 }, { OpEncoding::m6 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m6 }, { Symbols::m64real } },
            { { 0xD8, 0xF0 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xF0 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86_64["fidiv"] = {
            { { 0xDE }, { OpEncoding::m6 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m6 }, { Symbols::m32int } }
        };
        oplookup_x86_64["fdivr"] = {
            { { 0xD8 }, { OpEncoding::m7 }, { Symbols::m32real } },
            { { 0xDC }, { OpEncoding::m7 }, { Symbols::m64real } },
            { { 0xD8, 0xF8 }, { OpEncoding::i }, { Symbols::st0, Symbols::sti } },
            { { 0xDC, 0xF8 }, { OpEncoding::i }, { Symbols::sti, Symbols::st0 } }
        };
        oplookup_x86_64["fidivr"] = {
            { { 0xDE }, { OpEncoding::m7 }, { Symbols::m16int } },
            { { 0xDA }, { OpEncoding::m7 }, { Symbols::m32int } }
        };
        oplookup_x86_64["fld"] = {
            { { 0xD9 }, { OpEncoding::m0 }, { Symbols::m32real } },
            { { 0xDD }, { OpEncoding::m0 }, { Symbols::m64real } },
            { { 0xD9, 0xC0 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xDB }, { OpEncoding::m5 }, { Symbols::m80real } }
        };
        oplookup_x86_64["fst"] = {
            { { 0xD9 }, { OpEncoding::m2 }, { Symbols::m32real } },
            { { 0xDD }, { OpEncoding::m2 }, { Symbols::m64real } },
            { { 0xDD, 0xD0 }, { OpEncoding::i }, { Symbols::sti } }
        };
        oplookup_x86_64["fstp"] = {
            { { 0xD9 }, { OpEncoding::m3 }, { Symbols::m32real } },
            { { 0xDB }, { OpEncoding::m7 }, { Symbols::m80real } },
            { { 0xDD }, { OpEncoding::m3 }, { Symbols::m64real } },
            { { 0xDD, 0xD8 }, { OpEncoding::i }, { Symbols::sti } }
        };
        oplookup_x86_64["frstor"] = {
            { { 0xDD }, { OpEncoding::m4 }, { Symbols::m94_108byte } }
        };
        oplookup_x86_64["fnsave"] = {
            { { 0xDD }, { OpEncoding::m6 }, { Symbols::m94_108byte } }
        };
        oplookup_x86_64["fnstsw"] = {
            { { 0xDD }, { OpEncoding::m7 }, { Symbols::m2byte } },
            { { 0xDF, 0xE0 }, { }, { Symbols::ax } }
        };
        oplookup_x86_64["ffree"] = {
            { { 0xDD, 0xC0 }, { OpEncoding::i }, { Symbols::sti } }
        };
        oplookup_x86_64["fldenv"] = {
            { { 0xD9 }, { OpEncoding::m4 }, { Symbols::m14_28byte } }
        };
        oplookup_x86_64["fldcw"] = {
            { { 0xD9 }, { OpEncoding::m5 }, { Symbols::m2byte } }
        };
        oplookup_x86_64["fnstenv"] = {
            { { 0xD9 }, { OpEncoding::m6 }, { Symbols::m14_28byte } }
        };
        oplookup_x86_64["fnstcw"] = {
            { { 0xD9 }, { OpEncoding::m7 }, { Symbols::m2byte } }
        };
        oplookup_x86_64["fxch"] = {
            { { 0xD9, 0xC8 }, { OpEncoding::i }, { Symbols::sti } },
            { { 0xD9, 0xC9 }, { }, { } }
        };
        oplookup_x86_64["fnop"] = { { { 0xD9, 0xD0 }, { }, { } } };
        oplookup_x86_64["fchs"] = { { { 0xD9, 0xE0 }, { }, { } } };
        oplookup_x86_64["fabs"] = { { { 0xD9, 0xE1 }, { }, { } } };
        oplookup_x86_64["ftst"] = { { { 0xD9, 0xE4 }, { }, { } } };
        oplookup_x86_64["fxam"] = { { { 0xD9, 0xE5 }, { }, { } } };
        oplookup_x86_64["fld1"] = { { { 0xD9, 0xE8 }, { }, { } } };
        oplookup_x86_64["fldl2t"] = { { { 0xD9, 0xE9 }, { }, { } } };
        oplookup_x86_64["fldl2e"] = { { { 0xD9, 0xEA }, { }, { } } };
        oplookup_x86_64["fldpi"] = { { { 0xD9, 0xEB }, { }, { } } };
        oplookup_x86_64["fldlg2"] = { { { 0xD9, 0xEC }, { }, { } } };
        oplookup_x86_64["fldln2"] = { { { 0xD9, 0xED }, { }, { } } };
        oplookup_x86_64["fldz"] = { { { 0xD9, 0xEE }, { }, { } } };
        oplookup_x86_64["f2xm1"] = { { { 0xD9, 0xF0 }, { }, { } } };
        oplookup_x86_64["fyl2x"] = { { { 0xD9, 0xF1 }, { }, { } } };
        oplookup_x86_64["fptan"] = { { { 0xD9, 0xF2 }, { }, { } } };
        oplookup_x86_64["fpatan"] = { { { 0xD9, 0xF3 }, { }, { } } };
        oplookup_x86_64["fxtract"] = { { { 0xD9, 0xF4 }, { }, { } } };
        oplookup_x86_64["fprem1"] = { { { 0xD9, 0xF5 }, { }, { } } };
        oplookup_x86_64["fdecstp"] = { { { 0xD9, 0xF6 }, { }, { } } };
        oplookup_x86_64["fincstp"] = { { { 0xD9, 0xF7 }, { }, { } } };
        oplookup_x86_64["fprem"] = { { { 0xD9, 0xF8 }, { }, { } } };
        oplookup_x86_64["fyl2xp1"] = { { { 0xD9, 0xF9 }, { }, { } } };
        oplookup_x86_64["fsqrt"] = { { { 0xD9, 0xFA }, { }, { } } };
        oplookup_x86_64["fsincos"] = { { { 0xD9, 0xFB }, { }, { } } };
        oplookup_x86_64["frndint"] = { { { 0xD9, 0xFC }, { }, { } } };
        oplookup_x86_64["fscale"] = { { { 0xD9, 0xFD }, { }, { } } };
        oplookup_x86_64["fsin"] = { { { 0xD9, 0xFE }, { }, { } } };
        oplookup_x86_64["fcos"] = { { { 0xD9, 0xFF }, { }, { } } };
        oplookup_x86_64["hlt"] = { { { 0xF4 }, { }, { } } };
        oplookup_x86_64["inc"] = {
            { { 0x40 }, { OpEncoding::rd }, { Symbols::r32 } },
            { { 0xFE }, { OpEncoding::m0 }, { Symbols::rm8 } },
            { { 0xFF }, { OpEncoding::m0 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m0 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["in"] = {
            { { 0xE4 }, { OpEncoding::ib }, { Symbols::al, Symbols::imm8 } },
            { { 0xE5 }, { OpEncoding::ib }, { Symbols::ax, Symbols::imm8 } },
            { { 0xE5 }, { OpEncoding::ib }, { Symbols::eax, Symbols::imm8 } },
            { { 0xEC }, { }, { Symbols::al, Symbols::dx } },
            { { 0xED }, { }, { Symbols::ax, Symbols::dx } },
            { { 0xED }, { }, { Symbols::eax, Symbols::dx } }
        };
        oplookup_x86_64["ins"] = {
            { { 0x6C }, { }, { Symbols::m8, Symbols::dx } },
            { { 0x6D }, { }, { Symbols::m16, Symbols::dx } },
            { { 0x6D }, { }, { Symbols::m32, Symbols::dx } }
        };
        oplookup_x86_64["int3"] = { { { 0xCC }, { }, { } } };
        oplookup_x86_64["int"] = {
            { { 0xCD }, { OpEncoding::ib }, { Symbols::imm8 } }
        };
        oplookup_x86_64["into"] = { { { 0xCE }, { }, { } } };
        oplookup_x86_64["iret"] = { { { 0xCF }, { }, { } } };
        oplookup_x86_64["iretd"] = { { { 0xCF }, { }, { } } };
        oplookup_x86_64["idiv"] = {
            { { 0xF6 }, { OpEncoding::m7 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m7 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m7 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["imul"] = {
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
        oplookup_x86_64["jmp"] = {
            { { 0xEB }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0xE9 }, { OpEncoding::cw }, { Symbols::rel16 } },
            { { 0xE9 }, { OpEncoding::cd }, { Symbols::rel32 } },
            { { 0xEA }, { OpEncoding::cd }, { Symbols::ptr16_16 } },
            { { 0xEA }, { OpEncoding::cp }, { Symbols::ptr16_32 } },
            { { 0xFF }, { OpEncoding::m4 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m4 }, { Symbols::rm32 }, BaseSet_x86_64::OPS_DEFAULT_64_BITS },
            { { 0xFF }, { OpEncoding::m5 }, { Symbols::m16_16 } },
            { { 0xFF }, { OpEncoding::m5 }, { Symbols::m16_32 }, BaseSet_x86_64::OPS_DEFAULT_64_BITS },
        };
        oplookup_x86_64["jo"] = {
            { { 0x70 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x80 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jno"] = {
            { { 0x71 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x81 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jb"] = {
            { { 0x72 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x82 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jae"] = {
            { { 0x73 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x83 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jnb"] = {
            { { 0x73 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x83 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["je"] = {
            { { 0x74 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x84 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jz"] = {
            { { 0x74 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x84 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jne"] = {
            { { 0x75 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x85 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jnz"] = {
            { { 0x75 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x85 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jbe"] = {
            { { 0x76 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x86 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jna"] = {
            { { 0x76 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x86 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["ja"] = {
            { { 0x77 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x87 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["js"] = {
            { { 0x78 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x88 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jns"] = {
            { { 0x79 }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x89 }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jp"] = {
            { { 0x7A }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8A }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jpo"] = {
            { { 0x7B }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8B }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jl"] = {
            { { 0x7C }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8C }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jnl"] = {
            { { 0x7D }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8D }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jle"] = {
            { { 0x7E }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8E }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jng"] = {
            { { 0x7E }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8E }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["jg"] = {
            { { 0x7F }, { OpEncoding::cb }, { Symbols::rel8 } },
            { { 0x0F, 0x8F }, { OpEncoding::cd }, { Symbols::rel32 } },
        };
        oplookup_x86_64["lahf"] = { { { 0x9F }, { } } };
        oplookup_x86_64["leave"] = { { { 0xC9 }, { } } };
        oplookup_x86_64["lea"] = {
            { { 0x8D }, { OpEncoding::r }, { Symbols::r16, Symbols::m } },
            { { 0x8D }, { OpEncoding::r }, { Symbols::r32, Symbols::m } },
        };
        oplookup_x86_64["les"] = {
            { { 0xC4 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0xC4 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } }
        };
        oplookup_x86_64["lds"] = {
            { { 0xC5 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0xC5 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } }
        };
        oplookup_x86_64["lodsb"] = { { { 0xAC }, { } } };
        oplookup_x86_64["lodsd"] = { { { 0xAD }, { } } };
        oplookup_x86_64["loopne"] = { { { 0xE0 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86_64["loopnz"] = { { { 0xE0 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86_64["loope"] = { { { 0xE1 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86_64["loopz"] = { { { 0xE1 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86_64["loop"] = { { { 0xE2 }, { OpEncoding::cb }, { Symbols::rel8 } }, };
        oplookup_x86_64["mov"] = {
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
        oplookup_x86_64["movs"] = {
            { { 0xA4 }, { }, { Symbols::m8, Symbols::m8 } },
            { { 0xA5 }, { }, { Symbols::m16, Symbols::m16 } },
            { { 0xA5 }, { }, { Symbols::m32, Symbols::m32 } },
        };
        oplookup_x86_64["mul"] = {
            { { 0xF6 }, { OpEncoding::m4 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m4 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m4 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["neg"] = {
            { { 0xF6 }, { OpEncoding::m3 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m3 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m3 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["nop"] = {
            { { 0x90 }, { }, { } }
        };
        oplookup_x86_64["not"] = {
            { { 0xF6 }, { OpEncoding::m2 }, { Symbols::rm8 } },
            { { 0xF7 }, { OpEncoding::m2 }, { Symbols::rm16 } },
            { { 0xF7 }, { OpEncoding::m2 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["out"] = {
            { { 0xE6 }, { OpEncoding::ib }, { Symbols::imm8, Symbols::al } },
            { { 0xE7 }, { OpEncoding::ib }, { Symbols::imm8, Symbols::ax } },
            { { 0xE7 }, { OpEncoding::ib }, { Symbols::imm8, Symbols::eax } },
            { { 0xEE }, { }, { Symbols::dx, Symbols::al } },
            { { 0xEF }, { }, { Symbols::dx, Symbols::ax } },
            { { 0xEF }, { }, { Symbols::dx, Symbols::eax } }
        };
        oplookup_x86_64["outs"] = {
            { { 0x6E }, { }, { Symbols::m8, Symbols::dx } },
            { { 0x6F }, { }, { Symbols::m16, Symbols::dx } },
            { { 0x6F }, { }, { Symbols::m32, Symbols::dx } }
        };
        oplookup_x86_64["pop"] = {
            { { 0x58 }, { OpEncoding::rd }, { Symbols::r32 }, BaseSet_x86_64::OPS_DEFAULT_64_BITS },
            { { 0x8F }, { OpEncoding::m0 }, { Symbols::m32 } },
            { { 0x07 }, { }, { Symbols::es } },
            { { 0x17 }, { }, { Symbols::ss } },
            { { 0x1F }, { }, { Symbols::ds } },
            { { 0x0F, 0xA1 }, { }, { Symbols::fs } },
            { { 0x0F, 0xA9 }, { }, { Symbols::gs } }
        };
        oplookup_x86_64["popf"] = { { { 0x9D }, { } } };
        oplookup_x86_64["popfd"] = { { { 0x9D }, { } } };
        oplookup_x86_64["popa"] = { { { 0x61 }, { } } };
        oplookup_x86_64["popad"] = { { { 0x61 }, { } } };
        oplookup_x86_64["pusha"] = { { { 0x60 }, { } } };
        oplookup_x86_64["pushad"] = { { { 0x60 }, { } } };
        oplookup_x86_64["push"] = {
            { { 0x68 }, { }, { Symbols::imm32 } },
            { { 0x6A }, { }, { Symbols::imm8 } },
            { { 0x50 }, { OpEncoding::rd }, { Symbols::r32 }, BaseSet_x86_64::OPS_DEFAULT_64_BITS },
            { { 0x06 }, { }, { Symbols::es } },
            { { 0x0E }, { }, { Symbols::cs } },
            { { 0x16 }, { }, { Symbols::ss } },
            { { 0x1E }, { }, { Symbols::ds } },
            { { 0x0F, 0xA0 }, { }, { Symbols::fs } },
            { { 0x0F, 0xA8 }, { }, { Symbols::gs } },
            { { 0xFF }, { OpEncoding::m6 }, { Symbols::rm16 } },
            { { 0xFF }, { OpEncoding::m6 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["pushf"] = { { { 0x9C }, { } } };
        oplookup_x86_64["pushfd"] = { { { 0x9C }, { } } };
        oplookup_x86_64["ret"] = {
            { { 0xC2 }, { OpEncoding::iw }, { Symbols::imm16 } },
            { { 0xCA }, { OpEncoding::iw }, { Symbols::imm16 } },
            { { 0xC3 }, { }, { } },
            { { 0xCB }, { }, { } }
        };
        oplookup_x86_64["retn"] = { { { 0xC3 }, { } } };
        oplookup_x86_64["rcl"] = {
            { { 0xC0 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86_64["rcr"] = {
            { { 0xC0 }, { OpEncoding::m3, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m3, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86_64["rol"] = {
            { { 0xC0 }, { OpEncoding::m0, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m0, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86_64["ror"] = {
            { { 0xC0 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m1, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86_64["sahf"] = { { { 0x9E }, { } } };
        oplookup_x86_64["sal"] = {
            { { 0xC0 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86_64["sar"] = {
            { { 0xC0 }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86_64["scasb"] = { { { 0xAE }, { } } };
        oplookup_x86_64["scasd"] = { { { 0xAF }, { } } };
        oplookup_x86_64["shr"] = {
            { { 0xC0 }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm8, Symbols::imm8 } },
            { { 0xC1 }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } }
        };
        oplookup_x86_64["stosb"] = { { { 0xAA }, { } } };
        oplookup_x86_64["stosd"] = { { { 0xAB }, { } } };
        oplookup_x86_64["stc"] = { { { 0xF9 }, { } } };
        oplookup_x86_64["std"] = { { { 0xFD }, { } } };
        oplookup_x86_64["sti"] = { { { 0xFB }, { } } };
        oplookup_x86_64["test"] = {
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
        oplookup_x86_64["wait"] = { { { 0x9B }, { }, { } } };
        oplookup_x86_64["fwait"] = { { { 0x9B }, { }, { } } };
        oplookup_x86_64["xchg"] = {
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
        oplookup_x86_64["xlatb"] = { { { 0xD7 }, { } } };

        // Extended SIMD instructions
        oplookup_x86_64["sldt"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m0 }, { Symbols::rm16 } },
            { { 0x0F, 0x00 }, { OpEncoding::m0 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["str"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m1 }, { Symbols::rm16 } },
        };
        oplookup_x86_64["lldt"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m2 }, { Symbols::rm16 } },
        };
        oplookup_x86_64["ltr"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m3 }, { Symbols::rm16 } },
        };
        oplookup_x86_64["verr"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m4 }, { Symbols::rm16 } },
        };
        oplookup_x86_64["verw"] = {
            { { 0x0F, 0x00 }, { OpEncoding::m5 }, { Symbols::rm16 } },
        };
        oplookup_x86_64["sgdt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m0 }, { Symbols::m } },
        };
        oplookup_x86_64["sidt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m1 }, { Symbols::m } },
        };
        oplookup_x86_64["lgdt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m2 }, { Symbols::m16_32 } },
        };
        oplookup_x86_64["lidt"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m3 }, { Symbols::m16_32 } },
        };
        oplookup_x86_64["smsw"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m4 }, { Symbols::rm16 } },
            { { 0x0F, 0x01 }, { OpEncoding::m5 }, { Symbols::rm32 } },
        };
        oplookup_x86_64["lmsw"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m6 }, { Symbols::rm16 } },
        };
        oplookup_x86_64["invlpg"] = {
            { { 0x0F, 0x01 }, { OpEncoding::m7 }, { Symbols::m } },
        };
        oplookup_x86_64["lar"] = {
            { { 0x0F, 0x02 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x02 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["lsl"] = {
            { { 0x0F, 0x03 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0x03 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["clts"] = { { { 0x0F, 0x06 }, { }, { } } };
        oplookup_x86_64["invd"] = { { { 0x0F, 0x08 }, { }, { } } };
        oplookup_x86_64["wbinvd"] = { { { 0x0F, 0x09 }, { }, { } } };
        oplookup_x86_64["ud2"] = { { { 0x0F, 0x0B }, { }, { } } };
        oplookup_x86_64["movups"] = {
            { { 0x0F, 0x10 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } },
            { { 0x0F, 0x11 }, { OpEncoding::r }, { Symbols::xmm_m128, Symbols::xmm } }
        };
        oplookup_x86_64["movhlps"] = {
            { { 0x0F, 0x12 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm } } // xmm, xmm2
        };
        oplookup_x86_64["movlps"] = {
            { { 0x0F, 0x12 }, { OpEncoding::r }, { Symbols::xmm, Symbols::m64 } },
            { { 0x0F, 0x13 }, { OpEncoding::r }, { Symbols::m64, Symbols::xmm } }
        };
        oplookup_x86_64["unpcklps"] = {
            { { 0x0F, 0x14 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["unpckhps"] = {
            { { 0x0F, 0x15 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["movhps"] = {
            { { 0x0F, 0x16 }, { OpEncoding::r }, { Symbols::xmm, Symbols::m64 } },
            { { 0x0F, 0x17 }, { OpEncoding::r }, { Symbols::m64, Symbols::xmm } }
        };
        oplookup_x86_64["movlhps"] = {
            { { 0x0F, 0x16 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm } } // xmm, xmm2
        };
        oplookup_x86_64["prefetcht0"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m0 }, { Symbols::m8 } }
        };
        oplookup_x86_64["prefetcht1"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m1 }, { Symbols::m8 } }
        };
        oplookup_x86_64["prefetcht2"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m2 }, { Symbols::m8 } }
        };
        oplookup_x86_64["prefetchnta"] = {
            { { 0x0F, 0x18 }, { OpEncoding::m3 }, { Symbols::m8 } }
        };
        oplookup_x86_64["movaps"] = {
            { { 0x0F, 0x28 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } },
            { { 0x0F, 0x29 }, { OpEncoding::r }, { Symbols::xmm_m128, Symbols::xmm } }
        };
        oplookup_x86_64["cvtpi2ps"] = {
            { { 0x0F, 0x2A }, { OpEncoding::r }, { Symbols::xmm, Symbols::mm_m64 } },
        };
        oplookup_x86_64["movntps"] = {
            { { 0x0F, 0x2B }, { OpEncoding::r }, { Symbols::m128, Symbols::xmm } },
        };
        oplookup_x86_64["cvttps2pi"] = {
            { { 0x0F, 0x2C }, { OpEncoding::r }, { Symbols::mm, Symbols::xmm_m64 } },
        };
        oplookup_x86_64["cvtps2pi"] = {
            { { 0x0F, 0x2D }, { OpEncoding::r }, { Symbols::mm, Symbols::xmm_m64 } },
        };
        oplookup_x86_64["ucomiss"] = {
            { { 0x0F, 0x2E }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } },
        };
        oplookup_x86_64["comiss"] = {
            { { 0x0F, 0x2F }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } },
        };
        oplookup_x86_64["wrmsr"] = { { { 0x0F, 0x30 }, { }, { } } };
        oplookup_x86_64["rdtsc"] = { { { 0x0F, 0x31 }, { }, { } } };
        oplookup_x86_64["rdmsr"] = { { { 0x0F, 0x32 }, { }, { } } };
        oplookup_x86_64["rdpmc"] = { { { 0x0F, 0x33 }, { }, { } } };
        oplookup_x86_64["sysenter"] = { { { 0x0F, 0x34 }, { }, { } } };
        oplookup_x86_64["sysexit"] = { { { 0x0F, 0x35 }, { }, { } } };
        oplookup_x86_64["movmskps"] = {
            { { 0x0F, 0x50 }, { OpEncoding::r }, { Symbols::r32, Symbols::xmm } }
        };
        oplookup_x86_64["sqrtps"] = {
            { { 0x0F, 0x51 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["rsqrtps"] = {
            { { 0x0F, 0x52 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["rcpps"] = {
            { { 0x0F, 0x53 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["andps"] = {
            { { 0x0F, 0x54 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["andnps"] = {
            { { 0x0F, 0x55 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["orps"] = {
            { { 0x0F, 0x56 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["xorps"] = {
            { { 0x0F, 0x57 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["addps"] = {
            { { 0x0F, 0x58 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["mulps"] = {
            { { 0x0F, 0x59 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["subps"] = {
            { { 0x0F, 0x5C }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["minps"] = {
            { { 0x0F, 0x5D }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["divps"] = {
            { { 0x0F, 0x5E }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["maxps"] = {
            { { 0x0F, 0x5F }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m128 } }
        };
        oplookup_x86_64["punpcklbw"] = {
            { { 0x0F, 0x60 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m32 } }
        };
        oplookup_x86_64["punpcklbd"] = {
            { { 0x0F, 0x61 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m32 } }
        };
        oplookup_x86_64["punpcklbq"] = {
            { { 0x0F, 0x62 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m32 } }
        };
        oplookup_x86_64["packsswb"] = {
            { { 0x0F, 0x63 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pcmpgtb"] = {
            { { 0x0F, 0x64 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pcmpgtw"] = {
            { { 0x0F, 0x65 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pcmpgtd"] = {
            { { 0x0F, 0x66 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["packuswb"] = {
            { { 0x0F, 0x67 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["punpckhbw"] = {
            { { 0x0F, 0x68 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["punpckhbd"] = {
            { { 0x0F, 0x69 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["punpckhbq"] = {
            { { 0x0F, 0x6A }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["packssdw"] = {
            { { 0x0F, 0x6B }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["movd"] = {
            { { 0x0F, 0x6E }, { OpEncoding::r }, { Symbols::mm, Symbols::rm32 } },
            { { 0x0F, 0x7E }, { OpEncoding::r }, { Symbols::rm32, Symbols::mm } }
        };
        oplookup_x86_64["movq"] = {
            { { 0x0F, 0x6F }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } },
            { { 0x0F, 0x7F }, { OpEncoding::r }, { Symbols::mm_m64, Symbols::mm } }
        };
        oplookup_x86_64["pshufw"] = {
            { { 0x0F, 0x70 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::mm, Symbols::mm_m64, Symbols::imm8 } }
        };
        oplookup_x86_64["psrlw"] = {
            { { 0x0F, 0x71 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } },
            { { 0x0F, 0xD1 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psraw"] = {
            { { 0x0F, 0x71 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } },
            { { 0x0F, 0xE1 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psllw"] = {
            { { 0x0F, 0x71 }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } },
            { { 0x0F, 0xF1 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psrld"] = {
            { { 0x0F, 0x72 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } },
            { { 0x0F, 0xD2 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psrad"] = {
            { { 0x0F, 0x72 }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } },
            { { 0x0F, 0xE2 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pslld"] = {
            { { 0x0F, 0x72 }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } },
            { { 0x0F, 0xF2 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psrlq"] = {
            { { 0x0F, 0x73 }, { OpEncoding::m2, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } },
            { { 0x0F, 0xD3 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psllq"] = {
            { { 0x0F, 0x73 }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::mm, Symbols::imm8 } },
            { { 0x0F, 0xF3 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pcmpeqb"] = {
            { { 0x0F, 0x74 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pcmpeqw"] = {
            { { 0x0F, 0x75 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pcmpeqd"] = {
            { { 0x0F, 0x76 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["emms"] = { { { 0x0F, 0x77 }, { }, { } } };
        oplookup_x86_64["seto"] = { { { 0x0F, 0x90 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setno"] = { { { 0x0F, 0x91 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setb"] = { { { 0x0F, 0x92 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setae"] = { { { 0x0F, 0x93 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setnb"] = { { { 0x0F, 0x93 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["sete"] = { { { 0x0F, 0x94 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setz"] = { { { 0x0F, 0x94 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setne"] = { { { 0x0F, 0x95 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setnz"] = { { { 0x0F, 0x95 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setbe"] = { { { 0x0F, 0x96 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setna"] = { { { 0x0F, 0x96 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["seta"] = { { { 0x0F, 0x97 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["sets"] = { { { 0x0F, 0x98 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setns"] = { { { 0x0F, 0x99 }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setp"] = { { { 0x0F, 0x9A }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setpo"] = { { { 0x0F, 0x9B }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setl"] = { { { 0x0F, 0x9C }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setnl"] = { { { 0x0F, 0x9D }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setle"] = { { { 0x0F, 0x9E }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setng"] = { { { 0x0F, 0x9E }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["setg"] = { { { 0x0F, 0x9F }, { }, { Symbols::rm8 } } };
        oplookup_x86_64["cpuid"] = { { { 0x0F, 0xA2 }, { }, { } } };
        oplookup_x86_64["bt"] = {
            { { 0x0F, 0xA3 }, { }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xA3 }, { }, { Symbols::rm32, Symbols::r32 } },
            { { 0x0F, 0xBA }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm16, Symbols::imm8 } },
            { { 0x0F, 0xBA }, { OpEncoding::m4, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup_x86_64["btc"] = {
            { { 0x0F, 0xBA }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm16, Symbols::imm8 } },
            { { 0x0F, 0xBA }, { OpEncoding::m7, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
            { { 0x0F, 0xBB }, { }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xBB }, { }, { Symbols::rm32, Symbols::r32 } },
        };
        oplookup_x86_64["bsf"] = { 
            { { 0x0F, 0xBC }, { }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0xBC }, { }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["bsr"] = { 
            { { 0x0F, 0xBD }, { }, { Symbols::r16, Symbols::rm16 } },
            { { 0x0F, 0xBD }, { }, { Symbols::r32, Symbols::rm32 } },
        };
        oplookup_x86_64["shld"] = {
            { { 0x0F, 0xA4 }, { }, { Symbols::rm16, Symbols::r16, Symbols::imm8 } },
            { { 0x0F, 0xA4 }, { }, { Symbols::rm32, Symbols::r32, Symbols::imm8 } },
            { { 0x0F, 0xA5 }, { }, { Symbols::rm16, Symbols::r16, Symbols::cl } },
            { { 0x0F, 0xA5 }, { }, { Symbols::rm32, Symbols::r32, Symbols::cl } },
        };
        oplookup_x86_64["rsm"] = { { { 0x0F, 0xAA }, { }, { } } };
        oplookup_x86_64["bts"] = {
            { { 0x0F, 0xAB }, { }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xAB }, { }, { Symbols::rm32, Symbols::r32 } },
            { { 0x0F, 0xBA }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm16, Symbols::imm8 } },
            { { 0x0F, 0xBA }, { OpEncoding::m5, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup_x86_64["shrd"] = {
            { { 0x0F, 0xAC }, { }, { Symbols::rm16, Symbols::r16, Symbols::imm8 } },
            { { 0x0F, 0xAC }, { }, { Symbols::rm32, Symbols::r32, Symbols::imm8 } },
            { { 0x0F, 0xAD }, { }, { Symbols::rm16, Symbols::r16, Symbols::cl } },
            { { 0x0F, 0xAD }, { }, { Symbols::rm32, Symbols::r32, Symbols::cl } },
        };
        oplookup_x86_64["fxsave"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m0 }, { Symbols::m512byte } }
        };
        oplookup_x86_64["fxrstor"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m1 }, { Symbols::m512byte } }
        };
        oplookup_x86_64["ldmxcsr"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m2 }, { Symbols::m32 } }
        };
        oplookup_x86_64["stmxcsr"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m3 }, { Symbols::m32 } }
        };
        oplookup_x86_64["sfence"] = {
            { { 0x0F, 0xAE }, { OpEncoding::m7 }, { } }
        };
        oplookup_x86_64["cmpxchg"] = {
            { { 0x0F, 0xB0 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x0F, 0xB1 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xB1 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } }
        };
        oplookup_x86_64["lss"] = {
            { { 0x0F, 0xB2 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0x0F, 0xB2 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } },
        };
        oplookup_x86_64["btr"] = {
            { { 0x0F, 0xB3 }, { }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xB3 }, { }, { Symbols::rm32, Symbols::r32 } },
            { { 0x0F, 0xBA }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::rm16, Symbols::imm8 } },
            { { 0x0F, 0xBA }, { OpEncoding::m6, OpEncoding::ib }, { Symbols::rm32, Symbols::imm8 } },
        };
        oplookup_x86_64["lfs"] = {
            { { 0x0F, 0xB4 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0x0F, 0xB4 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } },
        };
        oplookup_x86_64["lgs"] = {
            { { 0x0F, 0xB5 }, { OpEncoding::r }, { Symbols::r16, Symbols::m16_16 } },
            { { 0x0F, 0xB5 }, { OpEncoding::r }, { Symbols::r32, Symbols::m16_32 } },
        };
        oplookup_x86_64["movzx"] = {
            { { 0x0F, 0xB6 }, { OpEncoding::r }, { Symbols::r16, Symbols::rm8 } },
            { { 0x0F, 0xB6 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm8 } },
            { { 0x0F, 0xB7 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm16 } }
        };
        oplookup_x86_64["movsx"] = {
            { { 0x0F, 0xBE }, { OpEncoding::r }, { Symbols::r16, Symbols::rm8 } },
            { { 0x0F, 0xBE }, { OpEncoding::r }, { Symbols::r32, Symbols::rm8 } },
            { { 0x0F, 0xBF }, { OpEncoding::r }, { Symbols::r32, Symbols::rm16 } }
        };
        oplookup_x86_64["movsxd"] = {
            { { 0x63 }, { OpEncoding::r }, { Symbols::r32, Symbols::rm32 } }
        };
        oplookup_x86_64["xadd"] = {
            { { 0x0F, 0xC0 }, { OpEncoding::r }, { Symbols::rm8, Symbols::r8 } },
            { { 0x0F, 0xC1 }, { OpEncoding::r }, { Symbols::rm16, Symbols::r16 } },
            { { 0x0F, 0xC1 }, { OpEncoding::r }, { Symbols::rm32, Symbols::r32 } }
        };
        oplookup_x86_64["cmpps"] = {
            { { 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::xmm, Symbols::xmm_m128, Symbols::imm8 } }
        };
        oplookup_x86_64["pinsrw"] = {
            { { 0x0F, 0xC4 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::mm, Symbols::rm16, Symbols::imm8 } }
        };
        oplookup_x86_64["pextrw"] = {
            { { 0x0F, 0xC5 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::r32, Symbols::mm, Symbols::imm8 } }
        };
        oplookup_x86_64["shufps"] = {
            { { 0x0F, 0xC6 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::xmm, Symbols::xmm_m128, Symbols::imm8 } }
        };
        oplookup_x86_64["cmpxchg8b"] = {
            { { 0x0F, 0xC7 }, { OpEncoding::m1 }, { Symbols::m64 } }
        };
        oplookup_x86_64["bswap"] = {
            { { 0x0F, 0xC8 }, { OpEncoding::rd }, { Symbols::r32 } }
        };
        oplookup_x86_64["pmullw"] = {
            { { 0x0F, 0xD5 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pmovmskb"] = {
            { { 0x0F, 0xD7 }, { OpEncoding::r }, { Symbols::r32, Symbols::mm } }
        };
        oplookup_x86_64["psubusb"] = {
            { { 0x0F, 0xD8 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psubusw"] = {
            { { 0x0F, 0xD9 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pminub"] = {
            { { 0x0F, 0xDA }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pand"] = {
            { { 0x0F, 0xDB }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["paddusb"] = {
            { { 0x0F, 0xDC }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["paddusw"] = {
            { { 0x0F, 0xDD }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pmaxub"] = {
            { { 0x0F, 0xDE }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pandn"] = {
            { { 0x0F, 0xDF }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["movntq"] = {
            { { 0x0F, 0xE7 }, { OpEncoding::r }, { Symbols::m64, Symbols::mm } }
        };
        oplookup_x86_64["psadbw"] = {
            { { 0x0F, 0xF6 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["maskmovq"] = {
            { { 0x0F, 0xF7 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pavgb"] = {
            { { 0x0F, 0xE0 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pavgw"] = {
            { { 0x0F, 0xE3 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pmulhuw"] = {
            { { 0x0F, 0xE4 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pmulhw"] = {
            { { 0x0F, 0xE5 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psubsb"] = {
            { { 0x0F, 0xE8 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psubsw"] = {
            { { 0x0F, 0xE9 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pminsw"] = {
            { { 0x0F, 0xEA }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["por"] = {
            { { 0x0F, 0xEB }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["paddsb"] = {
            { { 0x0F, 0xEC }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["paddsw"] = {
            { { 0x0F, 0xED }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pmaxsw"] = {
            { { 0x0F, 0xEE }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pxor"] = {
            { { 0x0F, 0xEF }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["pmaddwd"] = {
            { { 0x0F, 0xF5 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psubb"] = {
            { { 0x0F, 0xF8 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psubw"] = {
            { { 0x0F, 0xF9 }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["psubd"] = {
            { { 0x0F, 0xFA }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["paddb"] = {
            { { 0x0F, 0xFC }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["paddw"] = {
            { { 0x0F, 0xFD }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };
        oplookup_x86_64["paddd"] = {
            { { 0x0F, 0xFE }, { OpEncoding::r }, { Symbols::mm, Symbols::mm_m64 } }
        };

        // Extended simd instructions (F3 PREFIX)
        oplookup_x86_64["movss"] = {
            { { 0xF3, 0x0F, 0x10 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } },
            { { 0xF3, 0x0F, 0x11 }, { OpEncoding::r }, { Symbols::xmm_m32, Symbols::xmm } },
        };
        oplookup_x86_64["cvtsi2ss"] = {
            { { 0xF3, 0x0F, 0x2A }, { OpEncoding::r }, { Symbols::xmm, Symbols::rm32 } }
        };
        oplookup_x86_64["cvttss2si"] = {
            { { 0xF3, 0x0F, 0x2C }, { OpEncoding::r }, { Symbols::r32, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["cvtss2si"] = {
            { { 0xF3, 0x0F, 0x2D }, { OpEncoding::r }, { Symbols::r32, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["sqrtss"] = {
            { { 0xF3, 0x0F, 0x51 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["rsqrtss"] = {
            { { 0xF3, 0x0F, 0x52 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["rcpss"] = {
            { { 0xF3, 0x0F, 0x53 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["addss"] = {
            { { 0xF3, 0x0F, 0x58 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["mulss"] = {
            { { 0xF3, 0x0F, 0x59 }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["subss"] = {
            { { 0xF3, 0x0F, 0x5C }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["minss"] = {
            { { 0xF3, 0x0F, 0x5D }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["divss"] = {
            { { 0xF3, 0x0F, 0x5E }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["maxss"] = {
            { { 0xF3, 0x0F, 0x5F }, { OpEncoding::r }, { Symbols::xmm, Symbols::xmm_m32 } }
        };
        oplookup_x86_64["cmpss"] = {
            { { 0xF3, 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::ib }, { Symbols::xmm, Symbols::xmm_m32, Symbols::imm8 } }
        };
        oplookup_x86_64["cmpeqss"] = {
            { { 0xF3, 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::m0 }, { Symbols::xmm, Symbols::xmm } }
        };
        oplookup_x86_64["cmpltss"] = {
            { { 0xF3, 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::m1 }, { Symbols::xmm, Symbols::xmm } }
        };
        oplookup_x86_64["cmpless"] = {
            { { 0xF3, 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::m2 }, { Symbols::xmm, Symbols::xmm } }
        };
        oplookup_x86_64["cmpunordss"] = {
            { { 0xF3, 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::m3 }, { Symbols::xmm, Symbols::xmm } }
        };
        oplookup_x86_64["cmpneqss"] = {
            { { 0xF3, 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::m4 }, { Symbols::xmm, Symbols::xmm } }
        };
        oplookup_x86_64["cmpnltss"] = {
            { { 0xF3, 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::m5 }, { Symbols::xmm, Symbols::xmm } }
        };
        oplookup_x86_64["cmpnless"] = {
            { { 0xF3, 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::m6 }, { Symbols::xmm, Symbols::xmm } }
        };
        oplookup_x86_64["cmpordss"] = {
            { { 0xF3, 0x0F, 0xC2 }, { OpEncoding::r, OpEncoding::m7 }, { Symbols::xmm, Symbols::xmm } }
        };
    }

    static BaseSet_x86_64::Opcode read_x86_64(ByteStream& stream, uintptr_t& offset, size_t& pos, DisassemblyOptions& options, const std::unordered_map<std::string, uint8_t> prelookup_x86_64, const std::vector<std::vector<BaseSet_x86_64::OpRef>> oplookup_x86_64, bool is64mode)
    {
        using Opcode = BaseSet_x86_64::Opcode;
        using OpEncoding = BaseSet_x86_64::OpEncoding;
        using OpData = BaseSet_x86_64::OpData;
        using OpRef = BaseSet_x86_64::OpRef;
        using Symbols = BaseSet_x86_64::Symbols;

        constexpr const uint8_t PRE_CS      = 0x2E;
        constexpr const uint8_t PRE_SS      = 0x36;
        constexpr const uint8_t PRE_DS      = 0x3E;
        constexpr const uint8_t PRE_ES      = 0x26;
        constexpr const uint8_t PRE_FS      = 0x64;
        constexpr const uint8_t PRE_GS      = 0x65;
        constexpr const uint8_t PRE_OPSOR1  = 0x66;
        constexpr const uint8_t PRE_OPSOR2  = 0x67;
        constexpr const uint8_t PRE_LOCK    = 0xF0;
        constexpr const uint8_t PRE_REPNE   = 0xF2;
        constexpr const uint8_t PRE_REPE    = 0xF3;

        Opcode opcode = { 0 };
        uint8_t cur = stream.next();
        
        OpData opData;
        OpRef opRef = OpRef();

        bool hasRex = false;
        uint8_t rexEnc = 0;

        auto findEntry = [](const std::vector<BaseSet_x86_64::OpEncoding>& entries, const BaseSet_x86_64::OpEncoding& enc)
        {
            if (entries.empty()) return false;

            for (const auto entry : entries)
                if (entry == enc)
                    return true;

            return false;
        };

        // Prefix check...
        // x86/64 instructions allow up to 4 prefixes
        //
        for (int i = 0; i < 4; i++)
        {
            for (const auto ref : oplookup_x86_64[cur])
            {
                if (ref.extData.settings & BaseSet_x86_64::OPS_IS_PREFIX)
                {
                    switch (cur)
                    {
                    case PRE_CS:
                        opcode.prefix |= BaseSet_x86_64::PRE_SEG_CS;
                        break;
                    case PRE_SS:
                        opcode.prefix |= BaseSet_x86_64::PRE_SEG_SS;
                        break;
                    case PRE_DS:
                        opcode.prefix |= BaseSet_x86_64::PRE_SEG_DS;
                        break;
                    case PRE_ES:
                        opcode.prefix |= BaseSet_x86_64::PRE_SEG_ES;
                        break;
                    case PRE_FS:
                        opcode.prefix |= BaseSet_x86_64::PRE_SEG_FS;
                        break;
                    case PRE_GS:
                        opcode.prefix |= BaseSet_x86_64::PRE_SEG_GS;
                        break;
                    case PRE_LOCK:
                        opcode.prefix |= BaseSet_x86_64::PRE_LOCK;
                        opcode.text += "lock ";
                        break;
                    case PRE_REPNE:
                        opcode.prefix |= BaseSet_x86_64::PRE_REPNE;
                        opcode.text += "repne ";
                        break;
                    case PRE_REPE:
                        opcode.prefix |= BaseSet_x86_64::PRE_REPE;
                        opcode.text += "repe ";
                        break;
                    case PRE_OPSOR1:
                        opcode.prefix |= BaseSet_x86_64::PRE_OPSOR1;
                        break;
                    case PRE_OPSOR2:
                        opcode.prefix |= BaseSet_x86_64::PRE_OPSOR2;
                        break;
                    }

                    cur = stream.next();
                    break;
                }
            }

            if (is64mode)
            {
                if (cur >= 0x40 && cur <= 0x4F)
                {
                    rexEnc = cur;
                    hasRex = true;
                    opcode.prefix |= BaseSet_x86_64::PRE_REX;
                    cur = stream.next();
                }
            }
        }

        // Now we've sorted through the prefixes.
        // Next we find out which instruction reference matches the opcode,
        // since there may be varying modes and sizes per instruction
        // 
        const auto oldPos = stream.getpos();

        for (const auto ref : oplookup_x86_64[cur])
        {
            stream.setpos(oldPos);

            if (ref.extData.settings & BaseSet_x86_64::OPS_16MODE)
                if (!((opcode.prefix & BaseSet_x86_64::PRE_OPSOR1) || (opcode.prefix & BaseSet_x86_64::PRE_OPSOR2)))
                    continue;

            bool matched = true;
            bool vreg = false;

            // ignore the final opcode byte if it has the rb/rw/rd mode...
            // it is variable and determines the register
            for (size_t i = 0; i < ref.extData.entries.size(); i++)
            {
                switch (ref.extData.entries[i])
                {
                case OpEncoding::rb:
                case OpEncoding::rw:
                case OpEncoding::rd:
                    vreg = true;
                    break;
                }
            }

            for (size_t i = 0; i < ref.extData.code.size(); i++)
            {
                const auto b = stream.next();

                if (vreg && i == ref.extData.code.size() - 1)
                {
                    // rb/rw/rd modes
                    if (!(b >= ref.extData.code[i] && b < ref.extData.code[i] + 8))
                    {
                        matched = false;
                        break;
                    }
                }
                else if (b != ref.extData.code[i])
                {
                    matched = false;
                    break;
                }
            }

            if (!matched)
                continue;

            matched = true;

            for (size_t i = 0; i < ref.extData.entries.size() && matched; i++)
            {
                const auto m = ((stream.current() % 0x40) / 8);

                switch (ref.extData.entries[i])
                {
                case OpEncoding::m0:
                    matched = (m == 0);
                    break;
                case OpEncoding::m1:
                    matched = (m == 1);
                    break;
                case OpEncoding::m2:
                    matched = (m == 2);
                    break;
                case OpEncoding::m3:
                    matched = (m == 3);
                    break;
                case OpEncoding::m4:
                    matched = (m == 4);
                    break;
                case OpEncoding::m5:
                    matched = (m == 5);
                    break;
                case OpEncoding::m6:
                    matched = (m == 6);
                    break;
                case OpEncoding::m7:
                    matched = (m == 7);
                    break;
                }
            }

            if (!matched)
                continue;

            // ... perform other checks on opcode entries...
            
            opRef = ref;

            // ... 
            break;
        }

        if (opRef.opCodeName.empty())
            return opcode;

        const auto nOperands = opRef.extData.symbols.size();

        opcode.text += opRef.opCodeName;
        opcode.text += " ";
        opcode.operands.resize(nOperands);

        uint8_t setmodrm = 0, modrm = 0;

        for (size_t i = 0; i < nOperands; i++)
        {
            if (i) opcode.text += ", ";

            if (opRef.extData.settings & BaseSet_x86_64::OPS_DEFAULT_64_BITS)
            {
                switch (opRef.extData.symbols[i])
                {
                case Symbols::eax:
                    opRef.extData.symbols[i] = Symbols::rax;
                    break;
                case Symbols::ecx:
                    opRef.extData.symbols[i] = Symbols::rcx;
                    break;
                case Symbols::edx:
                    opRef.extData.symbols[i] = Symbols::rdx;
                    break;
                case Symbols::ebx:
                    opRef.extData.symbols[i] = Symbols::rbx;
                    break;
                case Symbols::esp:
                    opRef.extData.symbols[i] = Symbols::rsp;
                    break;
                case Symbols::ebp:
                    opRef.extData.symbols[i] = Symbols::rbp;
                    break;
                case Symbols::esi:
                    opRef.extData.symbols[i] = Symbols::rsi;
                    break;
                case Symbols::edi:
                    opRef.extData.symbols[i] = Symbols::rdi;
                    break;
                }
            }

            auto& cop = opcode.operands[i];
            const auto symbol = opRef.extData.symbols[i];
            switch (symbol)
            {
            case Symbols::one:
                opcode.text += "1";
                break;
            case Symbols::imm8:
            case Symbols::moffs8:
            {
                cop.imm8 = stream.current();
                stream.skip(sizeof(uint8_t));
                cop.immSize = 8;
                char s[18];
                sprintf(s, "%02Xh", cop.imm8);
                opcode.text += s;
                break;
            }
            case Symbols::imm16:
            case Symbols::moffs16:
            {
                memcpy(&cop.imm16, stream.pcurrent(), sizeof(uint16_t));
                stream.skip(sizeof(uint16_t));
                cop.immSize = 16;
                char s[18];
                sprintf(s, "%04Xh", cop.imm16);
                opcode.text += s;
                break;
            }
            case Symbols::imm32:
            case Symbols::moffs32:
            {
                if (rexEnc & (1 << 3) && !findEntry(opRef.extData.entries, OpEncoding::id))
                {
                    memcpy(&cop.imm64, stream.pcurrent(), sizeof(uint64_t));
                    stream.skip(sizeof(uint64_t));
                    cop.immSize = 64;
                    char s[18];
                    sprintf(s, "%016llXh", cop.imm64);
                    opcode.text += s;
                }
                else
                {
                    memcpy(&cop.imm32, stream.pcurrent(), sizeof(uint32_t));
                    stream.skip(sizeof(uint32_t));
                    cop.immSize = 32;
                    char s[18];
                    sprintf(s, "%08Xh", cop.imm32);
                    opcode.text += s;
                }
                break;
            }
            case Symbols::imm64:
            case Symbols::moffs64:
            {
                memcpy(&cop.imm64, stream.pcurrent(), sizeof(uint64_t));
                stream.skip(sizeof(uint64_t));
                cop.immSize = 64;
                char s[18];
                sprintf(s, "%016llXh", cop.imm64);
                opcode.text += s;
                break;
            }
            case Symbols::ptr16_16:
            case Symbols::ptr16_32:
            {
                memcpy(&cop.imm32, stream.pcurrent(), sizeof(uint32_t));
                stream.skip(sizeof(uint32_t));
                memcpy(&cop.disp16, stream.pcurrent(), sizeof(uint16_t));
                stream.skip(sizeof(uint16_t));

                char s[32];
                sprintf(s, "%04X:%08Xh", cop.disp16, cop.imm32);
                opcode.text += s;
                break;
            }
            case Symbols::sreg:
                if (findEntry(opRef.extData.entries, OpEncoding::r))
                    cop.regs.push_back(((setmodrm ? modrm : stream.current()) % 0x40) / 8);
                else
                    cop.regs.push_back((setmodrm ? modrm : stream.current()) % 8);
                opcode.text += Mnemonics::SREG[cop.regs.back()];
                break;
            case Symbols::al:
                cop.regs.push_back(0);
                cop.bitSize = 8;
                opcode.text += Mnemonics::R8[cop.regs.back()];
                break;
            case Symbols::ax:
                cop.regs.push_back(0);
                cop.bitSize = 16;
                opcode.text += Mnemonics::R16[cop.regs.back()];
                break;
            case Symbols::eax:
                cop.regs.push_back(0);
                cop.bitSize = 32;
                opcode.text += (rexEnc & (1 << 3) && rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] :
                    (rexEnc & (1 << 2)) ? Mnemonics::R32ext[cop.regs.back()] : ((rexEnc & (1 << 3)) ? Mnemonics::R64[cop.regs.back()] : Mnemonics::R32[cop.regs.back()]);
                break;
            case Symbols::rax:
                cop.regs.push_back(0);
                cop.bitSize = 64;
                opcode.text += (rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                break;
            case Symbols::cl:
                cop.regs.push_back(1);
                cop.bitSize = 8;
                opcode.text += Mnemonics::R8[cop.regs.back()];
                break;
            case Symbols::cx:
                cop.regs.push_back(1);
                cop.bitSize = 16;
                opcode.text += Mnemonics::R16[cop.regs.back()];
                break;
            case Symbols::ecx:
                cop.regs.push_back(1);
                cop.bitSize = 32;
                opcode.text += (rexEnc & (1 << 3) && rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] : 
                    (rexEnc & (1 << 2)) ? Mnemonics::R32ext[cop.regs.back()] : ((rexEnc & (1 << 3)) ? Mnemonics::R64[cop.regs.back()] : Mnemonics::R32[cop.regs.back()]);
                break;
            case Symbols::rcx:
                cop.regs.push_back(1);
                cop.bitSize = 64;
                opcode.text += (rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                break;
            case Symbols::dl:
                cop.regs.push_back(2);
                cop.bitSize = 8;
                opcode.text += Mnemonics::R8[cop.regs.back()];
                break;
            case Symbols::dx:
                cop.regs.push_back(2);
                cop.bitSize = 16;
                opcode.text += Mnemonics::R16[cop.regs.back()];
                break;
            case Symbols::edx:
                cop.regs.push_back(2);
                cop.bitSize = 32;
                opcode.text += (rexEnc & (1 << 3) && rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] :
                    (rexEnc & (1 << 2)) ? Mnemonics::R32ext[cop.regs.back()] : ((rexEnc & (1 << 3)) ? Mnemonics::R64[cop.regs.back()] : Mnemonics::R32[cop.regs.back()]);
                break;
            case Symbols::rdx:
                cop.regs.push_back(2);
                cop.bitSize = 64;
                opcode.text += (rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                break;
            case Symbols::bl:
                cop.regs.push_back(3);
                cop.bitSize = 8;
                opcode.text += Mnemonics::R8[cop.regs.back()];
                break;
            case Symbols::bx:
                cop.regs.push_back(3);
                cop.bitSize = 16;
                opcode.text += Mnemonics::R16[cop.regs.back()];
                break;
            case Symbols::ebx:
                cop.regs.push_back(3);
                cop.bitSize = 32;
                opcode.text += (rexEnc & (1 << 3) && rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] :
                    (rexEnc & (1 << 2)) ? Mnemonics::R32ext[cop.regs.back()] : ((rexEnc & (1 << 3)) ? Mnemonics::R64[cop.regs.back()] : Mnemonics::R32[cop.regs.back()]);
                break;
            case Symbols::rbx:
                cop.regs.push_back(3);
                cop.bitSize = 64;
                opcode.text += (rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                break;
            case Symbols::ah:
                cop.regs.push_back(4);
                cop.bitSize = 8;
                opcode.text += Mnemonics::R8[cop.regs.back()];
                break;
            case Symbols::sp:
                cop.regs.push_back(4);
                cop.bitSize = 16;
                opcode.text += Mnemonics::R16[cop.regs.back()];
                break;
            case Symbols::esp:
                cop.regs.push_back(4);
                cop.bitSize = 32;
                opcode.text += (rexEnc & (1 << 3) && rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] :
                    (rexEnc & (1 << 2)) ? Mnemonics::R32ext[cop.regs.back()] : ((rexEnc & (1 << 3)) ? Mnemonics::R64[cop.regs.back()] : Mnemonics::R32[cop.regs.back()]);
                break;
            case Symbols::rsp:
                cop.regs.push_back(4);
                cop.bitSize = 64;
                opcode.text += (rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                break;
            case Symbols::ch:
                cop.regs.push_back(5);
                cop.bitSize = 8;
                opcode.text += Mnemonics::R8[cop.regs.back()];
                break;
            case Symbols::bp:
                cop.regs.push_back(5);
                cop.bitSize = 16;
                opcode.text += Mnemonics::R16[cop.regs.back()];
                break;
            case Symbols::ebp:
                cop.regs.push_back(5);
                cop.bitSize = 32;
                opcode.text += (rexEnc & (1 << 3) && rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] :
                    (rexEnc & (1 << 2)) ? Mnemonics::R32ext[cop.regs.back()] : ((rexEnc & (1 << 3)) ? Mnemonics::R64[cop.regs.back()] : Mnemonics::R32[cop.regs.back()]);
                break;
            case Symbols::rbp:
                cop.regs.push_back(5);
                cop.bitSize = 64;
                opcode.text += (rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                break;
            case Symbols::dh:
                cop.regs.push_back(6);
                cop.bitSize = 8;
                opcode.text += Mnemonics::R8[cop.regs.back()];
                break;
            case Symbols::si:
                cop.regs.push_back(6);
                cop.bitSize = 16;
                opcode.text += Mnemonics::R16[cop.regs.back()];
                break;
            case Symbols::esi:
                cop.regs.push_back(6);
                cop.bitSize = 32;
                opcode.text += (rexEnc & (1 << 3) && rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] :
                    (rexEnc & (1 << 2)) ? Mnemonics::R32ext[cop.regs.back()] : ((rexEnc & (1 << 3)) ? Mnemonics::R64[cop.regs.back()] : Mnemonics::R32[cop.regs.back()]);
                break;
            case Symbols::rsi:
                cop.regs.push_back(6);
                cop.bitSize = 64;
                opcode.text += (rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                break;
            case Symbols::bh:
                cop.regs.push_back(7);
                cop.bitSize = 8;
                opcode.text += Mnemonics::R8[cop.regs.back()];
                break;
            case Symbols::di:
                cop.regs.push_back(7);
                cop.bitSize = 16;
                opcode.text += Mnemonics::R16[cop.regs.back()];
                break;
            case Symbols::edi:
                cop.regs.push_back(7);
                cop.bitSize = 32;
                opcode.text += (rexEnc & (1 << 3) && rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] :
                    (rexEnc & (1 << 2)) ? Mnemonics::R32ext[cop.regs.back()] : ((rexEnc & (1 << 3)) ? Mnemonics::R64[cop.regs.back()] : Mnemonics::R32[cop.regs.back()]);
                break;
            case Symbols::rdi:
                cop.regs.push_back(7);
                cop.bitSize = 64;
                opcode.text += (rexEnc & 1) ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                break;
            case Symbols::r8:
                cop.bitSize = 8;
                if (findEntry(opRef.extData.entries, OpEncoding::r))
                    cop.regs.push_back(((setmodrm ? modrm : stream.current()) % 0x40) / 8);
                else
                    cop.regs.push_back((setmodrm ? modrm : stream.current()) % 8);
                opcode.text += Mnemonics::R8[cop.regs.back()];
                break;
            case Symbols::r16:
                cop.bitSize = 16;
                if (findEntry(opRef.extData.entries, OpEncoding::r))
                    cop.regs.push_back(((setmodrm ? modrm : stream.current()) % 0x40) / 8);
                else
                    cop.regs.push_back((setmodrm ? modrm : stream.current()) % 8);
                opcode.text += Mnemonics::R16[cop.regs.back()];
                break;
            case Symbols::r32:
            {
                if (findEntry(opRef.extData.entries, OpEncoding::r))
                    cop.regs.push_back(((setmodrm ? modrm : stream.current()) % 0x40) / 8);
                else
                    cop.regs.push_back((setmodrm ? modrm : stream.current()) % 8);

                if (!hasRex)
                {
                    cop.bitSize = 32;
                    opcode.text += Mnemonics::R32[cop.regs.back()];
                }
                else
                {
                    bool isLargeOp = (rexEnc & (1 << 3));
                    bool isRegExt = (rexEnc & (1 << 2));

                    if (isLargeOp)
                    {
                        cop.bitSize = 64;
                        opcode.text += isRegExt ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                    }
                    else
                    {
                        cop.bitSize = 32;
                        opcode.text += isRegExt ? Mnemonics::R32ext[cop.regs.back()] : Mnemonics::R32[cop.regs.back()];
                    }
                }
                break;
            }
            case Symbols::mm:
            {
                if (findEntry(opRef.extData.entries, OpEncoding::r))
                    cop.regs.push_back(((setmodrm ? modrm : stream.current()) % 0x40) / 8);
                else
                    cop.regs.push_back((setmodrm ? modrm : stream.current()) % 8);

                if (!hasRex)
                {
                    cop.bitSize = 128;
                    opcode.text += Mnemonics::MM[cop.regs.back()];
                }
                else
                {
                    bool isLargeOp = (rexEnc & (1 << 3));
                    bool isRegExt = (rexEnc & (1 << 2));

                    if (isLargeOp)
                    {
                        cop.bitSize = 128;
                        opcode.text += isRegExt ? Mnemonics::MMext[cop.regs.back()] : Mnemonics::MM[cop.regs.back()];
                    }
                    else
                    {
                        cop.bitSize = 128;
                        opcode.text += isRegExt ? Mnemonics::MMext[cop.regs.back()] : Mnemonics::MM[cop.regs.back()];
                    }
                }
                break;
            }
            case Symbols::xmm:
            {
                if (findEntry(opRef.extData.entries, OpEncoding::r))
                    cop.regs.push_back(((setmodrm ? modrm : stream.current()) % 0x40) / 8);
                else
                    cop.regs.push_back((setmodrm ? modrm : stream.current()) % 8);

                if (!hasRex)
                {
                    cop.bitSize = 128;
                    opcode.text += Mnemonics::XMM[cop.regs.back()];
                }
                else
                {
                    bool isLargeOp = (rexEnc & (1 << 3));
                    bool isRegExt = (rexEnc & (1 << 2));

                    if (isLargeOp)
                    {
                        cop.bitSize = 128;
                        opcode.text += isRegExt ? Mnemonics::XMMext[cop.regs.back()] : Mnemonics::XMM[cop.regs.back()];
                    }
                    else
                    {
                        cop.bitSize = 128;
                        opcode.text += isRegExt ? Mnemonics::XMMext[cop.regs.back()] : Mnemonics::XMM[cop.regs.back()];
                    }
                }
                break;
            }
            case Symbols::m:
            case Symbols::m8:
            case Symbols::m16:
            case Symbols::m32:
            case Symbols::m32real:
            case Symbols::m32int:
            case Symbols::rm8:
            case Symbols::rm16:
            case Symbols::rm32:
            case Symbols::rm64:
            case Symbols::m16_16:
            case Symbols::m16_32:
            case Symbols::mm_m32:
            case Symbols::mm_m64:
            case Symbols::xmm_m32:
            case Symbols::xmm_m64:
            case Symbols::xmm_m128:
            {
                uint8_t sb = 0;
                uint8_t mb = stream.current();
                auto mode = mb >> 6;
                auto r1 = (mode) ? ((mb % (mode << 6)) / 8) : 0;
                auto r2 = ((mode) ? (mb % (mode << 6)) : mb) % 8;
                bool hasSib = false;

                if (findEntry(opRef.extData.entries, OpEncoding::r))
                {
                    setmodrm = true;
                    modrm = mb;
                }

                switch (mode)
                {
                case 0:
                {
                    opcode.text += "[";

                    if (r2 == 4)
                    {
                        stream.next();
                        sb = stream.current();
                        mode = sb >> 5;
                        r1 = (mode) ? ((sb % (mode << 5)) / 8) : 0;
                        r2 = ((mode) ? (sb % (mode << 5)) : sb) % 8;
                        hasSib = true;
                    }

                    if (r2 == 5)
                    {
                        cop.regs.push_back(r1);

                        if (!hasRex)
                            opcode.text += Mnemonics::R32[cop.regs.back()];
                        else
                        {
                            bool isRegExt = (rexEnc & 1);

                            cop.bitSize = 64;
                            opcode.text += isRegExt ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                        }

                        int mul = ((sb >> 6) << 2) / 4;
                        if (mul)
                        {
                            char s[4];
                            mul--;
                            std::vector<int>muls = { 2, 4, 8 };
                            sprintf(s, "*%i", muls[mul]);
                            opcode.text += s;
                        }

                        stream.skip(1);
                        memcpy(&cop.imm32, stream.pcurrent(), sizeof(uint32_t));
                        stream.skip(sizeof(uint32_t));
                        cop.immSize = 32;
                        char s[20];
                        if (cop.imm32 > INT32_MAX)
                            sprintf(s, "-%08Xh", (UINT32_MAX - cop.imm32) + 1);
                        else
                            sprintf(s, "+%08Xh", cop.imm32);
                        opcode.text += s;
                    }
                    else
                    {
                        cop.regs.push_back(r2);

                        if (!hasRex)
                            opcode.text += Mnemonics::R32[cop.regs.back()];
                        else
                        {
                            bool isRegExt = (rexEnc & 1);

                            cop.bitSize = 64;
                            opcode.text += isRegExt ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                        }

                        if (hasSib && (sb % 0x40) != 0x24)
                        {
                            opcode.text += "+";
                            cop.regs.push_back(r1);

                            if (!hasRex)
                                opcode.text += Mnemonics::R32[cop.regs.back()];
                            else
                            {
                                bool isRegExt = (rexEnc & 2);

                                cop.bitSize = 64;
                                opcode.text += isRegExt ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                            }

                            int mul = ((sb >> 6) << 2) / 4;
                            if (mul)
                            {
                                char s[4];
                                mul--;
                                std::vector<int>muls = { 2, 4, 8 };
                                sprintf(s, "*%i", muls[mul]);
                                opcode.text += s;
                            }
                        }
                    }

                    stream.skip(1);

                    opcode.text += "]";
                    break;
                }
                case 1:
                {
                    opcode.text += "[";

                    if (r2 == 4)
                    {
                        stream.next();
                        sb = stream.current();
                        mode = sb >> 5;
                        r1 = (mode) ? ((sb % (mode << 5)) / 8) : 0;
                        r2 = ((mode) ? (sb % (mode << 5)) : sb) % 8;
                        hasSib = true;
                    }

                    cop.regs.push_back(r2);

                    if (!hasRex)
                        opcode.text += Mnemonics::R32[cop.regs.back()];
                    else
                    {
                        bool isRegExt = (rexEnc & 1);

                        cop.bitSize = 64;
                        opcode.text += isRegExt ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                    }

                    if (hasSib && (sb % 0x40) != 0x24)
                    {
                        opcode.text += "+";
                        cop.regs.push_back(r1);

                        if (!hasRex)
                            opcode.text += Mnemonics::R32[cop.regs.back()];
                        else
                        {
                            bool isRegExt = (rexEnc & 2);

                            cop.bitSize = 64;
                            opcode.text += isRegExt ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                        }

                        int mul = ((sb >> 6) << 2) / 4;
                        if (mul)
                        {
                            char s[4];
                            mul--;
                            std::vector<int>muls = { 2, 4, 8 };
                            sprintf(s, "*%i", muls[mul]);
                            opcode.text += s;
                        }
                    }
                    
                    stream.skip(1);
                    cop.imm8 = stream.next();
                    cop.immSize = 8;
                    char s[20];
                    if (cop.imm8 > INT8_MAX)
                        sprintf(s, "-%02Xh]", (UINT8_MAX - cop.imm8) + 1);
                    else
                        sprintf(s, "+%02Xh]", cop.imm8);

                    opcode.text += s;
                    break;
                }
                case 2:
                {
                    opcode.text += "[";

                    if (r2 == 4)
                    {
                        stream.next();
                        sb = stream.current();
                        mode = sb >> 5;
                        r1 = (mode) ? ((sb % (mode << 5)) / 8) : 0;
                        r2 = ((mode) ? (sb % (mode << 5)) : sb) % 8;
                        hasSib = true;
                    }

                    cop.regs.push_back(r2);

                    if (!hasRex)
                        opcode.text += Mnemonics::R32[cop.regs.back()];
                    else
                    {
                        bool isRegExt = (rexEnc & 1);

                        cop.bitSize = 64;
                        opcode.text += isRegExt ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                    }

                    if (hasSib && (sb % 0x40) != 0x24)
                    {
                        opcode.text += "+";
                        cop.regs.push_back(r1);

                        if (!hasRex)
                            opcode.text += Mnemonics::R32[cop.regs.back()];
                        else
                        {
                            bool isRegExt = (rexEnc & 2);

                            cop.bitSize = 64;
                            opcode.text += isRegExt ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                        }

                        int mul = ((sb >> 6) << 2) / 4;
                        if (mul)
                        {
                            char s[4];
                            mul--;
                            std::vector<int>muls = { 2, 4, 8 };
                            sprintf(s, "*%i", muls[mul]);
                            opcode.text += s;
                        }
                    }
                    
                    stream.skip(1);
                    memcpy(&cop.imm32, stream.pcurrent(), sizeof(uint32_t));
                    stream.skip(sizeof(uint32_t));
                    cop.immSize = 32;
                    char s[20];
                    if (cop.imm32 > INT32_MAX)
                        sprintf(s, "-%08Xh]", (UINT32_MAX - cop.imm32) + 1);
                    else
                        sprintf(s, "+%08Xh]", cop.imm32);

                    opcode.text += s;
                    break;
                }
                case 3:
                {
                    cop.regs.push_back(r2);

                    if (!hasRex)
                        opcode.text += Mnemonics::R32[cop.regs.back()];
                    else
                    {
                        bool isLargeOp = (rexEnc & (1 << 3));
                        bool isRegExt = (rexEnc & 1);

                        if (isLargeOp)
                        {
                            cop.bitSize = 64;
                            opcode.text += isRegExt ? Mnemonics::R64ext[cop.regs.back()] : Mnemonics::R64[cop.regs.back()];
                        }
                        else
                        {
                            cop.bitSize = 32;
                            opcode.text += Mnemonics::R32[cop.regs.back()];
                        }
                    }

                    if (findEntry(opRef.extData.entries, OpEncoding::r))
                        stream.skip(1);

                    break;
                }
                }

                // if there is no 'r' encoding to worry about,
                // we can skip the mod/rm byte
                if (!findEntry(opRef.extData.entries, OpEncoding::r))
                    stream.skip(1);

                break;
            }
            default:
                //throw SeraphException("Unknown symbol");
                break;
            }
        }

        return opcode;
    }

    Disassembler<TargetArchitecture::x64>::Disassembler() : stream(), options(DisassemblyOptions::Default) 
    {
        initTable1(prelookup_x86_64);
        initTable2(oplookup_x86_64); 
    };

    Disassembler<TargetArchitecture::x64>::Disassembler(const DisassemblyOptions& _options) : stream(), options(_options) 
    {
        initTable1(prelookup_x86_64);
        initTable2(oplookup_x86_64);
    };

    Disassembler<TargetArchitecture::x64>::Disassembler(const ByteStream& _stream) : stream(_stream), options(DisassemblyOptions::Default) 
    {
        initTable1(prelookup_x86_64);
        initTable2(oplookup_x86_64);
    };

    Disassembler<TargetArchitecture::x64>::Disassembler(const ByteStream& _stream, const DisassemblyOptions& _options) : stream(_stream), options(_options)
    {
        initTable1(prelookup_x86_64);
        initTable2(oplookup_x86_64);
    };

    //Disassembler(const DisassemblyOptions& _options) : stream(), options(_options) {};
    //Disassembler(const ByteStream& _stream) : stream(_stream), options(DisassemblyOptions::Default) {};
    //Disassembler(const ByteStream& _stream, const DisassemblyOptions& _options) : stream(_stream), options(_options) {};


    BaseSet_x86_64::Opcode Disassembler<TargetArchitecture::x86>::readNext()
    {
        return read_x86_64(stream, offset, pos, options, prelookup_x86_64, oplookup_x86_64, false);
    }

    BaseSet_x86_64::Opcode Disassembler<TargetArchitecture::x64>::readNext()
    {
        return read_x86_64(stream, offset, pos, options, prelookup_x86_64, oplookup_x86_64, true);
    }

    BaseSet_ARM::Opcode Disassembler<TargetArchitecture::ARM>::readNext()
    {
        return BaseSet_ARM::Opcode();
    }

    Assembler<TargetArchitecture::x86>::Assembler()
    {
        initTable1(prelookup_x86_64);
        initTable3(oplookup_x86_64);
    }

    Assembler<TargetArchitecture::x64>::Assembler()
    {
        initTable1(prelookup_x86_64);
        initTable3(oplookup_x86_64);
    }

    // Parses and converts assembly code string directly to
    // a stream of bytes
    ByteStream compile_x86_64(const std::string& source, std::unordered_map<std::string, uint8_t>& prelookup_x86_64, std::unordered_map<std::string, std::vector<BaseSet_x86_64::OpData>>& oplookup_x86_64, const uintptr_t offset, bool mode64)
    {
        ByteStream stream;

        using Symbols = BaseSet_x86_64::Symbols;
        using Operand = BaseSet_x86_64::Operand;
        using OpEncoding = BaseSet_x86_64::OpEncoding;
        using OpData = BaseSet_x86_64::OpData;

        const uint8_t B_OPERAND_SIZE_OVERRIDE = 0x66;
        const uint8_t B_ADDRESS_SIZE_OVERRIDE = 0x67;
        const uint8_t B_REX_OVERRIDE = 0x40;

        Parser::Scope scope = Parser::compile<TargetArchitecture::x86>(source, prelookup_x86_64);
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

        auto getLabel = [&getLabels](const std::string& label)
        {
            Parser::Node* res = nullptr;

            for (auto& node : getLabels())
                if (node->label == label)
                    return node;

            return res;
        };

        auto findEntry = [](const std::vector<BaseSet_x86_64::OpEncoding>& entries, const BaseSet_x86_64::OpEncoding& enc)
        {
            if (entries.empty()) return false;

            for (const auto entry : entries)
                if (entry == enc)
                    return true;

            return false;
        };

        // Go through the parsed nodes
        for (Parser::Node& node : mainBody.nodes)
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
                        // the corresponding address in memory.
                        // If the label's memory address hasn't been determined, we mark this node
                        for (auto labelNode : getLabels())
                        {
                            std::string::size_type n = 0;

                            while ((n = node.operands[opIndex].find(labelNode->label, n)) != std::string::npos)
                            {
                                char str[32];

                                //if (labelNode->streamIndex == INT_MAX)
                                //{
                                    // MARK THIS OPERAND -- recalculate the relative offset at the very end
                                    node.marked = true;
                                    node.markedOperand = opIndex;
                                    node.markedLabel = labelNode->label;
                                //}

                                if (!mode64)
                                    sprintf_s(str, "%08Xh", 0);
                                //    sprintf_s(str, "%08Xh", static_cast<uint32_t>(offset + labelNode->streamIndex));
                                else
                                    sprintf_s(str, "%016llXh", static_cast<uint64_t>(0));
                                //    sprintf_s(str, "%016llXh", static_cast<uint64_t>(offset + labelNode->streamIndex));

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
                            case ']':
                                rm = false;
                                break;
                            case '[':
                                operand.hasMod = true;
                                node.hasMod++;
                                node.modIndex = static_cast<int32_t>(opIndex);
                                operand.flags |= BaseSet_x86_64::OP_RM;
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
                                        operand.bitSize = 8;
                                        parts.push_back("r8");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::R8ext[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        operand.regExt = operand.regExt ? 4 : (operand.regs.empty()) ? 1 : 2;

                                        operand.opmode = (rm) ? Symbols::rm8 : Symbols::r8;
                                        operand.bitSize = 8;
                                        parts.push_back("r8");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::R16[i])
                                    {
                                        operand.opmode = (rm) ? Symbols::rm16 : Symbols::r16;
                                        operand.bitSize = 16;
                                        parts.push_back("r16");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::R16ext[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        operand.regExt = operand.regExt ? 4 : (operand.regs.empty()) ? 1 : 2;

                                        operand.opmode = (rm) ? Symbols::rm16 : Symbols::r16;
                                        operand.bitSize = 16;
                                        parts.push_back("r16");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::R32[i])
                                    {
                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::r32;
                                        operand.bitSize = 32;
                                        parts.push_back("r32");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::R32ext[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        operand.regExt = operand.regExt ? 4 : (operand.regs.empty()) ? 1 : 2;

                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::r32;
                                        operand.bitSize = 32;
                                        parts.push_back("r32");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::R64[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::r32;
                                        operand.bitSize = 64;
                                        parts.push_back("r32");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::R64ext[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        operand.regExt = operand.regExt ? 4 : (operand.regs.empty()) ? 1 : 2;

                                        operand.opmode = (rm) ? Symbols::rm32 : Symbols::r32;
                                        operand.bitSize = 64;
                                        parts.push_back("r32");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::SREG[i])
                                    {
                                        operand.opmode = Symbols::sreg;
                                        operand.bitSize = 16;
                                        parts.push_back("sreg");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::STI[i])
                                    {
                                        operand.opmode = Symbols::sti;
                                        operand.bitSize = 16;
                                        parts.push_back("sti");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::STIext[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        operand.regExt = operand.regExt ? 4 : (operand.regs.empty()) ? 1 : 2;

                                        operand.opmode = Symbols::sti;
                                        operand.bitSize = 16;
                                        parts.push_back("sti");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::CRI[i])
                                    {
                                        operand.opmode = Symbols::cri;
                                        operand.bitSize = 32;
                                        parts.push_back("cri");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::CRIext[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        operand.regExt = operand.regExt ? 4 : (operand.regs.empty()) ? 1 : 2;

                                        operand.opmode = Symbols::cri;
                                        operand.bitSize = 32;
                                        parts.push_back("cri");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::DRI[i])
                                    {
                                        operand.opmode = Symbols::dri;
                                        operand.bitSize = 32;
                                        parts.push_back("dri");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::DRIext[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        operand.regExt = operand.regExt ? 4 : (operand.regs.empty()) ? 1 : 2;

                                        operand.opmode = Symbols::dri;
                                        operand.bitSize = 32;
                                        parts.push_back("dri");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::MM[i])
                                    {
                                        node.mmx = true;

                                        operand.opmode = (rm) ? Symbols::mm_m32 : Symbols::mm;
                                        operand.bitSize = 64;
                                        parts.push_back("mm");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::MMext[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        operand.regExt = operand.regExt ? 4 : (operand.regs.empty()) ? 1 : 2;

                                        node.mmx = true;
                                        operand.opmode = (rm) ? Symbols::mm_m32 : Symbols::mm;
                                        operand.bitSize = 64;
                                        parts.push_back("mm");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::XMM[i])
                                    {
                                        node.mmx = true;

                                        operand.opmode = (rm) ? Symbols::xmm_m32 : Symbols::xmm;
                                        operand.bitSize = 128;
                                        parts.push_back("xmm");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                    else if (token == Mnemonics::XMMext[i])
                                    {
                                        if (!mode64) throw SeraphException("64-bit operands not supported");

                                        node.mmx = true;

                                        operand.bitSize = 128;
                                        operand.regExt = operand.regExt ? 4 : (operand.regs.empty()) ? 1 : 2;

                                        operand.opmode = (rm) ? Symbols::xmm_m128 : Symbols::xmm;
                                        parts.push_back("xmm");
                                        operand.regs.push_back(static_cast<uint8_t>(i));
                                        isReserved = true;
                                    }
                                }

                                node.bitSize = (node.bitSize == 0) ? operand.bitSize : node.bitSize;

                                if (isReserved)
                                    continue;

                                size_t sizeNumber = 0; // calculate size

                                bool isNumber = true;
                                bool isNumberHex = false;

                                const auto segPos = token.find(":");
                                bool isSegment = (segPos != std::string::npos);

                                if (token.length() <= ((mode64) ? 17u : 9u) || isSegment)
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
                                        if (token.length() <= 16) sizeNumber = 16;
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
                                            operand.imm8 = static_cast<uint8_t>(std::strtoul(token.c_str(), nullptr, 16));

                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm8 = UINT8_MAX - operand.imm8 + 1; // invert sign

                                            operand.immSize = 8;
                                            operand.flags |= BaseSet_x86_64::OP_IMM8;
                                            parts.push_back("imm8");
                                            break;
                                        case 4:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm16;
                                            operand.imm16 = static_cast<uint16_t>(std::strtoul(token.c_str(), nullptr, 16));

                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm16 = UINT16_MAX - operand.imm16 + 1; // invert sign

                                            operand.immSize = 16;
                                            operand.flags |= BaseSet_x86_64::OP_IMM16;
                                            parts.push_back("imm16");
                                            break;
                                        case 8:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm32;
                                            operand.imm32 = static_cast<uint32_t>(std::strtoul(token.c_str(), nullptr, 16));

                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm32 = UINT32_MAX - operand.imm32 + 1; // invert sign

                                            operand.immSize = 32;
                                            operand.flags |= BaseSet_x86_64::OP_IMM32;
                                            parts.push_back("imm32");
                                            break;
                                        case 16:
                                            if (!mode64) throw SeraphException("64-bit values not supported");

                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm64;
                                            operand.imm64 = static_cast<uint64_t>(std::strtoull(token.c_str(), nullptr, 16));

                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm64 = UINT64_MAX - operand.imm64 + 1; // invert sign

                                            operand.immSize = 64;
                                            operand.flags |= BaseSet_x86_64::OP_IMM64;
                                            parts.push_back("imm64");
                                            break;
                                        default: // Segment/Pointer Offset (Only supports hex)
                                        {
                                            if (isSegment)
                                            {
                                                operand.opmode = Symbols::ptr16_32;
                                                operand.disp16 = static_cast<uint16_t>(std::strtoul(token.substr(0, segPos).c_str(), nullptr, 16));
                                                operand.imm32 = std::strtoul(token.substr(segPos + 1, token.length() - (segPos + 1)).c_str(), nullptr, 16);
                                                operand.flags |= BaseSet_x86_64::OP_IMM16 | BaseSet_x86_64::OP_IMM32;

                                                parts.push_back("ptr16_32");
                                            }
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

                                            operand.immSize = 8;
                                            operand.flags |= BaseSet_x86_64::OP_IMM8;
                                            parts.push_back("imm8");
                                            break;
                                        case 4:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm16;
                                            operand.imm16 = std::atoi(token.c_str());

                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm16 = UINT16_MAX - operand.imm16 + 1;

                                            operand.immSize = 16;
                                            operand.flags |= BaseSet_x86_64::OP_IMM16;
                                            parts.push_back("imm16");
                                            break;
                                        case 8:
                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm32;
                                            operand.imm32 = std::atoi(token.c_str());

                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm32 = UINT32_MAX - operand.imm32 + 1;

                                            operand.immSize = 32;
                                            operand.flags |= BaseSet_x86_64::OP_IMM32;
                                            parts.push_back("imm32");
                                            break;
                                        case 16:
                                            if (!mode64) throw SeraphException("64-bit values not supported");

                                            operand.opmode = (rm) ? operand.opmode : Symbols::imm64;

                                            operand.imm64 = std::atoi(token.c_str());
                                            if (!parts.empty()) if (parts.back() == "-")
                                                operand.imm64 = UINT64_MAX - operand.imm64 + 1;

                                            operand.immSize = 64;
                                            operand.flags |= BaseSet_x86_64::OP_IMM64;
                                            parts.push_back("imm64");
                                            break;
                                        }
                                    }
                                }
                                else
                                {
                                    throw SeraphException("Could not identify label '%s'", token.c_str());
                                }

                                break;
                            }
                            }
                        };

                        // For debugging..
                        // 
                        //printf("(%s) (%i) operand pattern (mod: %i. node has mod: %i): ", node.opName.c_str(), operand.opmode, operand.hasMod, node.hasMod);
                        //for (auto s : parts)
                        //    printf("%s ", s.c_str());
                        //printf("\n");

                        operand.pattern = parts;
                        node.opData.operands.push_back(operand);
                    }
                }

                break;
            }
            }

            if (node.type == Parser::Node::NodeType::AsmNode)
            {
                bool hasExtRegs, reject, solved = false;

                // Look up the corresponding opcode information
                // for our parsed opcode
                for (auto lookup = oplookup_x86_64.begin(); lookup != oplookup_x86_64.end() && !solved; lookup++)
                {
                    if (lookup->first == node.opName)
                    {
                        for (const auto& opvariant : lookup->second)
                        {
                            // Copy the opcodes to a new table for making adjustments,
                            // while figuring out what variant of the opcode to use..
                            // To-do: Probably inefficient, rewrite soon ***
                            std::vector<BaseSet_x86_64::Operand> userOperands(node.opData.operands);
                            
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
                                        // Reset the "hasMod" property of this node,
                                        // which remains the constant while checking
                                        // each opcode variant
                                        for (auto& op : node.opData.operands)
                                        {
                                            node.hasMod = op.hasMod;
                                            if (node.hasMod) break;
                                        }

                                        bool regspec = false;
                                        bool forceValidate = false;

                                        // NOTE: this is a DUPLICATE of the opcode we are using, in this instance.
                                        // Se we can make direct changes to the opcode's type or values
                                        auto op = &userOperands[i];

                                        // Do a check for opcodes that require an rm8/16/32.
                                        // A single register will be accepted, since it is the
                                        // 3rd mode of rm
                                        switch (op->opmode)
                                        {
                                            //
                                            // REG OPERAND <===> RM OPERAND
                                            //
                                        case Symbols::r8:
                                            if (opvariant.symbols[i] == Symbols::rm8 && !node.hasMod)
                                            {
                                                node.hasMod++;
                                                op->opmode = Symbols::rm8;
                                                op->flags = BaseSet_x86_64::OP_R8;
                                                forceValidate = true;
                                            }
                                            break;
                                        case Symbols::r16:
                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::m16_16:
                                                forceValidate = true;
                                                op->opmode = Symbols::m16_16;
                                                op->flags = BaseSet_x86_64::OP_R16;
                                                node.addPrefix(0x66);
                                                break;
                                            case Symbols::rm16:
                                                if (!node.hasMod)
                                                {
                                                    node.hasMod++;
                                                    op->opmode = Symbols::rm16;
                                                    op->flags = BaseSet_x86_64::OP_R16;
                                                    forceValidate = true;
                                                }
                                                break;
                                            }
                                            break;
                                        case Symbols::r32:
                                            if (opvariant.symbols[i] == Symbols::rm32 && !node.hasMod)
                                            {
                                                node.hasMod++;
                                                op->opmode = Symbols::rm32;
                                                op->flags = BaseSet_x86_64::OP_R32;
                                                forceValidate = true;
                                            }
                                            break;
                                        case Symbols::mm:
                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::mm_m32:
                                            case Symbols::mm_m64:
                                                node.hasMod++;
                                                op->opmode = Symbols::mm_m32;
                                                op->flags = BaseSet_x86_64::OP_MM;
                                                forceValidate = true;
                                                break;
                                            }
                                            break;
                                        case Symbols::xmm: // the user passed xmm0-xmm7
                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::mm:
                                                // opcodes that use mm registers can also use xmm, with this prefix
                                                node.addPrefix(B_OPERAND_SIZE_OVERRIDE);
                                                op->opmode = Symbols::mm;
                                                op->flags = BaseSet_x86_64::OP_MM;
                                                forceValidate = true;
                                                break;
                                            case Symbols::mm_m32:
                                            case Symbols::mm_m64:
                                                // opcodes that use mm registers can also use xmm, with this prefix
                                                node.addPrefix(B_OPERAND_SIZE_OVERRIDE);
                                                op->opmode = Symbols::mm_m32;
                                                op->flags = BaseSet_x86_64::OP_MM;
                                                forceValidate = true;
                                                break;
                                            case Symbols::xmm_m32:
                                            case Symbols::xmm_m64:
                                            case Symbols::xmm_m128:
                                                node.hasMod++;
                                                op->opmode = Symbols::xmm_m32;
                                                op->flags = BaseSet_x86_64::OP_XMM;
                                                forceValidate = true;
                                                break;
                                            }
                                            break;
                                            //
                                            // RM OPERAND <===> REG OPERAND
                                            //
                                        case Symbols::rm8: // redundant
                                            //if (node.hasMod) break;

                                            if (opvariant.symbols[i] == Symbols::r8)
                                            {
                                                node.hasMod++;
                                                op->opmode = Symbols::rm8;
                                                op->flags = BaseSet_x86_64::OP_R8;
                                                forceValidate = true;
                                            }
                                            break;
                                        case Symbols::rm16: // redundant
                                            //if (node.hasMod) break;

                                            if (opvariant.symbols[i] == Symbols::r16)
                                            {
                                                node.hasMod++;
                                                op->opmode = Symbols::rm16;
                                                op->flags = BaseSet_x86_64::OP_R16;
                                                forceValidate = true;
                                            }
                                            break;
                                        case Symbols::rm32: // the user passed r32 or [r32+...] (also used in MMX m32/m64/m128 opcodes)
                                            //if (node.hasMod) break;

                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::r32:
                                                if (!op->hasMod)
                                                {
                                                    node.hasMod++;
                                                    op->opmode = Symbols::rm32;
                                                    op->flags = BaseSet_x86_64::OP_R32;
                                                    forceValidate = true;
                                                }
                                                break;
                                            case Symbols::m:
                                            case Symbols::mm:
                                            case Symbols::m8:
                                            case Symbols::m32:
                                            case Symbols::m32int:
                                            case Symbols::m32real:
                                            case Symbols::m64:
                                            case Symbols::m128:
                                            case Symbols::m16_16:
                                            case Symbols::m16_32:
                                            case Symbols::mm_m32:
                                            case Symbols::mm_m64:
                                            case Symbols::xmm_m32:
                                            case Symbols::xmm_m64:
                                            case Symbols::xmm_m128:
                                                forceValidate = true;
                                                break;
                                            }
                                            break;
                                        case Symbols::mm_m32:
                                            //if (node.hasMod) break;

                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::mm:
                                                node.hasMod++;
                                                op->opmode = Symbols::mm_m32;
                                                op->flags = BaseSet_x86_64::OP_MM;
                                                forceValidate = true;
                                                break;
                                            case Symbols::mm_m64:
                                                forceValidate = true;
                                                break;
                                            }
                                            break;
                                        case Symbols::xmm_m32:
                                            //if (node.hasMod) break;

                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::xmm:
                                                node.hasMod++;
                                                op->opmode = Symbols::xmm_m32;
                                                op->flags = BaseSet_x86_64::OP_XMM;
                                                forceValidate = true;
                                                break;
                                            case Symbols::xmm_m64:
                                            case Symbols::xmm_m128:
                                                forceValidate = true;
                                                break;
                                            }
                                            break;
                                            //
                                            // IMM <===> REL (various configurations)
                                            //
                                        case Symbols::imm8:
                                            switch (opvariant.symbols[i])
                                            {
                                            // Example: ret 4 (imm8) should work. ('ret' expects imm16)
                                            case Symbols::imm16:
                                                op->opmode = Symbols::imm16;
                                                op->flags = BaseSet_x86_64::OP_IMM16;
                                                op->immSize = 16;
                                                op->imm16 = static_cast<uint16_t>(op->imm8);
                                                forceValidate = true;
                                                break;
                                            case Symbols::rel8:
                                                op->rel8 = op->imm8;
                                                forceValidate = true;
                                                break;
                                            case Symbols::rel16:
                                                op->rel16 = op->imm16;
                                                forceValidate = true;
                                                break;
                                            case Symbols::rm32:
                                                if (op->hasMod && node.hasMod == 1)
                                                {
                                                    op->opmode = Symbols::rm32;
                                                    forceValidate = true;
                                                }
                                                break;
                                            }
                                            break;
                                        case Symbols::imm16: // To-do: optimize by enabling shorter (rel8) jump when necessary
                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::rel16:
                                            case Symbols::rel32:
                                            case Symbols::imm32:
                                                op->rel16 = op->imm16;
                                                op->rel32 = op->imm32;
                                                forceValidate = true;
                                                break;
                                            case Symbols::rm32:
                                                if (op->hasMod && node.hasMod == 1)
                                                {
                                                    op->opmode = Symbols::rm32;
                                                    forceValidate = true;
                                                }
                                                break;
                                            }
                                            break;
                                        case Symbols::imm32:
                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::rel32:
                                                op->rel32 = op->imm32;
                                                op->opmode = Symbols::rel32;
                                                forceValidate = true;
                                                break;
                                            case Symbols::rm32:
                                                if (op->hasMod && node.hasMod == 1)
                                                {
                                                    op->opmode = Symbols::rm32;
                                                    forceValidate = true;
                                                }
                                                break;
                                            }
                                            break;
                                        case Symbols::imm64:
                                            switch (opvariant.symbols[i])
                                            {
                                            case Symbols::rm32: // we can use the r/m displacement mode
                                                if (!node.hasMod && node.operands.size() == 1)// && !findEntry(opvariant.entries, OpEncoding::r))
                                                {
                                                    op->flags = BaseSet_x86_64::OP_IMM64;
                                                    op->opmode = Symbols::rm32;
                                                    forceValidate = true;
                                                }
                                                break;
                                            case Symbols::rel32:
                                                if (op->imm64 < UINT32_MAX)
                                                {
                                                    op->rel32 = static_cast<uint32_t>(op->imm64);
                                                    op->opmode = Symbols::rel32;
                                                    forceValidate = true;
                                                }
                                                break;
                                            case Symbols::rel64:
                                                op->rel64 = op->imm64;
                                                op->opmode = Symbols::rel64;
                                                forceValidate = true;
                                                break;
                                            case Symbols::imm32:
                                                forceValidate = true;
                                                break;
                                            }
                                            break;
                                        }

                                        switch (op->opmode)
                                        {
                                        //
                                        // R32 <===> (specific reg)
                                        //
                                        case Symbols::cri:
                                        case Symbols::dri:
                                        case Symbols::sti:
                                        case Symbols::sreg:
                                        case Symbols::r8:
                                        case Symbols::r16:
                                        case Symbols::r32:
                                        case Symbols::r64:
                                            if (!op->regs.empty())
                                            {
                                                const auto reg = op->regs.front();

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

                                        // ***
                                        // Consider the following opcodes and their r/m byte:
                                        // 
                                        // 1. psrlq xmm2,3Fh				        encoding: m2, ib	66 0F 73 (D2) 3F 	+C0 	(mm, imm8) (!hasMod)			
                                        // 2. pcmpeqw mm3,mm2				        encoding: r		    0F 75 (DA)		    +C0 	(mm, mm_m64) (!hasMod)
                                        // 3. pcmpeqw mm3,[ecx+04h]		            encoding: r		    0F 75 (59) 04		+40 	(mm, mm_m64)
                                        // 4. pextrw edx,mm5,40h			        encoding: r		    0F C5 (D5) 40 		+C0 	(r32, mm, imm8) (!hasMod)		
                                        // 5. pextrw edx,[ecx],40h			        encoding: r		    0F C5 (11) 0F		+00 	(r32, mm, imm8) (hasMod)		
                                        // 
                                        // 1. Our parser reads "xmm+imm8", but the opcode expects an "mm". We use a prefix to employ xmm, and because there is no mod AND no "r" encoding, we use the 3rd mode for the register.
                                        // 2. Our parser reads "mm+mm". So if the opcode expected an mm_m64, we need one of the mm's to pass as an mm_m64, but act like an mm.
                                        // 3. Our parser reads "mm+rm32". So if the opcode expected an mm_m64, we need this rm32 to pass as an mm_m64, but act like an rm32.
                                        // 4. Our parser reads "r32+mm+imm8". An exception happens where we have two register-only operands. After this is allowed to pass, we have to change the second register-only operand to a "mm_m64" in order to translate to the correct bytecode.
                                        // 5. According to my research, "mm" can also translate to an r/m with a 32-bit register.
                                        //
                                        // It may seem like this is all confusing (and it is), but this enables my parser
                                        // to work along with the format provided by intel reference manuals for x86_64
                                        // This also leaves us with a very minimalistic lookup table / room for optimizing
                                        //
                                        //printf("%i (%s) == %i?\n", op->opmode, node.operands[i].c_str(), opvariant.symbols[i]);

                                        if (forceValidate)
                                            continue;
                                        else if (regspec)
                                            // We won't be using this opmode. It only
                                            // enabled us to look up the correct opcode information
                                            op->opmode = Symbols::not_set;
                                        else if (!forceValidate)
                                            // Reject this opcode comparison if the (other) opmodes do not match
                                            reject = (op->opmode != opvariant.symbols[i]);
                                    }

                                    if (reject)
                                        continue;
                                }
                            }

                            // For debugging..
                            // 
                            //printf("Matched operand (%s) (hasMod: %i) ", node.opName.c_str(), node.hasMod);
                            //for (auto x : node.opData.operands)
                            //    for (auto s : x.pattern)
                            //        printf("%s ", s.c_str());
                            //printf("\nMatched to variant: ");
                            //for (auto x : opvariant.symbols)
                            //    printf("(%i) ", x);
                            //printf("\n");
                            
                            solved = true;

                            size_t streamStartIndex = stream.size();
                            uint8_t usingrex = 0;
                            uint8_t rexEnc = 0;
                            uint8_t hasextreg = 0;
                            uint8_t has64data = 0;

                            if (mode64)
                            {
                                // Note:
                                // Registers used in mod r/m are automatically 64-bit, based on the instruction
                                // We only need to worry about:
                                // -> 64-bit registers being used in the first operand,
                                // -> any of the NEW registers being used in _both_ operands
                                // -> 64-bit immediate/displacement values
                                // Example:
                                // lea ebp,[rsp+00000100] --> 8D AC 24 00 01 00 00
                                // lea rbp,[rsp+00000100] --> 48 8D AC 24 00 01 00 00
                                // lea r8,[rsp+00000100] --> 4C 8D AC 24 00 01 00 00
                                // lea rbp,[r8+00000100] --> 49 8D AC 24 00 01 00 00
                                // lea r8,[r9+00000100] --> 4D 8D AC 24 00 01 00 00
                                // lea ebp,[r9+00000100] --> 41 8D AC 24 00 01 00 00
                                // mov rax,00007F1212121200 --> 48 B8 00 12 12 12 12 7F 00 00

                                for (size_t opIndex = 0; opIndex < userOperands.size(); opIndex++)
                                {
                                    auto op = userOperands[opIndex];

                                    if (op.bitSize >= 64)
                                        has64data++;

                                    if (op.regExt)
                                        hasextreg++;
                                }
                                
                                if (!(opvariant.settings & BaseSet_x86_64::OPS_DEFAULT_64_BITS))
                                {
                                    if (has64data || hasextreg)
                                    {
                                        usingrex = 1;
                                        rexEnc |= 1 << 6; // 01000000
                                    }
                                }
                            }

                            // Add prefix flags
                            for (const uint8_t pre : node.prefixes)
                                stream.add(pre);

                            const auto noperands = userOperands.size();
                            auto insCode = opvariant.code;
                            bool wroteCode = false;
                            uint8_t regenc = 0;
                            uint8_t modenc = 0;

                            for (const auto entry : opvariant.entries)
                            {
                                // If the opcode format is "+rd", then the final opcode byte
                                // is used to denote the (8-32-64 bit) register
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
                                    regenc = 1;
                                    break;
                                case OpEncoding::rb:
                                case OpEncoding::rw:
                                case OpEncoding::rd:
                                    if (opvariant.code.size() > 1)
                                        for (size_t i = 0; i < opvariant.code.size() - 1; i++)
                                            stream.add(opvariant.code[i]);

                                    if (userOperands.front().regExt)
                                    {
                                        usingrex = 1;
                                        rexEnc |= 1 << 6; // 01000000
                                        rexEnc |= 1;
                                    }

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
                                bool hasImm8 = false, hasImm16 = false, hasImm32 = false, hasImm64 = false;
                                bool hasDisp8 = false, hasDisp16 = false, hasDisp32 = false, hasDisp64 = false;
                                bool useModByte = false;

                                uint8_t imm8value = 0;
                                uint16_t imm16value = 0;
                                uint32_t imm32value = 0;
                                uint64_t imm64value = 0;

                                uint8_t disp8value = 0;
                                uint16_t disp16value = 0;
                                uint32_t disp32value = 0;
                                uint64_t disp64value = 0;

                                uint8_t modbyte = modenc;
                                uint8_t sibbyte = 0;

                                modenc = 0;

                                for (size_t i = 0; i < userOperands.size(); i++)
                                {
                                    const auto op = userOperands[i];

                                    if (node.marked && node.markedOperand == i)
                                        node.markedOffset = stream.size() + useModByte + hasSib + hasImm8 + (hasImm16 ? 16 : 0) + (hasImm32 ? 32 : 0) + (hasImm64 ? 64 : 0) + hasDisp8 + (hasDisp16 ? 16 : 0) + (hasDisp32 ? 32 : 0) + (hasDisp64 ? 64 : 0);
                                    
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
                                    case Symbols::imm64:
                                        rexEnc |= 1 << 3;
                                        disp64value = op.imm64;
                                        hasDisp64 = true;
                                        break;
                                    case Symbols::rel8:
                                        imm8value = static_cast<uint8_t>(op.rel8 - (offset + stream.size() + 1));
                                        hasImm8 = true;
                                        break;
                                    case Symbols::rel16:
                                        imm16value = static_cast<uint16_t>(op.rel16 - (offset + stream.size() + 2));
                                        hasImm16 = true;
                                        break;
                                    case Symbols::rel32:
                                        imm32value = static_cast<uint32_t>(op.rel32 - (offset + stream.size() + 4));
                                        hasImm32 = true;
                                        break;
                                    case Symbols::rel64:
                                        imm64value = static_cast<uint64_t>(op.rel64 - (offset + stream.size() + 8));
                                        hasImm64 = true;
                                        break;
                                    case Symbols::ptr16_32:
                                        disp16value = op.disp16;
                                        hasDisp16 = true;
                                        imm32value = op.imm32;
                                        hasImm32 = true;
                                        break;
                                    case Symbols::sti:
                                        if (!findEntry(opvariant.entries, OpEncoding::i))
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
                                    case Symbols::moffs64:
                                        rexEnc |= 1 << 3;
                                        imm64value = op.imm64;
                                        hasImm64 = true;
                                        break;
                                    case Symbols::cri:
                                    case Symbols::dri:
                                    case Symbols::sreg:
                                    case Symbols::mm:
                                    case Symbols::xmm:
                                    case Symbols::r8:
                                    case Symbols::r16:
                                    case Symbols::r32:
                                    case Symbols::r64:
                                        useModByte = true;

                                        if (op.bitSize >= 64)
                                            rexEnc |= 1 << 3;

                                        if (op.regExt)
                                            rexEnc |= 1 << 2;

                                        if (!findEntry(opvariant.entries, OpEncoding::r))
                                        {
                                            modenc = 3 << 6;
                                            modbyte += op.regs.front();
                                            break;
                                        }

                                        modbyte += op.regs.front() << 3;
                                        break;
                                    case Symbols::mm2:
                                    case Symbols::xmm2:
                                        useModByte = true;
                                        modenc = 3 << 6; // restricted to one mode (3rd)
                                        modbyte += op.regs.front();
                                        break;
                                    case Symbols::rm8:
                                    case Symbols::rm16:
                                    case Symbols::rm32:
                                    case Symbols::rm64:
                                    case Symbols::m16_16:
                                    case Symbols::m16_32:
                                    case Symbols::mm_m32:
                                    case Symbols::mm_m64:
                                    case Symbols::xmm_m32:
                                    case Symbols::xmm_m64:
                                    case Symbols::xmm_m128:
                                        useModByte = true;

                                        // Just a single register-only operand
                                        if (op.regs.size() == 1 && !(op.flags & BaseSet_x86_64::OP_RM)/*!node.hasMod*/)
                                        {
                                            if (op.bitSize >= 64)
                                                rexEnc |= 1 << 3;

                                            if (op.regExt)
                                                rexEnc |= 1;

                                            modenc = 3 << 6;
                                            modbyte += op.regs.front();
                                            break;
                                        }
                                        
                                        // No regs, or segments, just a 32-bit memory offset
                                        if (op.regs.size() == 0 && op.flags & BaseSet_x86_64::OP_IMM32 && !node.segment)
                                        {
                                            modbyte += 5;
                                            imm32value = op.imm32;
                                            hasImm32 = true;
                                            break;
                                        }

                                        // Multiplier? Ok, introduce SIB
                                        if (op.mul)
                                            sibbyte |= (1 + (op.mul >> 2)) << 6;

                                        switch (op.regs.size())
                                        {
                                        case 0:
                                            //if (node.segment)
                                            //{
                                                hasSib = true;
                                                modbyte += 4;
                                                sibbyte |= 1 << 5;
                                                sibbyte += 5;
                                                imm32value = (op.flags & BaseSet_x86_64::OP_IMM8) ? op.imm8 : op.imm32;
                                                hasImm32 = true;
                                            //}
                                            //else
                                            //{
                                            //    modbyte += 5;
                                            //    //modenc = 2 << 6;
                                            //    imm32value = (op.flags & BaseSet_x86_64::OP_IMM8) ? op.imm8 : op.imm32;
                                            //    hasImm32 = true;
                                            //}
                                            break;
                                        case 1:
                                            // If a multiplier is present, use displacement mode w/ reg
                                            if (op.mul)
                                            {
                                                hasSib = true;
                                                modbyte += 4;
                                                sibbyte += 5;
                                                sibbyte += op.regs.front() << 3;

                                                if (op.flags & BaseSet_x86_64::OP_IMM8)
                                                {
                                                    imm32value = op.imm8;
                                                    hasImm32 = true;
                                                }
                                                else if (op.flags & BaseSet_x86_64::OP_IMM32)
                                                {
                                                    imm32value = op.imm32;
                                                    hasImm32 = true;
                                                }
                                                else if (op.flags & BaseSet_x86_64::OP_IMM64)
                                                {
                                                    imm32value = 0;
                                                    hasImm32 = true;
                                                    disp64value = op.imm64;
                                                    hasDisp64 = true;
                                                }

                                                break;
                                            }
                                            
                                            // No multiplier?
                                            // 
                                            if (op.regs.front() == 4) // SP/ESP
                                            {
                                                modbyte += op.regs.front();
                                                hasSib = true;
                                                sibbyte |= 1 << 5; // set index flag
                                                sibbyte += 4;
                                            }
                                            else
                                            {
                                                // Use mod byte for registers
                                                modbyte += op.regs.front();
                                            }

                                            // Append standard IMM values 
                                            if (op.flags & BaseSet_x86_64::OP_IMM8)
                                            {
                                                modenc = 1 << 6;
                                                imm8value = op.imm8;
                                                hasImm8 = true;
                                            }
                                            else if (op.flags & BaseSet_x86_64::OP_IMM32)
                                            {
                                                modenc = 2 << 6;
                                                imm32value = op.imm32;
                                                hasImm32 = true;
                                            }
                                            else if (op.flags & BaseSet_x86_64::OP_IMM64)
                                            {
                                                modenc = 2 << 6;
                                                imm32value = 0;
                                                hasImm32 = true;
                                                disp64value = op.imm64;
                                                hasDisp64 = true;
                                            }

                                            break;
                                        case 2:
                                        default:
                                            hasSib = true;
                                            modbyte += 4;
                                            sibbyte += op.regs.front();
                                            sibbyte += op.regs.back() << 3;

                                            if (op.flags & BaseSet_x86_64::OP_IMM8)
                                            {
                                                modenc = 1 << 6;
                                                imm8value = op.imm8;
                                                hasImm8 = true;
                                            }
                                            else if (op.flags & BaseSet_x86_64::OP_IMM32)
                                            {
                                                modenc = 2 << 6;
                                                imm32value = op.imm32;
                                                hasImm32 = true;
                                            }
                                            else if (op.flags & BaseSet_x86_64::OP_IMM64)
                                            {
                                                modenc = 2 << 6;
                                                imm32value = 0;
                                                hasImm32 = true;
                                                disp64value = op.imm64;
                                                hasDisp64 = true;
                                            }

                                            break;
                                        }

                                        if (useModByte && op.regExt)
                                            rexEnc |= op.regExt == 4 ? 1 : op.regExt;

                                        break;
                                    }
                                }

                                modbyte |= modenc;

                                if (usingrex) // append our finished rex encoding at the beginning
                                    stream.insert(stream.begin() + streamStartIndex, rexEnc);

                                if (useModByte)
                                    stream.add(modbyte);

                                if (hasSib)
                                    stream.add(sibbyte);

                                if (hasImm8)
                                    stream.add(imm8value);

                                if (hasImm16)
                                {
                                    std::vector<uint8_t> b(2, 0);
                                    memcpy(&b[0], &imm16value, 2);
                                    stream.add(b);
                                }

                                if (hasImm32)
                                {
                                    std::vector<uint8_t> b(4, 0);
                                    memcpy(&b[0], &imm32value, 4);
                                    stream.add(b);
                                }

                                if (hasImm64)
                                {
                                    std::vector<uint8_t> b(8, 0);
                                    memcpy(&b[0], &imm64value, 8);
                                    stream.add(b);
                                }

                                if (hasDisp8)
                                    stream.add(disp8value);

                                if (hasDisp16)
                                {
                                    std::vector<uint8_t> b(2, 0);
                                    memcpy(&b[0], &disp16value, 2);
                                    stream.add(b);
                                }

                                if (hasDisp32)
                                {
                                    std::vector<uint8_t> b(4, 0);
                                    memcpy(&b[0], &disp32value, 4);
                                    stream.add(b);
                                }

                                if (hasDisp64)
                                {
                                    std::vector<uint8_t> b(8, 0);
                                    memcpy(&b[0], &disp64value, 8);
                                    stream.add(b);
                                }
                            }

                            break;
                        }
                    }
                }

                if (!solved)
                {
                    std::stringstream errMsg;
                    errMsg << node.opName;

                    int n = 0;

                    for (auto op : node.opData.operands)
                    {
                        if (n++ > 0) errMsg << ",";
                        errMsg << " ";
                        for (auto s : op.pattern)
                            errMsg << s;
                    }

                    throw SeraphException("Could not understand pattern '%s'", errMsg.str().c_str());
                }
            }
        }

        for (Parser::Node& node : mainBody.nodes)
        {
            if (node.marked)
            {
                auto labelNode = getLabel(node.markedLabel);
                if (labelNode)
                {
                    // printf("Marked code offset: %016llX. Needs to jump to: %016llX (label `%s`).\n", offset + node.markedOffset, offset + labelNode->streamIndex, labelNode->label.c_str());

                    const auto offsetOverwrite = offset + node.markedOffset;
                    const auto offsetJumpTo = offset + labelNode->streamIndex;
                    const auto relative = offsetJumpTo - (offsetOverwrite + 4);

                    *reinterpret_cast<uint32_t*>(&stream.data()[node.markedOffset]) = static_cast<uint32_t>(relative);
                }
            }
        }

        return stream;
    }


    ByteStream Assembler<TargetArchitecture::x86>::compile(const std::string& source, const uintptr_t offset)
    {
        return compile_x86_64(source, prelookup_x86_64, oplookup_x86_64, offset, false);
    }

    ByteStream Assembler<TargetArchitecture::x64>::compile(const std::string& source, const uintptr_t offset)
    {
        return compile_x86_64(source, prelookup_x86_64, oplookup_x86_64, offset, true);
    }
}

