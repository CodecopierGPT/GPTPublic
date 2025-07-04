#include <iostream>
#include <regex>
#include <string>
#include <vector>

// IPv6 full form regex: eight groups of 1-4 hex digits
static const std::regex ip6_full(
    R"(^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$)",
    std::regex_constants::icase);

// IPv6 compressed form regex: exactly one "::"
// IPv6 compressed form regex covering valid "::" usage
static const std::regex ip6_comp(
    R"(^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?)$)",
    std::regex_constants::icase);

struct TestCase {
    std::string input;
    bool expect;
};

void run_tests(const std::string& name, const std::regex& re,
               const std::vector<TestCase>& cases) {
    int passed = 0;
    std::cout << "Testing " << name << std::endl;
    for (const auto& tc : cases) {
        bool result = std::regex_match(tc.input, re);
        std::cout << "  " << tc.input << " -> "
                  << (result ? "match" : "no match")
                  << " (expect " << (tc.expect ? "match" : "no match") << ")";
        if (result == tc.expect) {
            std::cout << " [OK]" << std::endl;
            ++passed;
        } else {
            std::cout << " [FAIL]" << std::endl;
        }
    }
    std::cout << name << ": " << passed << "/" << cases.size()
              << " tests passed" << std::endl << std::endl;
}

int main() {
    std::vector<TestCase> full_cases = {
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
        {"ABCD:EF01:2345:6789:ABCD:EF01:2345:6789", true},
        {"1:2:3:4:5:6:7:8", true},
        {"0000:0000:0000:0000:0000:0000:0000:0000", true},
        {"ffff:FFFF:ffff:FFFF:ffff:FFFF:ffff:FFFF", true},
        {"FE80:0000:0000:0000:0202:B3FF:FE1E:8329", true},
        {"0:0:0:0:0:0:0:0", true},

        {"2001:db8:85a3::8a2e:370:7334", false},
        {"2001:db8:85a3:0:0:8a2e:370", false},
        {"1:2:3:4:5:6:7:8:9", false},
        {"12345:0:0:0:0:0:0:1", false},
        {"GGGG:0000:0000:0000:0000:0000:0000:0001", false},
        {":1:2:3:4:5:6:7:8", false},
        {"1:2:3:4:5:6:7:8:", false},
        {"", false},
        {"1::2:3:4:5:6:7", false},
        {"1:2:3:4:5:6:7", false},
        {"1:2:3:4:5:6:7:8 ", false},
        {" 1:2:3:4:5:6:7:8", false}
    };

    std::vector<TestCase> comp_cases = {
        {"::", true},
        {"::1", true},
        {"1::", true},
        {"1::1", true},
        {"2001:db8::8a2e:370:7334", true},
        {"2001:db8::", true},
        {"ffff::ffff", true},
        {"::ffff", true},
        {"1:2:3:4:5:6::7", true},
        {"1:2:3::4:5:6:7", true},
        {"fe80::1ff:fe23:4567:890a", true},
        {"::1234:5678:9abc:def0", true},
        {"1:2:3:4:5::6:7", true},
        {"0:0:0:0:0::", true},
        {"::0", true},
        {"0::0", true},

        {"1::2::3", false},
        {"::g", false},
        {"12345::", false},
        {"::1:2:3:4:5:6:7:8:9", false},
        {":1::2", false},
        {"::ffff:192.168.0.1", false},
        {"1:2:3:4:5:6:7::8", false},
        {"1:2:3:4:5:6:7:8::", false},
        {"", false},
        {":::1", false},
        {"1:::2", false},
        {":::", false},
        {"1:2:3:4:5:6::7::", false},
        {"::1:2:3:4:5:6:7:8", false},
        {"1::2:", false}
    };

    run_tests("ip6_full", ip6_full, full_cases);
    run_tests("ip6_comp", ip6_comp, comp_cases);
    return 0;
}

