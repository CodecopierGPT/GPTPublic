
#include <string>
#include <cctype>
using namespace std;

string fix_domain_name(const string& s) {
    if (s.empty()) {
        return "";
    }
    
    string result;
    result.reserve(s.length()); // 预分配空间提高效率
    
    for (char c : s) {
        // 只保留字母、数字和连接符
        if (isalnum(c) || c == '-') {
            result += c;
        }
        // 其他字符直接丢弃
    }
    
    if (result.empty()) {
        return "";
    }
    
    // 处理连接符规则
    string fixed;
    fixed.reserve(result.length());
    
    char prev = '\0';
    for (char c : result) {
        // 跳过开头的连接符
        if (fixed.empty() && c == '-') {
            continue;
        }
        
        // 跳过连续的连接符
        if (c == '-' && prev == '-') {
            continue;
        }
        
        fixed += c;
        prev = c;
    }
    
    // 去掉结尾的连接符
    while (!fixed.empty() && fixed.back() == '-') {
        fixed.pop_back();
    }
    
    // 限制长度为63个字符
    if (fixed.length() > 63) {
        fixed = fixed.substr(0, 63);
        // 再次检查结尾是否有连接符
        while (!fixed.empty() && fixed.back() == '-') {
            fixed.pop_back();
        }
    }
    
    return fixed;
}
