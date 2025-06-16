#include <iostream>
#include <string>
#include <regex>
#include <algorithm>
#include <cctype>
#include <vector>
#include <sstream>

using namespace std;

class HostValidator {
private:
    // 危险字符列表，用于防止注入攻击
    static const string DANGEROUS_CHARS;
    
    // IPv4地址正则表达式
    static const regex IPV4_PATTERN;
    
    // IPv6地址正则表达式  
    static const regex IPV6_PATTERN;
    
    // 域名正则表达式
    static const regex DOMAIN_PATTERN;
    
public:
    /**
     * 检查字符串是否包含危险字符
     */
    bool containsDangerousChars(const string& input) const {
        return input.find_first_of(DANGEROUS_CHARS) != string::npos;
    }
    
    /**
     * 验证IPv4地址
     */
    bool isValidIPv4(const string& ip) const {
        if (!regex_match(ip, IPV4_PATTERN)) {
            return false;
        }
        
        // 进一步验证每个数字段是否在0-255范围内
        vector<string> octets;
        stringstream ss(ip);
        string octet;
        
        while (getline(ss, octet, '.')) {
            octets.push_back(octet);
        }
        
        if (octets.size() != 4) return false;
        
        for (const string& oct : octets) {
            // 检查前导零（除了"0"本身）
            if (oct.length() > 1 && oct[0] == '0') {
                return false;
            }
            
            int num = stoi(oct);
            if (num < 0 || num > 255) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 验证IPv6地址
     */
    bool isValidIPv6(const string& ip) const {
        // 基本格式检查
        if (!regex_match(ip, IPV6_PATTERN)) {
            return false;
        }
        
        // 检查双冒号的使用（最多只能有一个）
        size_t doubleColonCount = 0;
        size_t pos = 0;
        while ((pos = ip.find("::", pos)) != string::npos) {
            doubleColonCount++;
            pos += 2;
        }
        
        if (doubleColonCount > 1) {
            return false;
        }
        
        // 检查段数
        vector<string> segments;
        stringstream ss(ip);
        string segment;
        
        if (doubleColonCount == 0) {
            // 没有双冒号，必须有8段
            while (getline(ss, segment, ':')) {
                segments.push_back(segment);
            }
            if (segments.size() != 8) return false;
        }
        
        return true;
    }
    
    /**
     * 验证域名/主机名
     */
    bool isValidDomain(const string& domain) const {
        // 长度检查
        if (domain.length() > 253) return false;
        if (domain.empty()) return false;
        
        // 基本格式检查
        if (!regex_match(domain, DOMAIN_PATTERN)) {
            return false;
        }
        
        // 不能以点开始或结束
        if (domain[0] == '.' || domain.back() == '.') {
            return false;
        }
        
        // 检查每个标签的长度
        vector<string> labels;
        stringstream ss(domain);
        string label;
        
        while (getline(ss, label, '.')) {
            if (label.length() > 63 || label.empty()) {
                return false;
            }
            // 标签不能以连字符开始或结束
            if (label[0] == '-' || label.back() == '-') {
                return false;
            }
            labels.push_back(label);
        }
        
        return labels.size() > 0;
    }
    
    /**
     * 主验证函数
     */
    bool validate(const string& host) const {
        // 基本安全检查
        if (host.empty() || host.length() > 253) {
            return false;
        }
        
        // 检查危险字符
        if (containsDangerousChars(host)) {
            return false;
        }
        
        // 尝试各种格式验证
        return isValidIPv4(host) || isValidIPv6(host) || isValidDomain(host);
    }
};

// 静态成员定义
const string HostValidator::DANGEROUS_CHARS = ";<>|&`$(){}[]\"'\\*?~^!";

const regex HostValidator::IPV4_PATTERN(
    R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
);

const regex HostValidator::IPV6_PATTERN(
    R"(^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$|^::$|^::1$|^([0-9a-fA-F]{0,4}:){1,6}:$|^:([0-9a-fA-F]{0,4}:){1,6}$)"
);

const regex HostValidator::DOMAIN_PATTERN(
    R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$)"
);

/**
 * 主要的验证函数
 */
bool is_valid_host(const string& host) {
    static HostValidator validator;
    return validator.validate(host);
}
