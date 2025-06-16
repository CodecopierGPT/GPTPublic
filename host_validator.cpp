#include <string>
#include <vector>
#include <regex>
#include <sstream>
#include <cctype>
#include "host_validator.h"

using namespace std;

class HostValidator {
private:
    // 危险字符列表，用于防止注入攻击
    static const string DANGEROUS_CHARS;
    
    // 域名正则表达式
    static const regex DOMAIN_PATTERN;

    /**
     * 验证纯IPv6十六进制格式的辅助函数
     */
    bool isValidIPv6Hex(const string& ip) const {
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
        
        // 分割地址段
        vector<string> segments;
        if (doubleColonCount == 1) {
            // 有双冒号的情况
            size_t doubleColonPos = ip.find("::");
            string before = ip.substr(0, doubleColonPos);
            string after = ip.substr(doubleColonPos + 2);
            
            if (!before.empty()) {
                stringstream ss(before);
                string segment;
                while (getline(ss, segment, ':')) {
                    if (!segment.empty()) segments.push_back(segment);
                }
            }
            
            if (!after.empty()) {
                stringstream ss(after);
                string segment;
                while (getline(ss, segment, ':')) {
                    if (!segment.empty()) segments.push_back(segment);
                }
            }
            
            // 双冒号表示零压缩，总段数不能超过8
            if (segments.size() >= 8) return false;
        } else {
            // 没有双冒号，必须有8段
            stringstream ss(ip);
            string segment;
            while (getline(ss, segment, ':')) {
                segments.push_back(segment);
            }
            if (segments.size() != 8) return false;
        }
        
        // 验证每个段
        for (const string& segment : segments) {
            if (segment.length() > 4 || segment.empty()) {
                return false;
            }
            
            for (char c : segment) {
                if (!isxdigit(c)) {
                    return false;
                }
            }
        }
        
        return true;
    }

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
        // 分割IP地址
        vector<string> octets;
        stringstream ss(ip);
        string octet;
        
        while (getline(ss, octet, '.')) {
            octets.push_back(octet);
        }
        
        // 必须有4段
        if (octets.size() != 4) return false;
        
        for (const string& oct : octets) {
            // 检查空段
            if (oct.empty()) return false;
            
            // 检查前导零（除了"0"本身）
            if (oct.length() > 1 && oct[0] == '0') {
                return false;
            }
            
            // 检查是否只包含数字
            for (char c : oct) {
                if (!isdigit(c)) return false;
            }
            
            // 检查长度（最多3位）
            if (oct.length() > 3) return false;
            
            // 转换为数字并检查范围
            try {
                int num = stoi(oct);
                if (num < 0 || num > 255) {
                    return false;
                }
            } catch (...) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 验证IPv6地址
     */
    bool isValidIPv6(const string& ip) const {
        // 处理特殊情况
        if (ip == "::") return true;
        if (ip == "::1") return true;
        
        // 检查是否包含IPv4映射 (::ffff:192.0.2.1)
        size_t lastColon = ip.find_last_of(':');
        if (lastColon != string::npos && lastColon < ip.length() - 1) {
            string lastPart = ip.substr(lastColon + 1);
            // 如果最后一部分看起来像IPv4地址，尝试验证
            if (lastPart.find('.') != string::npos) {
                if (isValidIPv4(lastPart)) {
                    // 验证IPv6部分
                    string ipv6Part = ip.substr(0, lastColon + 1);
                    return isValidIPv6Hex(ipv6Part + "0");
                }
            }
        }
        
        return isValidIPv6Hex(ip);
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
     * 检查是否看起来像IPv4地址（包括格式错误的）
     */
    bool looksLikeIPv4(const string& host) const {
        // 包含点且所有非点字符都是数字
        if (host.find('.') == string::npos) return false;
        
        for (char c : host) {
            if (c != '.' && !isdigit(c)) {
                return false;
            }
        }
        return true;
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
        
        // 智能选择验证器：
        // 1. 如果看起来像IPv4地址（包含点且都是数字），只用IPv4验证
        if (looksLikeIPv4(host)) {
            return isValidIPv4(host);
        }
        
        // 2. 如果包含冒号，很可能是IPv6地址
        if (host.find(':') != string::npos) {
            return isValidIPv6(host);
        }
        
        // 3. 否则当作域名验证
        return isValidDomain(host);
    }
};

// 静态成员定义
const string HostValidator::DANGEROUS_CHARS = ";<>|&`$(){}[]\"'\\*?~^!";

// 保留域名正则表达式
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
