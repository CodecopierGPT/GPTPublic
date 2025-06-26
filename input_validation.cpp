#include "input_validation.h"
#include <regex>
#include <arpa/inet.h>
#include <algorithm>
#include <cctype>

// Shell命令转义函数
std::string shell_quote(const std::string& s) {
    std::string res;
    res.reserve(s.size() + 2);   // 头尾包裹 + 少量引号转义
    res += '\'';                 // 起始单引号

    for (char c : s) {
        if (c == '\'')
            res += "'\\''";      // 结束 -> \' -> 重新开始
        else
            res += c;
    }

    res += '\'';                 // 结束单引号
    return res;
}

// IP地址验证函数
bool validate_ipv4(const std::string& ip) {
    // 使用inet_pton进行验证
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
}

// IPv6地址验证函数
bool validate_ipv6(const std::string& ip) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) == 1;
}

// 子网掩码验证函数
bool validate_netmask(const std::string& mask) {
    // 首先验证是否为有效的IPv4地址
    if (!validate_ipv4(mask)) {
        return false;
    }
    
    // 转换为32位整数验证是否为有效掩码
    struct sockaddr_in sa;
    inet_pton(AF_INET, mask.c_str(), &(sa.sin_addr));
    uint32_t mask_val = ntohl(sa.sin_addr.s_addr);
    
    // 有效的掩码必须是连续的1后面跟连续的0
    if (mask_val == 0) return false;
    
    // 检查方法：mask_val 加 1 应该是 2 的幂
    // 例如：11111111111111111111111100000000 (255.255.255.0) + 1 = 100000000 (2^8)
    uint32_t check = mask_val + 1;
    
    // 特殊情况：255.255.255.255 (/32)
    if (mask_val == 0xFFFFFFFF) return true;
    
    // 检查是否只有高位连续的1
    // 方法：反转后应该是连续的1（即2^n - 1的形式）
    uint32_t flipped = ~mask_val;
    return (flipped & (flipped + 1)) == 0;
}

// MAC地址验证函数
bool validate_mac_address(const std::string& mac) {
    // MAC地址格式: XX:XX:XX:XX:XX:XX (X为十六进制数字)
    std::regex mac_regex("^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");
    return std::regex_match(mac, mac_regex);
}

// 网络接口名验证函数
bool validate_interface_name(const std::string& ifname) {
    // Linux接口名规则：最多15个字符，字母开头，可包含字母、数字、下划线
    if (ifname.empty() || ifname.length() > 15) {
        return false;
    }
    
    // 必须以字母开头
    if (!std::isalpha(ifname[0])) {
        return false;
    }
    
    // 只能包含字母、数字、下划线、冒号（用于虚拟接口如eth0:0）
    for (char c : ifname) {
        if (!std::isalnum(c) && c != '_' && c != ':') {
            return false;
        }
    }
    
    return true;
}

// 主机名验证函数
bool validate_hostname(const std::string& hostname) {
    // RFC 1123: 主机名最多253个字符，每个标签最多63个字符
    if (hostname.empty() || hostname.length() > 253) {
        return false;
    }
    
    // 分割成标签
    size_t start = 0;
    size_t dot_pos = hostname.find('.');
    
    while (start < hostname.length()) {
        size_t label_len = (dot_pos != std::string::npos) ? 
                          (dot_pos - start) : (hostname.length() - start);
        
        // 标签长度检查
        if (label_len == 0 || label_len > 63) {
            return false;
        }
        
        // 标签内容检查
        for (size_t i = start; i < start + label_len; i++) {
            char c = hostname[i];
            // 必须是字母、数字或连字符
            if (!std::isalnum(c) && c != '-') {
                return false;
            }
            // 不能以连字符开头或结尾
            if (c == '-' && (i == start || i == start + label_len - 1)) {
                return false;
            }
        }
        
        if (dot_pos == std::string::npos) {
            break;
        }
        
        start = dot_pos + 1;
        dot_pos = hostname.find('.', start);
    }
    
    return true;
}

// 端口号验证函数
bool validate_port(int port) {
    return port >= 1 && port <= 65535;
}

// 文件路径验证函数
bool validate_filepath(const std::string& path) {
    // 禁止路径遍历
    if (path.find("..") != std::string::npos) {
        return false;
    }
    
    // 禁止绝对路径（可根据需求调整）
    if (!path.empty() && path[0] == '/') {
        return false;
    }
    
    // 只允许安全的字符
    for (char c : path) {
        if (!std::isalnum(c) && c != '/' && c != '_' && c != '-' && c != '.') {
            return false;
        }
    }
    
    return !path.empty();
}

// 数字字符串验证函数
bool validate_numeric(const std::string& str) {
    if (str.empty()) return false;
    
    for (char c : str) {
        if (!std::isdigit(c)) {
            return false;
        }
    }
    
    return true;
}

// 字母数字字符串验证函数
bool validate_alphanumeric(const std::string& str) {
    if (str.empty()) return false;
    
    for (char c : str) {
        if (!std::isalnum(c)) {
            return false;
        }
    }
    
    return true;
}
