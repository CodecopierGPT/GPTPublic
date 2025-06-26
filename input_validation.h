#ifndef INPUT_VALIDATION_H
#define INPUT_VALIDATION_H

#include <string>

// Shell命令转义函数
// 对字符串进行shell转义，防止命令注入
std::string shell_quote(const std::string& str);

// IP地址验证函数
// 验证IPv4地址格式是否正确 (如: 192.168.1.1)
bool validate_ipv4(const std::string& ip);

// IPv6地址验证函数
// 验证IPv6地址格式是否正确
bool validate_ipv6(const std::string& ip);

// 子网掩码验证函数
// 验证子网掩码格式是否正确 (如: 255.255.255.0)
bool validate_netmask(const std::string& mask);

// MAC地址验证函数
// 验证MAC地址格式是否正确 (如: AA:BB:CC:DD:EE:FF)
bool validate_mac_address(const std::string& mac);

// 网络接口名验证函数
// 验证网络接口名是否合法 (如: eth0, wlan0)
bool validate_interface_name(const std::string& ifname);

// 主机名验证函数
// 验证主机名是否合法 (RFC 1123)
bool validate_hostname(const std::string& hostname);

// 端口号验证函数
// 验证端口号是否在有效范围内 (1-65535)
bool validate_port(int port);

// 文件路径验证函数
// 验证文件路径是否安全（防止路径遍历攻击）
bool validate_filepath(const std::string& path);

// 数字字符串验证函数
// 验证字符串是否只包含数字
bool validate_numeric(const std::string& str);

// 字母数字字符串验证函数
// 验证字符串是否只包含字母和数字
bool validate_alphanumeric(const std::string& str);

#endif // INPUT_VALIDATION_H
