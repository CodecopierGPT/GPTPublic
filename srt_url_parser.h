#ifndef SRT_URL_PARSER_H_
#define SRT_URL_PARSER_H_

#include <string>
#include <map>
#include <vector>

// SRT选项结构体
struct srt_options {
  std::string mode;                   // caller/listener，没有找到，则默认caller
  std::string host;                   // 主机地址 (IP或域名)，listener模式为空
  int port;                           // 端口号， -1表示使用默认值
  std::string streamid;               // 流标识符，空字符串表示忽略
  
  // === 安全参数 ===
  std::string passphrase;             // 加密密码，空字符串表示不加密
  int pbkeylen;                       // 密钥长度：16(AES-128), 24(AES-192), 32(AES-256)， -1表示使用默认值
  
  // === 性能参数 ===
  int latency;                        // 延迟设置(毫秒)，-1表示使用默认值
  int maxbw;                          // 最大带宽(bytes/sec)，-1表示无限制
  int rcvbuf;                         // 接收缓冲区大小(bytes)，-1表示使用默认值
  int sndbuf;                         // 发送缓冲区大小(bytes)，-1表示使用默认值
  
  // === 网络参数 ===
  int ipttl;                          // IP层TTL值，-1表示使用默认值
  int conntimeo;                      // 连接超时(毫秒)，-1表示使用默认值
};

// 主函数声明
int parse_srt_url(const std::string& srt_url, srt_options& opt);
void print_srt_options(const srt_options& opt);

#endif  // SRT_URL_PARSER_H_
