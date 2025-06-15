// ===========================================
// 测试和使用示例
// ===========================================
#include <cstdio>
#include <cstddef>
#include <string>
#include <vector>
#include "srt_url_parser.h"
void test_parse_srt_url() {
  printf("=== SRT URL解析测试 ===\n\n");
  
  // 测试用例
  std::vector<std::string> test_urls = {
    // 基础URL
    "srt://192.168.1.100:9999",
    
    // 带流ID
    "srt://stream.example.com:1935?streamid=live/channel1",
    
    // 加密配置
    "srt://secure.example.com:9999?passphrase=secret123&pbkeylen=16",
    
    // 完整配置
    "srt://premium.example.com:1935?mode=caller&streamid=live/premium&passphrase=ultra_secure&pbkeylen=32&latency=100&maxbw=8000000&rcvbuf=4000000&sndbuf=4000000&ipttl=64&conntimeo=5000",
    
    // Listener模式
    "srt://:9999?mode=listener&streamid=live/input",
    
    // 只有参数，无主机端口
    "srt://?mode=listener&latency=200",
    
    // 错误格式测试
    "http://wrong.protocol.com:9999",
    "",
    "srt://",
    
    // 边界值测试
    "srt://test.com:1935?latency=0&maxbw=abc&pbkeylen=99"
  };
  
  for (size_t i = 0; i < test_urls.size(); ++i) {
    printf("测试 %zu: %s\n", i + 1, test_urls[i].c_str());
    
    srt_options opt;
    int result = parse_srt_url(test_urls[i], opt);
    
    if (result == 0) {
      printf("✅ 解析成功:\n");
      print_srt_options(opt);
    } else {
      printf("❌ 解析失败\n");
    }
    printf("\n");
  }
}

// 实际使用示例
void usage_example() {
  printf("=== 实际使用示例 ===\n\n");
  
  // 示例1：解析复杂URL
  std::string complex_url = "srt://live.example.com:1935?streamid=live/hd&passphrase=secret&latency=120&maxbw=5000000";
  srt_options options;
  
  if (parse_srt_url(complex_url, options) == 0) {
    printf("解析成功，配置如下:\n");
    printf("连接: %s:%d (模式: %s)\n", options.host.c_str(), options.port, options.mode.c_str());
    printf("流ID: %s\n", options.streamid.c_str());
    printf("加密: %s\n", options.passphrase.empty() ? "无" : "已启用");
    printf("延迟: %d ms\n", options.latency);
    printf("带宽限制: %d bytes/sec\n", options.maxbw);
  }
  
  printf("\n");
  
  // 示例2：listener模式
  std::string listener_url = "srt://:9999?mode=listener&streamid=input/camera1";
  srt_options listener_opt;
  
  if (parse_srt_url(listener_url, listener_opt) == 0) {
    printf("Listener配置:\n");
    printf("模式: %s\n", listener_opt.mode.c_str());
    printf("监听端口: %d\n", listener_opt.port);
    printf("流ID: %s\n", listener_opt.streamid.c_str());
  }
}

int main(){
    usage_example();
    test_parse_srt_url();
    return 0;  
}
