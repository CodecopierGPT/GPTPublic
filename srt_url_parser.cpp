#include <sstream>
#include <algorithm>
#include <cctype>

// ===========================================
// 内部辅助类：SRT URL解析器
// ===========================================
class SrtUrlParserHelper {
public:
  SrtUrlParserHelper() = default;
  ~SrtUrlParserHelper() = default;
  
  // 解析URL并填充选项结构体
  int parse(const std::string& srt_url, srt_options& opt) {
    // 1. 初始化默认值
    init_default_options(opt);
    
    // 2. 验证URL格式
    if (!validate_url_format(srt_url)) {
      return -1;
    }
    
    // 3. 分离URL各部分
    std::string main_part, param_part;
    if (!split_url_parts(srt_url, main_part, param_part)) {
      return -1;
    }
    
    // 4. 解析主体部分(host:port)
    if (!parse_main_part(main_part, opt)) {
      return -1;
    }
    
    // 5. 解析参数部分
    if (!param_part.empty()) {
      if (!parse_parameters(param_part, opt)) {
        return -1;
      }
    }
    
    // 6. 后处理验证
    return post_process_validation(opt);
  }

private:
  // 初始化默认值
  void init_default_options(srt_options& opt) {
    opt.mode = "caller";        // 默认caller模式
    opt.host = "";              // 默认空主机
    opt.port = -1;              // 默认端口
    opt.streamid = "";          // 默认空流ID
    opt.passphrase = "";        // 默认无加密
    opt.pbkeylen = -1;          // 默认密钥长度
    opt.latency = -1;           // 默认延迟
    opt.maxbw = -1;             // 默认无带宽限制
    opt.rcvbuf = -1;            // 默认接收缓冲区
    opt.sndbuf = -1;            // 默认发送缓冲区
    opt.ipttl = -1;             // 默认IP TTL
    opt.conntimeo = -1;         // 默认连接超时
  }
  
  // 验证URL格式
  bool validate_url_format(const std::string& url) {
    if (url.empty()) {
      return false;
    }
    
    // 检查是否以srt://开头
    const std::string srt_prefix = "srt://";
    if (url.find(srt_prefix) != 0) {
      return false;
    }
    
    // 基本长度检查
    if (url.length() <= srt_prefix.length()) {
      return false;
    }
    
    return true;
  }
  
  // 分离URL的主体部分和参数部分
  bool split_url_parts(const std::string& url, std::string& main_part, std::string& param_part) {
    // 移除srt://前缀
    const std::string srt_prefix = "srt://";
    std::string url_body = url.substr(srt_prefix.length());
    
    // 查找参数分隔符?
    size_t question_pos = url_body.find('?');
    if (question_pos != std::string::npos) {
      main_part = url_body.substr(0, question_pos);
      param_part = url_body.substr(question_pos + 1);
    } else {
      main_part = url_body;
      param_part = "";
    }
    
    return true;
  }
  
  // 解析主体部分(host:port)
  bool parse_main_part(const std::string& main_part, srt_options& opt) {
    if (main_part.empty()) {
      // 空主体，可能是listener模式
      opt.host = "";
      opt.port = -1;
      return true;
    }
    
    // 查找端口分隔符:
    size_t colon_pos = main_part.find(':');
    if (colon_pos != std::string::npos) {
      // 有端口号
      opt.host = main_part.substr(0, colon_pos);
      std::string port_str = main_part.substr(colon_pos + 1);
      
      if (!port_str.empty()) {
        opt.port = string_to_int(port_str, -1);
        if (opt.port <= 0 || opt.port > 65535) {
          // 端口号无效，使用默认值
          opt.port = -1;
        }
      }
    } else {
      // 没有端口号，只有主机
      opt.host = main_part;
      opt.port = -1;
    }
    
    return true;
  }
  
  // 解析参数部分
  bool parse_parameters(const std::string& param_part, srt_options& opt) {
    std::vector<std::string> param_pairs = split_string(param_part, '&');
    
    for (const auto& pair : param_pairs) {
      if (pair.empty()) continue;
      
      std::string key, value;
      if (!parse_key_value_pair(pair, key, value)) {
        continue;  // 跳过无效的参数对
      }
      
      // 根据key设置对应的选项值
      apply_parameter(key, value, opt);
    }
    
    return true;
  }
  
  // 解析键值对
  bool parse_key_value_pair(const std::string& pair, std::string& key, std::string& value) {
    size_t equal_pos = pair.find('=');
    if (equal_pos == std::string::npos) {
      // 没有=号，整个作为key，value为空
      key = trim_string(pair);
      value = "";
    } else {
      key = trim_string(pair.substr(0, equal_pos));
      value = trim_string(pair.substr(equal_pos + 1));
    }
    
    return !key.empty();
  }
  
  // 应用参数到选项结构体
  void apply_parameter(const std::string& key, const std::string& value, srt_options& opt) {
    if (key == "mode") {
      if (!value.empty()) {
        opt.mode = value;
      }
    } else if (key == "streamid") {
      opt.streamid = value;  // 允许空值
    } else if (key == "passphrase") {
      opt.passphrase = value;  // 允许空值
    } else if (key == "pbkeylen") {
      opt.pbkeylen = string_to_int(value, -1);
    } else if (key == "latency") {
      opt.latency = string_to_int(value, -1);
    } else if (key == "maxbw") {
      opt.maxbw = string_to_int(value, -1);
    } else if (key == "rcvbuf") {
      opt.rcvbuf = string_to_int(value, -1);
    } else if (key == "sndbuf") {
      opt.sndbuf = string_to_int(value, -1);
    } else if (key == "ipttl") {
      opt.ipttl = string_to_int(value, -1);
    } else if (key == "conntimeo") {
      opt.conntimeo = string_to_int(value, -1);
    }
    // 忽略未知参数
  }
  
  // 后处理验证和调整
  int post_process_validation(srt_options& opt) {
    // 如果是listener模式，清空host
    if (opt.mode == "listener") {
      opt.host = "";
    }
    
    // 验证pbkeylen值
    if (opt.pbkeylen != -1 && opt.pbkeylen != 16 && opt.pbkeylen != 24 && opt.pbkeylen != 32) {
      opt.pbkeylen = -1;  // 无效值，使用默认
    }
    
    // 验证latency范围
    if (opt.latency != -1 && (opt.latency < 20 || opt.latency > 8000)) {
      // 延迟超出合理范围，但不强制修改，由用户决定
    }
    
    // 验证端口范围
    if (opt.port != -1 && (opt.port <= 0 || opt.port > 65535)) {
      opt.port = -1;  // 无效端口，使用默认
    }
    
    return 0;  // 成功
  }
  
  // 辅助函数：字符串分割
  std::vector<std::string> split_string(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    
    while (std::getline(ss, item, delimiter)) {
      result.push_back(item);
    }
    
    return result;
  }
  
  // 辅助函数：字符串转整数
  int string_to_int(const std::string& str, int default_value) {
    if (str.empty()) {
      return default_value;
    }
    
    try {
      return std::stoi(str);
    } catch (const std::exception& e) {
      return default_value;
    }
  }
  
  // 辅助函数：去除字符串首尾空格
  std::string trim_string(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
      return "";
    }
    
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
  }
};

// ===========================================
// 主函数实现
// ===========================================
int parse_srt_url(const std::string& srt_url, srt_options& opt) {
  SrtUrlParserHelper parser;
  return parser.parse(srt_url, opt);
}
