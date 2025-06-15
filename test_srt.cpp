#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include "srt_url_parser.h"

srt_options make_default() {
    srt_options opt;
    opt.mode = "caller";
    opt.host = "";
    opt.port = -1;
    opt.streamid = "";
    opt.passphrase = "";
    opt.pbkeylen = -1;
    opt.latency = -1;
    opt.maxbw = -1;
    opt.rcvbuf = -1;
    opt.sndbuf = -1;
    opt.ipttl = -1;
    opt.conntimeo = -1;
    return opt;
}

bool equal_opts(const srt_options &a, const srt_options &b) {
    return a.mode == b.mode && a.host == b.host && a.port == b.port &&
           a.streamid == b.streamid && a.passphrase == b.passphrase &&
           a.pbkeylen == b.pbkeylen && a.latency == b.latency &&
           a.maxbw == b.maxbw && a.rcvbuf == b.rcvbuf && a.sndbuf == b.sndbuf &&
           a.ipttl == b.ipttl && a.conntimeo == b.conntimeo;
}

struct TestCase {
    std::string url;
    int expected_result;
    srt_options expected_opt;
};

int main() {
    std::vector<TestCase> cases;

    {
        TestCase t;
        t.url = "srt://192.168.1.100:9999";
        t.expected_result = 0;
        t.expected_opt = make_default();
        t.expected_opt.host = "192.168.1.100";
        t.expected_opt.port = 9999;
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "srt://stream.example.com:1935?streamid=live/channel1";
        t.expected_result = 0;
        t.expected_opt = make_default();
        t.expected_opt.host = "stream.example.com";
        t.expected_opt.port = 1935;
        t.expected_opt.streamid = "live/channel1";
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "srt://secure.example.com:9999?passphrase=secret123&pbkeylen=16";
        t.expected_result = 0;
        t.expected_opt = make_default();
        t.expected_opt.host = "secure.example.com";
        t.expected_opt.port = 9999;
        t.expected_opt.passphrase = "secret123";
        t.expected_opt.pbkeylen = 16;
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "srt://premium.example.com:1935?mode=caller&streamid=live/premium&passphrase=ultra_secure&pbkeylen=32&latency=100&maxbw=8000000&rcvbuf=4000000&sndbuf=4000000&ipttl=64&conntimeo=5000";
        t.expected_result = 0;
        t.expected_opt = make_default();
        t.expected_opt.host = "premium.example.com";
        t.expected_opt.port = 1935;
        t.expected_opt.streamid = "live/premium";
        t.expected_opt.passphrase = "ultra_secure";
        t.expected_opt.pbkeylen = 32;
        t.expected_opt.latency = 100;
        t.expected_opt.maxbw = 8000000;
        t.expected_opt.rcvbuf = 4000000;
        t.expected_opt.sndbuf = 4000000;
        t.expected_opt.ipttl = 64;
        t.expected_opt.conntimeo = 5000;
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "srt://:9999?mode=listener&streamid=live/input";
        t.expected_result = 0;
        t.expected_opt = make_default();
        t.expected_opt.mode = "listener";
        t.expected_opt.host = "";
        t.expected_opt.port = 9999;
        t.expected_opt.streamid = "live/input";
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "srt://?mode=listener&latency=200";
        t.expected_result = 0;
        t.expected_opt = make_default();
        t.expected_opt.mode = "listener";
        t.expected_opt.latency = 200;
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "http://wrong.protocol.com:9999";
        t.expected_result = -1;
        t.expected_opt = make_default();
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "";
        t.expected_result = -1;
        t.expected_opt = make_default();
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "srt://";
        t.expected_result = -1;
        t.expected_opt = make_default();
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "srt://test.com:70000";
        t.expected_result = 0;
        t.expected_opt = make_default();
        t.expected_opt.host = "test.com";
        t.expected_opt.port = -1; // invalid port should become default
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "srt://host:1234?pbkeylen=99";
        t.expected_result = 0;
        t.expected_opt = make_default();
        t.expected_opt.host = "host";
        t.expected_opt.port = 1234;
        t.expected_opt.pbkeylen = -1; // invalid value replaced with default
        cases.push_back(t);
    }

    {
        TestCase t;
        t.url = "srt://host:1234?pbkeylen=abc";
        t.expected_result = 0;
        t.expected_opt = make_default();
        t.expected_opt.host = "host";
        t.expected_opt.port = 1234;
        t.expected_opt.pbkeylen = -1; // invalid integer
        cases.push_back(t);
    }

    for (size_t i = 0; i < cases.size(); ++i) {
        srt_options opt;
        int ret = parse_srt_url(cases[i].url, opt);
        assert(ret == cases[i].expected_result);
        assert(equal_opts(opt, cases[i].expected_opt));
    }

    std::cout << "All tests passed\n";
    return 0;
}

