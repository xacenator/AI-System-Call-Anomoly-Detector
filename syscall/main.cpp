// ----- main.cpp -----
// Build: x64, C++17, Unicode. Run as Administrator.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <ws2tcpip.h>          // for InetNtopA
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Tdh.lib")

#include <krabs.hpp>           // or <krabs/krabs.hpp> depending on your layout
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>

#include "json_utf8.h"

// ===== Tunables =====
static const bool   FILTER_OUT_OPERATION_END = true;
static const bool   ONLY_INTERESTING_FILEIO = true;    // keep Write / Rename / SetInfo
static const size_t FILEIO_SAMPLE_EVERY_N = 1;       // set to 5/10 to sample FileIo
static const bool   DEDUP_BURSTS = true;    // collapse near-duplicate bursts
static const int    DEDUP_WINDOW_MS = 150;
// ====================

static std::mutex g_out_mu;
static std::atomic<bool> g_running{ true };

static BOOL WINAPI on_ctrl(DWORD c) {
    if (c == CTRL_C_EVENT || c == CTRL_BREAK_EVENT || c == CTRL_CLOSE_EVENT) {
        g_running = false; return TRUE;
    }
    return FALSE;
}

static std::string now_iso8601_utc() {
    using namespace std::chrono;
    auto tp = system_clock::now();
    auto tt = system_clock::to_time_t(tp);
    std::tm tm_utc{};
    gmtime_s(&tm_utc, &tt);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    return std::string(buf);
}

template<typename T>
static bool try_parse(krabs::parser& p, const wchar_t* name, T& out) {
    try { out = p.parse<T>(name); return true; }
    catch (...) { return false; }
}

static void json_kv(std::string& out, const char* key, const std::string& s) {
    out.push_back('"'); out += key; out += "\":";
    json_escape_append(out, s); out.push_back(',');
}
static void json_kv(std::string& out, const char* key, const std::wstring& ws) {
    out.push_back('"'); out += key; out += "\":";
    json_escape_append(out, ws); out.push_back(',');
}
template<typename Num>
static void json_kv(std::string& out, const char* key, Num v) {
    out.push_back('"'); out += key; out += "\":";
    out += std::to_string(v); out.push_back(',');
}

static void emit_json(std::string j) {
    if (!j.empty() && j.back() == ',') j.pop_back();
    j.push_back('}');
    std::lock_guard<std::mutex> lk(g_out_mu);
    std::cout << j << "\n";
    std::cout.flush();
}

// Helpers
static bool sane_w(const std::wstring& s) {
    if (s.empty()) return false;
    for (wchar_t c : s) if (c < 0x20) return false;
    return true;
}

static std::string ipv4_to_string(uint32_t v) {
    IN_ADDR a; a.S_un.S_addr = v; // ETW usually provides network byte order
    char buf[INET_ADDRSTRLEN] = { 0 };
    if (InetNtopA(AF_INET, &a, buf, sizeof(buf))) return std::string(buf);
    return {};
}

struct Key {
    uint32_t pid; uint32_t tid; uint32_t code;
    bool operator==(const Key& o) const noexcept {
        return pid == o.pid && tid == o.tid && code == o.code;
    }
};
struct KeyHash {
    size_t operator()(const Key& k) const noexcept {
        return (size_t)k.pid * 1315423911u ^ ((size_t)k.tid << 1) ^ k.code;
    }
};
static std::unordered_map<Key, uint64_t, KeyHash> g_seen;
static std::mutex g_seen_mu;

static uint64_t ms_now() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
static uint32_t fast_hash(const std::wstring& a, const std::wstring& b = L"", uint32_t extra = 0) {
    uint32_t h = 2166136261u;
    auto mix = [&](const std::wstring& s) { for (wchar_t c : s) { h ^= (uint32_t)(c & 0xFFFF); h *= 16777619u; } };
    mix(a); mix(b); h ^= extra; h *= 16777619u; return h;
}

int wmain() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(on_ctrl, TRUE);

    try {
        krabs::kernel_trace trace(L"ptd-kernel-trace");

        krabs::kernel::process_provider        proc;
        krabs::kernel::file_io_provider        fileio;
        krabs::kernel::network_tcpip_provider  net;   // key: TcpIp events

        std::atomic<size_t> fileio_counter{ 0 };

        auto callback = [&](const EVENT_RECORD& rec, const krabs::trace_context& ctx) {
            try {
                krabs::schema schema(rec, ctx.schema_locator);
                krabs::parser parser(schema);

                // Always use ETW header for IDs
                uint32_t pid = rec.EventHeader.ProcessId;
                uint32_t tid = rec.EventHeader.ThreadId;

                const std::wstring task = schema.task_name();    // "Process","FileIo","TcpIp","UdpIp"
                const std::wstring opcode = schema.opcode_name();  // "Start","Write","Connect","SendIPV4",...

                if (FILTER_OUT_OPERATION_END && opcode == L"OperationEnd") return;
                if (pid == 0 || pid == 4) return; // Idle/System noise

                if (task == L"FileIo" && ONLY_INTERESTING_FILEIO) {
                    if (!(opcode == L"Write" || opcode == L"Rename" || opcode == L"SetInfo"))
                        return;
                    size_t c = ++fileio_counter;
                    if (FILEIO_SAMPLE_EVERY_N > 1 && (c % FILEIO_SAMPLE_EVERY_N) != 0) return;
                }

                // Build dedup key using salient fields
                uint32_t code_hash = 0;
                std::wstring fname, saddr_w, daddr_w;
                uint32_t s4 = 0, d4 = 0, sport = 0, dport = 0;

                if (task == L"FileIo") {
                    try_parse(parser, L"FileName", fname);
                    code_hash = fast_hash(task + L":" + opcode, fname);
                }
                else if (task == L"TcpIp" || task == L"UdpIp") {
                    // Prefer numeric IPv4 if present
                    try_parse(parser, L"saddr", s4);  try_parse(parser, L"SourceIp", s4);
                    try_parse(parser, L"daddr", d4);  try_parse(parser, L"DestIp", d4);
                    try_parse(parser, L"sport", sport); try_parse(parser, L"SourcePort", sport);
                    try_parse(parser, L"dport", dport); try_parse(parser, L"DestPort", dport);
                    code_hash = fast_hash(task + L":" + opcode, L"", (sport << 16) ^ dport);
                }
                else {
                    code_hash = fast_hash(task + L":" + opcode);
                }

                if (DEDUP_BURSTS) {
                    Key k{ pid, tid, code_hash };
                    uint64_t now = ms_now();
                    std::lock_guard<std::mutex> lk(g_seen_mu);
                    auto it = g_seen.find(k);
                    if (it != g_seen.end() && (now - it->second) < (uint64_t)DEDUP_WINDOW_MS) return;
                    g_seen[k] = now;
                    if (g_seen.size() > 4096) g_seen.clear();
                }

                // Emit JSON
                std::string j = "{";
                json_kv(j, "ts", now_iso8601_utc());
                json_kv(j, "pid", pid);
                json_kv(j, "tid", tid);
                json_kv(j, "prov", utf16_to_utf8(schema.provider_name()));
                json_kv(j, "task", utf16_to_utf8(task));
                json_kv(j, "opcode", utf16_to_utf8(opcode));

                std::wstring w; uint64_t u64 = 0;

                if (task == L"Process") {
                    std::wstring img;
                    if (try_parse(parser, L"ImageName", img) && sane_w(img)) {
                        json_kv(j, "ImageName", img);
                    }
                    else if (try_parse(parser, L"ImageFileName", img) && sane_w(img)) {
                        json_kv(j, "ImageName", img);
                    }
                    std::wstring cmd;
                    if (try_parse(parser, L"CommandLine", cmd) && !cmd.empty()) {
                        if (cmd.size() > 512) cmd.resize(512);
                        json_kv(j, "CommandLine", cmd);
                    }
                }
                else if (task == L"FileIo") {
                    if (!fname.empty()) json_kv(j, "FileName", fname);
                    if (try_parse(parser, L"IoSize", u64))        json_kv(j, "IoSize", (long long)u64);
                    if (try_parse(parser, L"TransferSize", u64)) json_kv(j, "TransferSize", (long long)u64);
                }
                else if (task == L"TcpIp" || task == L"UdpIp") {
                    std::string s_ip, d_ip;
                    if (s4) s_ip = ipv4_to_string(s4);
                    if (d4) d_ip = ipv4_to_string(d4);
                    // Fallback to string fields if numeric missing (some builds)
                    if (s_ip.empty() && (try_parse(parser, L"saddr", saddr_w) || try_parse(parser, L"SourceIp", saddr_w)))
                        s_ip = utf16_to_utf8(saddr_w);
                    if (d_ip.empty() && (try_parse(parser, L"daddr", daddr_w) || try_parse(parser, L"DestIp", daddr_w)))
                        d_ip = utf16_to_utf8(daddr_w);

                    if (!s_ip.empty()) json_kv(j, "saddr", s_ip);
                    if (!d_ip.empty()) json_kv(j, "daddr", d_ip);
                    if (sport) json_kv(j, "sport", sport);
                    if (dport) json_kv(j, "dport", dport);
                }

                emit_json(j);
            }
            catch (...) {
                // ignore per-event parse failures
            }
            };

        // Wire providers
        proc.add_on_event_callback(callback);
        fileio.add_on_event_callback(callback);
        net.add_on_event_callback(callback);

        trace.enable(proc);
        trace.enable(fileio);
        trace.enable(net);

        // Start (blocking; Ctrl+C to stop)
        try {
            trace.start();
        }
        catch (const std::exception& e) {
            std::cerr << "[start failed] " << e.what() << "\n";
            return 2;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << "\n";
        return 1;
    }
    return 0;
}
