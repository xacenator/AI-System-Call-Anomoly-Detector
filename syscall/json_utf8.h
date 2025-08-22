#pragma once
#include <string>
#include <vector>
#include <windows.h>

inline std::string utf16_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int len = ::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string out; out.resize(len);
    // Use &out[0] instead of out.data() to get a non-const char* for LPSTR
    ::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &out[0], len, nullptr, nullptr);
    return out;
}

inline void json_escape_append(std::string& out, const std::string& s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
        case '\"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                char buf[7]; // \u00XX
                sprintf_s(buf, "\\u%04X", (unsigned)c);
                out += buf;
            }
            else {
                out.push_back((char)c);
            }
        }
    }
    out.push_back('"');
}

inline void json_escape_append(std::string& out, const std::wstring& ws) {
    std::string u8 = utf16_to_utf8(ws);
    json_escape_append(out, u8);
}

inline std::string json_escape(const std::wstring& ws) { std::string o; json_escape_append(o, ws); return o; }
inline std::string json_escape(const std::string& s) { std::string o; json_escape_append(o, s); return o; }
