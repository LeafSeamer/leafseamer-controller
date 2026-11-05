#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <array>
#include <memory>
#include <stdexcept>
#include <algorithm>

namespace content {
inline void need(bool ok, const char* code) { if (!ok) throw std::runtime_error(code); }
struct Handle {
  HANDLE value = INVALID_HANDLE_VALUE;
  explicit Handle(HANDLE h) : value(h) {}
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct PathLess {
  bool operator()(const std::wstring& a, const std::wstring& b) const {
    const int result = CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()), TRUE);
    need(result != 0, "content_path_compare"); return result == CSTR_LESS_THAN;
  }
};
struct Entry { std::wstring path; unsigned long long size; std::string digest; };
inline std::vector<std::wstring> parts(const std::wstring& value, wchar_t separator) {
  std::vector<std::wstring> result; size_t start = 0;
  for (;;) {
    const auto end = value.find(separator, start); const auto part = value.substr(start, end == std::wstring::npos ? end : end - start);
    need(!part.empty() && part != L"." && part != L".." && part.back() != L'.' && part.back() != L' ', "content_path");
    for (const wchar_t c : part) need(c >= 32 && c != 127 && std::wstring(L"<>:\"/\\|?*").find(c) == std::wstring::npos, "content_path");
    need(IsNormalizedString(NormalizationC, part.c_str(), static_cast<int>(part.size())) != 0, "content_path_normalization");
    auto base = part.substr(0, part.find(L'.'));
    for (auto& c : base) if (c >= L'a' && c <= L'z') c -= L'a' - L'A';
    need(base != L"CON" && base != L"PRN" && base != L"AUX" && base != L"NUL" && base != L"CONIN$" && base != L"CONOUT$" &&
      !(base.size() == 4 && (base.substr(0, 3) == L"COM" || base.substr(0, 3) == L"LPT") &&
        ((base[3] >= L'1' && base[3] <= L'9') || base[3] == L'\u00b9' || base[3] == L'\u00b2' || base[3] == L'\u00b3')), "content_path_reserved");
    result.push_back(part); if (end == std::wstring::npos) return result; start = end + 1;
  }
}
inline std::wstring identity(HANDLE handle) {
  FILE_ID_INFO info{}; need(GetFileInformationByHandleEx(handle, FileIdInfo, &info, sizeof(info)) != 0, "content_identity");
  wchar_t volume[17]; swprintf_s(volume, L"%016llx", info.VolumeSerialNumber); std::wstring out(volume); const wchar_t* hex = L"0123456789abcdef";
  for (const auto byte : info.FileId.Identifier) { out += hex[byte >> 4]; out += hex[byte & 15]; } return out;
}
inline std::wstring volumePath(HANDLE handle) {
  const DWORD size = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
  need(size > 0 && size <= 32768, "content_volume_path"); std::vector<wchar_t> buffer(size);
  const DWORD written = GetFinalPathNameByHandleW(handle, buffer.data(), size, FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
  need(written > 0 && written < size, "content_volume_path"); return std::wstring(buffer.data(), written);
}
inline FILE_STANDARD_INFO inspect(HANDLE handle, bool directory) {
  FILE_ATTRIBUTE_TAG_INFO attributes{}; FILE_STANDARD_INFO standard{};
  need(GetFileType(handle) == FILE_TYPE_DISK && GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
    GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)), "content_attributes");
  need((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 && !standard.DeletePending && (standard.Directory != FALSE) == directory, "content_file_type");
  if (!directory) need(standard.NumberOfLinks == 1, "content_hardlink"); return standard;
}
class Pin {
  std::map<std::wstring, std::unique_ptr<Handle>, PathLess> directories;
  struct File { Entry entry; std::unique_ptr<Handle> handle; std::wstring identity; };
  std::vector<File> files;
  std::map<std::wstring, bool, PathLess> expected;
  bool closed = false;
  ULONGLONG deadline;
  void within() const { need(GetTickCount64() < deadline, "content_timeout"); }
  void directory(const std::wstring& path) {
    if (directories.count(path)) return; within();
    auto handle = std::make_unique<Handle>(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    need(handle->value != INVALID_HANDLE_VALUE, "content_directory_open"); inspect(handle->value, true); directories.emplace(path, std::move(handle));
  }
  std::string hash(HANDLE file) {
    LARGE_INTEGER zero{}; need(SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) != 0, "content_read");
    BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE state = nullptr;
    need(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "content_crypto");
    try {
      need(BCryptCreateHash(algorithm, &state, nullptr, 0, nullptr, 0, 0) == 0, "content_crypto");
      std::array<unsigned char, 65536> buffer{}; DWORD count = 0;
      for (;;) { within(); need(ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr) != 0, "content_read");
        if (!count) break; need(BCryptHashData(state, buffer.data(), count, 0) == 0, "content_crypto"); }
      std::array<unsigned char, 32> digest{}; need(BCryptFinishHash(state, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0, "content_crypto");
      BCryptDestroyHash(state); state = nullptr; BCryptCloseAlgorithmProvider(algorithm, 0); algorithm = nullptr;
      const char* hex = "0123456789abcdef"; std::string out = "sha256:";
      for (const auto byte : digest) { out += hex[byte >> 4]; out += hex[byte & 15]; } return out;
    } catch (...) { if (state) BCryptDestroyHash(state); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); throw; }
  }
  void tree(const std::wstring& relative, std::set<std::wstring, PathLess>& found) {
    within(); const auto path = root + (relative.empty() ? L"" : L"\\" + relative);
    WIN32_FIND_DATAW data{}; const HANDLE search = FindFirstFileW((path + L"\\*").c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) { need(GetLastError() == ERROR_FILE_NOT_FOUND, "content_enumeration"); return; }
    try {
      for (;;) {
        within(); const std::wstring name(data.cFileName);
        if (name != L"." && name != L"..") {
          const auto child = relative.empty() ? name : relative + L"\\" + name; const bool isDirectory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
          const auto item = expected.find(child);
          need(item != expected.end() && item->second == isDirectory && (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 && found.insert(child).second, "content_inventory_mismatch");
          if (isDirectory) tree(child, found);
        }
        if (!FindNextFileW(search, &data)) { need(GetLastError() == ERROR_NO_MORE_FILES, "content_enumeration"); break; }
      }
      FindClose(search);
    } catch (...) { FindClose(search); throw; }
  }
  void streams(const std::wstring& path, bool directory = false) {
    within(); WIN32_FIND_STREAM_DATA data{};
    const HANDLE search = FindFirstStreamW(path.c_str(), FindStreamInfoStandard, &data, 0);
    if (search == INVALID_HANDLE_VALUE) { need(directory && GetLastError() == ERROR_HANDLE_EOF, "content_streams"); return; }
    try {
      need(!directory && std::wstring(data.cStreamName) == L"::$DATA", "content_alternate_stream");
      need(!FindNextStreamW(search, &data), "content_alternate_stream");
      need(GetLastError() == ERROR_HANDLE_EOF, "content_streams"); FindClose(search);
    } catch (...) { FindClose(search); throw; }
  }
  void inspectPinned() {
    for (const auto& item : directories) { within(); inspect(item.second->value, true); }
    streams(root, true);
    for (const auto& item : expected) if (item.second) streams(root + L"\\" + item.first, true);
    for (const auto& file : files) {
      within(); const auto info = inspect(file.handle->value, false);
      need(info.EndOfFile.QuadPart >= 0 && static_cast<unsigned long long>(info.EndOfFile.QuadPart) == file.entry.size && identity(file.handle->value) == file.identity, "content_pin_changed");
      auto relative = file.entry.path; std::replace(relative.begin(), relative.end(), L'/', L'\\'); streams(root + L"\\" + relative);
    }
    std::set<std::wstring, PathLess> found; tree(L"", found); need(found.size() == expected.size(), "content_inventory_mismatch"); within();
  }
public:
  std::wstring root, rootIdentity;
  Pin(std::wstring path, const std::vector<Entry>& entries, unsigned long timeoutMs) : deadline(GetTickCount64() + timeoutMs) {
    need(timeoutMs > 0 && timeoutMs <= 5000 && !entries.empty() && entries.size() <= 65536, "content_capacity");
    if (path.rfind(L"\\\\?\\", 0) == 0) path.erase(0, 4);
    need(path.size() > 3 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) && path[1] == L':' && path[2] == L'\\', "content_root_path");
    std::wstring current = L"\\\\?\\" + path.substr(0, 3);
    need(GetDriveTypeW(path.substr(0, 3).c_str()) == DRIVE_FIXED, "content_local_volume"); directory(current);
    for (const auto& part : parts(path.substr(3), L'\\')) { if (current.back() != L'\\') current += L'\\'; current += part; directory(current); }
    const HANDLE rootHandle = directories.at(current)->value;
    rootIdentity = identity(rootHandle); root = volumePath(rootHandle);
    unsigned long long total = 0; std::set<std::wstring> identities;
    for (const auto& entry : entries) {
      within(); need(entry.path.size() <= 240 && entry.size <= 268435456ULL && total <= 1073741824ULL - entry.size, "content_capacity"); total += entry.size;
      auto portable = entry.path; for (auto& c : portable) if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
      need(entry.path.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-/") == std::wstring::npos &&
        portable != L"extension.json" && portable != L"files.json", "content_portable_path");
      need(entry.digest.size() == 71 && entry.digest.substr(0, 7) == "sha256:" && entry.digest.find_first_not_of("0123456789abcdef", 7) == std::string::npos, "content_digest");
      const auto segments = parts(entry.path, L'/'); std::wstring relative;
      for (size_t i = 0; i < segments.size(); ++i) {
        if (i) relative += L'\\'; relative += segments[i]; const bool isDirectory = i + 1 < segments.size();
        const auto previous = expected.find(relative);
        need(previous == expected.end() || (previous->second && isDirectory), "content_path_collision"); expected[relative] = isDirectory;
        if (isDirectory) directory(root + L"\\" + relative);
      }
      auto handle = std::make_unique<Handle>(CreateFileW((root + L"\\" + relative).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
      need(handle->value != INVALID_HANDLE_VALUE, "content_file_open"); const auto info = inspect(handle->value, false);
      need(info.EndOfFile.QuadPart >= 0 && static_cast<unsigned long long>(info.EndOfFile.QuadPart) == entry.size, "content_size_mismatch");
      const auto fileIdentity = identity(handle->value); need(identities.insert(fileIdentity).second, "content_alias");
      need(hash(handle->value) == entry.digest, "content_digest_mismatch"); files.push_back({entry, std::move(handle), fileIdentity});
    }
    inspectPinned();
  }
  void check(unsigned long timeoutMs) {
    need(!closed && timeoutMs > 0 && timeoutMs <= 5000, "content_pin_closed"); deadline = GetTickCount64() + timeoutMs;
    try { inspectPinned(); } catch (...) { close(); throw; }
  }
  void close() { closed = true; files.clear(); directories.clear(); }
};
}
