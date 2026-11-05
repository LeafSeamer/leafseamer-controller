#include <node_api.h>
#include "content-root.h"
#include <cmath>

namespace {
constexpr napi_type_tag pinTag{0x930d96223f8f4861ULL, 0xa8447ea916fa8c29ULL};
void ok(napi_status status) { content::need(status == napi_ok, "content_argument"); }
napi_value property(napi_env env, napi_value value, const char* key) {
  napi_value result; ok(napi_get_named_property(env, value, key, &result)); return result;
}
std::wstring string(napi_env env, napi_value value, size_t max) {
  size_t length = 0; ok(napi_get_value_string_utf16(env, value, nullptr, 0, &length));
  content::need(length > 0 && length <= max, "content_argument");
  std::vector<char16_t> buffer(length + 1); size_t written = 0;
  ok(napi_get_value_string_utf16(env, value, buffer.data(), buffer.size(), &written));
  content::need(written == length && std::find(buffer.begin(), buffer.begin() + length, u'\0') == buffer.begin() + length, "content_argument");
  return std::wstring(buffer.begin(), buffer.begin() + length);
}
unsigned long timeout(napi_env env, napi_value value) {
  double number = 0; ok(napi_get_value_double(env, value, &number));
  content::need(std::isfinite(number) && number >= 1 && number <= 5000 && number == std::floor(number), "content_timeout_argument");
  return static_cast<unsigned long>(number);
}
std::vector<napi_value> arguments(napi_env env, napi_callback_info info, size_t expected) {
  size_t count = expected + 1; std::vector<napi_value> result(count);
  ok(napi_get_cb_info(env, info, &count, result.data(), nullptr, nullptr));
  content::need(count == expected, "content_argument"); return result;
}
content::Pin* pin(napi_env env, napi_value value) {
  bool tagged = false; ok(napi_check_object_type_tag(env, value, &pinTag, &tagged));
  content::need(tagged, "content_pin_token"); void* pointer = nullptr; ok(napi_unwrap(env, value, &pointer));
  content::need(pointer != nullptr, "content_pin_token"); return static_cast<content::Pin*>(pointer);
}
napi_value fail(napi_env env, const std::exception& error) {
  bool pending = false; napi_is_exception_pending(env, &pending);
  if (!pending) napi_throw_error(env, error.what(), error.what()); return nullptr;
}
napi_value nothing(napi_env env) { napi_value value; ok(napi_get_undefined(env, &value)); return value; }
void finalize(napi_env, void* pointer, void*) { delete static_cast<content::Pin*>(pointer); }
napi_value open(napi_env env, napi_callback_info info) {
  try {
    const auto args = arguments(env, info, 3); const auto root = string(env, args[0], 32760); const auto budget = timeout(env, args[2]);
    bool array = false; ok(napi_is_array(env, args[1], &array)); content::need(array, "content_argument");
    uint32_t count = 0; ok(napi_get_array_length(env, args[1], &count)); content::need(count > 0 && count <= 65536, "content_capacity");
    std::vector<content::Entry> entries; entries.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
      napi_value item; ok(napi_get_element(env, args[1], i, &item));
      const auto path = string(env, property(env, item, "path"), 240);
      const auto rawSize = string(env, property(env, item, "size_bytes"), 20);
      content::need(rawSize.find_first_not_of(L"0123456789") == std::wstring::npos && (rawSize.size() == 1 || rawSize[0] != L'0'), "content_size");
      unsigned long long size = 0;
      for (const auto c : rawSize) { size = size * 10 + (c - L'0'); content::need(size <= 268435456ULL, "content_capacity"); }
      const auto rawDigest = string(env, property(env, item, "digest"), 71);
      content::need(rawDigest.find_first_not_of(L"sha256:0123456789abcdef") == std::wstring::npos, "content_digest");
      std::string digest; for (const auto c : rawDigest) digest += static_cast<char>(c);
      entries.push_back({path, size, digest});
    }
    auto owned = std::make_unique<content::Pin>(root, entries, budget); napi_value token; ok(napi_create_object(env, &token));
    ok(napi_type_tag_object(env, token, &pinTag)); ok(napi_wrap(env, token, owned.get(), finalize, nullptr, nullptr));
    owned.release(); ok(napi_object_freeze(env, token)); return token;
  } catch (const std::exception& error) { return fail(env, error); }
}
napi_value check(napi_env env, napi_callback_info info) {
  try { const auto args = arguments(env, info, 2); pin(env, args[0])->check(timeout(env, args[1])); return nothing(env); }
  catch (const std::exception& error) { return fail(env, error); }
}
napi_value close(napi_env env, napi_callback_info info) {
  try { const auto args = arguments(env, info, 1); pin(env, args[0])->close(); return nothing(env); }
  catch (const std::exception& error) { return fail(env, error); }
}
napi_value describe(napi_env env, napi_callback_info info) {
  try {
    const auto args = arguments(env, info, 1); const auto value = pin(env, args[0]); napi_value result; ok(napi_create_object(env, &result));
    for (const auto& field : std::vector<std::pair<const char*, std::wstring>>{{"root", value->root}, {"rootIdentity", value->rootIdentity}}) {
      napi_value text; ok(napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(field.second.c_str()), field.second.size(), &text));
      ok(napi_set_named_property(env, result, field.first, text));
    }
    ok(napi_object_freeze(env, result)); return result;
  } catch (const std::exception& error) { return fail(env, error); }
}
napi_value init(napi_env env, napi_value exports) {
  const napi_property_descriptor methods[] = {
    {"pin", nullptr, open, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"verify", nullptr, check, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"close", nullptr, close, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"describe", nullptr, describe, nullptr, nullptr, nullptr, napi_default, nullptr}
  };
  if (napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok) return nullptr;
  return exports;
}
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
