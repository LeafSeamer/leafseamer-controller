#include <node_api.h>
#include <atomic>
#include <cstdint>
#include <string>
#ifdef _WIN32
#include <windows.h>
#include <powrprof.h>
#else
#include <time.h>
#include <sys/stat.h>
#endif

namespace {
struct State {
#ifdef _WIN32
  std::atomic<uint64_t> power_generation{0};
  HPOWERNOTIFY notification = nullptr;
  bool notifications_available = false;
#endif
};
bool ok(napi_env env, napi_status status) {
  if (status == napi_ok) return true;
  napi_throw_error(env, "native_clock_api", "native_clock_api");
  return false;
}
bool text(napi_env env, napi_value object, const char* name, const std::string& value) {
  napi_value field;
  return ok(env, napi_create_string_utf8(env, value.c_str(), value.size(), &field)) &&
    ok(env, napi_set_named_property(env, object, name, field));
}
bool number(napi_env env, napi_value object, const char* name, uint64_t value) {
  return text(env, object, name, std::to_string(value));
}
napi_value fail(napi_env env, const char* code) {
  napi_throw_error(env, code, code); return nullptr;
}
#ifdef _WIN32
ULONG CALLBACK power_event(PVOID context, ULONG type, PVOID) {
  if (type == PBT_APMSUSPEND || type == PBT_APMRESUMESUSPEND || type == PBT_APMRESUMEAUTOMATIC)
    static_cast<State*>(context)->power_generation.fetch_add(1, std::memory_order_relaxed);
  return ERROR_SUCCESS;
}
#else
bool ns(std::string& value) {
  struct stat info{};
  if (stat("/proc/self/ns/time", &info) != 0) return false;
  value = std::to_string(static_cast<uint64_t>(info.st_dev)) + ":" + std::to_string(static_cast<uint64_t>(info.st_ino));
  return true;
}
bool valid(const timespec& value) { return value.tv_sec >= 0 && value.tv_nsec >= 0 && value.tv_nsec < 1000000000; }
#endif
void finalize(napi_env, void* data, void*) {
  auto* state = static_cast<State*>(data);
#ifdef _WIN32
  if (state->notification) PowerUnregisterSuspendResumeNotification(state->notification);
#endif
  delete state;
}
napi_value capture(napi_env env, napi_callback_info) {
  napi_value result;
  if (!ok(env, napi_create_object(env, &result))) return nullptr;
  if (!text(env, result, "format", "leafseamer-native-clock/1")) return nullptr;
#ifdef _WIN32
  void* data = nullptr;
  if (!ok(env, napi_get_instance_data(env, &data))) return nullptr;
  auto* state = static_cast<State*>(data);
  const auto before_generation = state->power_generation.load(std::memory_order_relaxed);
  ULONGLONG before = 0, after = 0;
  FILETIME wall{};
  QueryInterruptTimePrecise(&before);
  GetSystemTimePreciseAsFileTime(&wall);
  QueryInterruptTimePrecise(&after);
  const auto after_generation = state->power_generation.load(std::memory_order_relaxed);
  const uint64_t filetime = (static_cast<uint64_t>(wall.dwHighDateTime) << 32) | wall.dwLowDateTime;
  if (!text(env, result, "platform", "win32") || !number(env, result, "before_100ns", before) ||
      !number(env, result, "wall_filetime_100ns", filetime) || !number(env, result, "after_100ns", after) ||
      !number(env, result, "continuity_before", before_generation) || !number(env, result, "continuity_after", after_generation) ||
      !text(env, result, "continuity_monitor", state->notifications_available ? "power_notifications" : "unavailable")) return nullptr;
#else
  std::string namespace_before, namespace_after;
  if (!ns(namespace_before)) return fail(env, "native_clock_namespace");
  timespec before{}, wall{}, after{};
  if (clock_gettime(CLOCK_BOOTTIME, &before) != 0 || clock_gettime(CLOCK_REALTIME, &wall) != 0 ||
      clock_gettime(CLOCK_BOOTTIME, &after) != 0 || !valid(before) || !valid(wall) || !valid(after)) return fail(env, "native_clock_read");
  if (!ns(namespace_after)) return fail(env, "native_clock_namespace");
  if (!text(env, result, "platform", "linux") || !number(env, result, "before_sec", static_cast<uint64_t>(before.tv_sec)) ||
      !number(env, result, "before_nsec", static_cast<uint64_t>(before.tv_nsec)) ||
      !number(env, result, "wall_sec", static_cast<uint64_t>(wall.tv_sec)) || !number(env, result, "wall_nsec", static_cast<uint64_t>(wall.tv_nsec)) ||
      !number(env, result, "after_sec", static_cast<uint64_t>(after.tv_sec)) || !number(env, result, "after_nsec", static_cast<uint64_t>(after.tv_nsec)) ||
      !text(env, result, "namespace_before", namespace_before) || !text(env, result, "namespace_after", namespace_after) ||
      !text(env, result, "continuity_monitor", "unavailable")) return nullptr;
#endif
  return result;
}
napi_value tick(napi_env env, napi_callback_info) {
  napi_value result;
#ifdef _WIN32
  ULONGLONG value = 0; QueryInterruptTimePrecise(&value);
  if (value > UINT64_MAX / 100) return fail(env, "native_clock_overflow");
  const uint64_t nanoseconds = value * 100;
#else
  timespec value{};
  if (clock_gettime(CLOCK_BOOTTIME, &value) != 0 || !valid(value) ||
      static_cast<uint64_t>(value.tv_sec) > (UINT64_MAX - static_cast<uint64_t>(value.tv_nsec)) / 1000000000)
    return fail(env, "native_clock_read");
  const uint64_t nanoseconds = static_cast<uint64_t>(value.tv_sec) * 1000000000 + static_cast<uint64_t>(value.tv_nsec);
#endif
  const auto value_string = std::to_string(nanoseconds);
  if (!ok(env, napi_create_string_utf8(env, value_string.c_str(), value_string.size(), &result))) return nullptr;
  return result;
}
napi_value initialize(napi_env env, napi_value exports) {
  auto* state = new State();
#ifdef _WIN32
  DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS subscriber{};
  subscriber.Callback = power_event; subscriber.Context = state;
  state->notifications_available = PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, &subscriber, &state->notification) == ERROR_SUCCESS;
#endif
  if (!ok(env, napi_set_instance_data(env, state, finalize, nullptr))) { finalize(env, state, nullptr); return nullptr; }
  napi_property_descriptor properties[] = {
    {"capture", nullptr, capture, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"tick", nullptr, tick, nullptr, nullptr, nullptr, napi_default, nullptr}
  };
  if (!ok(env, napi_define_properties(env, exports, 2, properties))) return nullptr;
  return exports;
}
}
NAPI_MODULE(leafseamer_clock, initialize)
