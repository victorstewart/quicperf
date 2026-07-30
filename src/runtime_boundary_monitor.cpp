#include "core/runtime_monitor_protocol.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <openssl/evp.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

struct MonitorResult {
  std::string status = "failed";
  std::string violation;
  std::string violationDetail;
  std::string executable;
  std::string executableSha256;
  int targetExitCode = -1;
  int targetSignal = 0;
  uint64_t scopeEntries = 0;
  uint64_t scopeExits = 0;
  uint64_t ownershipAttestations = 0;
  uint64_t vdsoSymbols = 0;
  uint64_t tracedEvents = 0;
};

struct Tracee {
  uint64_t scopeDepth = 0;
  bool breakpointsEnabled = false;
};

[[noreturn]] void fail(std::string_view message)
{
  throw std::runtime_error(std::string(message));
}

std::string jsonEscape(std::string_view value)
{
  std::string result;
  for (const unsigned char character : value)
  {
    switch (character)
    {
      case '\\': result += "\\\\"; break;
      case '"': result += "\\\""; break;
      case '\n': result += "\\n"; break;
      case '\r': result += "\\r"; break;
      case '\t': result += "\\t"; break;
      default:
        if (character < 0x20)
        {
          std::ostringstream escaped;
          escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                  << static_cast<unsigned>(character);
          result += escaped.str();
        }
        else
        {
          result.push_back(static_cast<char>(character));
        }
    }
  }
  return result;
}

std::string sha256(const std::filesystem::path& path)
{
  std::ifstream input(path, std::ios::binary);
  if (!input) fail("cannot open monitored executable for hashing");
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  if (!context) fail("cannot allocate SHA-256 context");
  std::array<unsigned char, 1 << 16> buffer {};
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
  unsigned digestLength = 0;
  bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
  while (ok && input)
  {
    input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    const auto count = input.gcount();
    if (count > 0)
      ok = EVP_DigestUpdate(
          context, buffer.data(), static_cast<size_t>(count)) == 1;
  }
  ok = ok && input.eof() &&
      EVP_DigestFinal_ex(context, digest.data(), &digestLength) == 1;
  EVP_MD_CTX_free(context);
  if (!ok || digestLength != 32) fail("cannot hash monitored executable");
  std::ostringstream result;
  for (unsigned index = 0; index < digestLength; ++index)
    result << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned>(digest[index]);
  return result.str();
}

void writeReport(const std::filesystem::path& path, const MonitorResult& result)
{
  const auto parent = path.parent_path();
  if (!parent.empty()) std::filesystem::create_directories(parent);
  const auto temporary = path.string() + ".tmp." + std::to_string(getpid());
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) fail("cannot create runtime-monitor report");
    output
        << "{\n"
        << "  \"schema_version\": \"quicperf.runtime-boundary-monitor.v1\",\n"
        << "  \"status\": \"" << jsonEscape(result.status) << "\",\n"
        << "  \"violation\": \"" << jsonEscape(result.violation) << "\",\n"
        << "  \"violation_detail\": \"" << jsonEscape(result.violationDetail) << "\",\n"
        << "  \"executable\": \"" << jsonEscape(result.executable) << "\",\n"
        << "  \"executable_sha256\": \"" << result.executableSha256 << "\",\n"
        << "  \"target_exit_code\": " << result.targetExitCode << ",\n"
        << "  \"target_signal\": " << result.targetSignal << ",\n"
        << "  \"scope_entries\": " << result.scopeEntries << ",\n"
        << "  \"scope_exits\": " << result.scopeExits << ",\n"
        << "  \"ownership_attestations\": " << result.ownershipAttestations << ",\n"
        << "  \"vdso_breakpoint_symbols\": " << result.vdsoSymbols << ",\n"
        << "  \"traced_events\": " << result.tracedEvents << "\n"
        << "}\n";
    output.flush();
    if (!output) fail("cannot write runtime-monitor report");
  }
  if (rename(temporary.c_str(), path.c_str()) != 0)
  {
    unlink(temporary.c_str());
    fail("cannot atomically install runtime-monitor report");
  }
}

std::optional<std::pair<uintptr_t, size_t>> vdsoMapping(pid_t pid)
{
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(maps, line))
  {
    if (!line.ends_with(" [vdso]")) continue;
    const auto dash = line.find('-');
    const auto space = line.find(' ');
    if (dash == std::string::npos || space == std::string::npos || dash >= space)
      return std::nullopt;
    uintptr_t begin = 0;
    uintptr_t end = 0;
    const auto beginResult = std::from_chars(
        line.data(), line.data() + dash, begin, 16);
    const auto endResult = std::from_chars(
        line.data() + dash + 1, line.data() + space, end, 16);
    if (beginResult.ec != std::errc {} || endResult.ec != std::errc {} ||
        beginResult.ptr != line.data() + dash ||
        endResult.ptr != line.data() + space || end <= begin)
      return std::nullopt;
    return std::pair {begin, static_cast<size_t>(end - begin)};
  }
  return std::nullopt;
}

template<class Type>
const Type* checkedObject(const std::vector<unsigned char>& image, size_t offset)
{
  if (offset > image.size() || sizeof(Type) > image.size() - offset) return nullptr;
  return reinterpret_cast<const Type*>(image.data() + offset);
}

std::vector<uintptr_t> vdsoClockSymbols(pid_t pid)
{
  const auto mapping = vdsoMapping(pid);
  if (!mapping || mapping->second > 1 << 20) fail("cannot locate bounded vDSO mapping");
  std::vector<unsigned char> image(mapping->second);
  const std::string memoryPath = "/proc/" + std::to_string(pid) + "/mem";
  const int descriptor = open(memoryPath.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) fail("cannot open tracee memory for vDSO audit");
  const ssize_t count = pread(
      descriptor, image.data(), image.size(), static_cast<off_t>(mapping->first));
  close(descriptor);
  if (count != static_cast<ssize_t>(image.size()))
    fail("cannot read complete vDSO mapping");

  const auto* header = checkedObject<Elf64_Ehdr>(image, 0);
  if (!header || std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
      header->e_ident[EI_CLASS] != ELFCLASS64 || header->e_shentsize != sizeof(Elf64_Shdr))
    fail("tracee vDSO is not a supported ELF64 image");
  if (header->e_shnum == 0 || header->e_shoff > image.size() ||
      static_cast<size_t>(header->e_shnum) >
          (image.size() - header->e_shoff) / sizeof(Elf64_Shdr))
    fail("tracee vDSO has an invalid section table");
  const auto* sections = reinterpret_cast<const Elf64_Shdr*>(
      image.data() + header->e_shoff);

  static const std::set<std::string_view> wanted {
      "__vdso_clock_gettime", "__vdso_gettimeofday", "__vdso_time"};
  std::vector<uintptr_t> result;
  for (size_t sectionIndex = 0; sectionIndex < header->e_shnum; ++sectionIndex)
  {
    const auto& symbolsSection = sections[sectionIndex];
    if (symbolsSection.sh_type != SHT_DYNSYM ||
        symbolsSection.sh_entsize != sizeof(Elf64_Sym) ||
        symbolsSection.sh_link >= header->e_shnum ||
        symbolsSection.sh_offset > image.size() ||
        symbolsSection.sh_size > image.size() - symbolsSection.sh_offset)
      continue;
    const auto& stringsSection = sections[symbolsSection.sh_link];
    if (stringsSection.sh_offset > image.size() ||
        stringsSection.sh_size > image.size() - stringsSection.sh_offset)
      continue;
    const char* strings = reinterpret_cast<const char*>(
        image.data() + stringsSection.sh_offset);
    const auto* symbols = reinterpret_cast<const Elf64_Sym*>(
        image.data() + symbolsSection.sh_offset);
    const size_t symbolCount = symbolsSection.sh_size / sizeof(Elf64_Sym);
    for (size_t index = 0; index < symbolCount; ++index)
    {
      const auto& symbol = symbols[index];
      if (symbol.st_name >= stringsSection.sh_size || !symbol.st_value) continue;
      const char* name = strings + symbol.st_name;
      const size_t remaining = stringsSection.sh_size - symbol.st_name;
      const size_t length = strnlen(name, remaining);
      if (length == remaining) continue;
      if (wanted.contains(std::string_view(name, length)))
        result.push_back(mapping->first + symbol.st_value);
    }
  }
  std::ranges::sort(result);
  result.erase(std::unique(result.begin(), result.end()), result.end());
  if (result.size() < 3) fail("tracee vDSO clock symbols are incomplete");
  if (result.size() > 4) result.resize(4);
  return result;
}

void pokeDebugRegister(pid_t tid, size_t index, uintptr_t value)
{
  const auto offset = offsetof(user, u_debugreg[0]) + index * sizeof(uintptr_t);
  errno = 0;
  if (ptrace(PTRACE_POKEUSER, tid, offset, value) != 0 && errno)
    fail("cannot configure tracee hardware breakpoint");
}

void configureBreakpoints(pid_t tid,
                          const std::vector<uintptr_t>& addresses,
                          bool enabled)
{
  for (size_t index = 0; index < 4; ++index)
    pokeDebugRegister(tid, index, enabled && index < addresses.size() ? addresses[index] : 0);
  uintptr_t control = 0;
  if (enabled)
  {
    for (size_t index = 0; index < addresses.size(); ++index)
      control |= uintptr_t {1} << (index * 2);
  }
  pokeDebugRegister(tid, 7, control);
  pokeDebugRegister(tid, 6, 0);
}

size_t directoryCount(const std::string& path, bool tasks)
{
  DIR* directory = opendir(path.c_str());
  if (!directory) fail("cannot enumerate tracee runtime ownership");
  size_t count = 0;
  while (const dirent* entry = readdir(directory))
  {
    if (entry->d_name[0] == '.') continue;
    if (tasks)
    {
      const std::string commPath = path + '/' + entry->d_name + "/comm";
      std::ifstream comm(commPath);
      std::string name;
      if (!(comm >> name)) continue;
      if (name.starts_with("iou-wrk-")) continue;
    }
    ++count;
  }
  closedir(directory);
  return count;
}

std::string syscallViolation(long number, const user_regs_struct& registers)
{
  if (number == SYS_clock_gettime || number == SYS_gettimeofday || number == SYS_time)
    return "direct_clock_syscall";
  if (number == SYS_clone
#ifdef SYS_clone3
      || number == SYS_clone3
#endif
      || number == SYS_fork || number == SYS_vfork)
    return "adapter_thread_create";
  if (number == SYS_poll || number == SYS_ppoll || number == SYS_select ||
      number == SYS_pselect6 || number == SYS_epoll_wait ||
      number == SYS_epoll_pwait
#ifdef SYS_epoll_pwait2
      || number == SYS_epoll_pwait2
#endif
      || number == SYS_io_uring_enter)
    return "adapter_poller_wait";
  if (number == SYS_nanosleep || number == SYS_clock_nanosleep)
    return "adapter_sleep";
  if (number == SYS_fcntl && registers.rsi != F_DUPFD &&
      registers.rsi != F_DUPFD_CLOEXEC)
    return {};
  if (number == SYS_open || number == SYS_openat
#ifdef SYS_openat2
      || number == SYS_openat2
#endif
      || number == SYS_creat || number == SYS_socket ||
      number == SYS_socketpair || number == SYS_pipe || number == SYS_pipe2 ||
      number == SYS_dup || number == SYS_dup2 || number == SYS_dup3 ||
      number == SYS_fcntl || number == SYS_epoll_create ||
      number == SYS_epoll_create1 || number == SYS_eventfd ||
      number == SYS_eventfd2 || number == SYS_timerfd_create ||
      number == SYS_signalfd || number == SYS_signalfd4 ||
      number == SYS_inotify_init || number == SYS_inotify_init1 ||
      number == SYS_io_uring_setup)
    return "adapter_fd_create";
  return {};
}

std::string traceeString(pid_t tid, uintptr_t address)
{
  if (!address) return "<null>";
  const std::string path = "/proc/" + std::to_string(tid) + "/mem";
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) return "<unreadable>";
  std::array<char, 512> value {};
  const ssize_t count = pread(
      descriptor, value.data(), value.size() - 1, static_cast<off_t>(address));
  close(descriptor);
  if (count <= 0) return "<unreadable>";
  return std::string(value.data(), strnlen(value.data(), static_cast<size_t>(count)));
}

std::string syscallDetail(pid_t tid, long number, const user_regs_struct& registers)
{
  std::string result = "syscall=" + std::to_string(number);
  if (number == SYS_open || number == SYS_creat)
    result += " path=" + traceeString(tid, registers.rdi);
  else if (number == SYS_openat
#ifdef SYS_openat2
           || number == SYS_openat2
#endif
  )
    result += " path=" + traceeString(tid, registers.rsi);
  else if (number == SYS_socket)
    result += " domain=" + std::to_string(registers.rdi) +
        " type=" + std::to_string(registers.rsi);
  return result;
}

std::string executableStackCandidates(pid_t tid,
                                      uintptr_t stackPointer,
                                      const std::string& executable)
{
  std::ifstream maps("/proc/" + std::to_string(tid) + "/maps");
  struct Mapping {
    uintptr_t begin;
    uintptr_t end;
    uintptr_t base;
  };
  std::vector<Mapping> mappings;
  std::string line;
  while (std::getline(maps, line))
  {
    if (!line.ends_with(' ' + executable)) continue;
    uintptr_t begin = 0;
    uintptr_t end = 0;
    uintptr_t offset = 0;
    if (sscanf(line.c_str(), "%lx-%lx %*4s %lx", &begin, &end, &offset) == 3 &&
        end > begin && begin >= offset)
      mappings.push_back({begin, end, begin - offset});
  }
  if (mappings.empty()) return {};
  const std::string memoryPath = "/proc/" + std::to_string(tid) + "/mem";
  const int descriptor = open(memoryPath.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) return {};
  std::array<uintptr_t, 512> words {};
  const ssize_t count = pread(
      descriptor, words.data(), sizeof(words), static_cast<off_t>(stackPointer));
  close(descriptor);
  if (count <= 0) return {};
  std::set<uintptr_t> seen;
  std::ostringstream result;
  size_t emitted = 0;
  for (size_t index = 0; index < static_cast<size_t>(count) / sizeof(uintptr_t); ++index)
  {
    for (const auto& mapping : mappings)
    {
      if (words[index] < mapping.begin || words[index] >= mapping.end) continue;
      const uintptr_t offset = words[index] - mapping.base;
      if (!seen.insert(offset).second) break;
      result << (emitted++ ? "," : " stack=") << "exe+0x" << std::hex << offset;
      break;
    }
    if (emitted == 16) break;
  }
  return result.str();
}

void terminateTracees(pid_t root)
{
  if (root > 0) kill(root, SIGKILL);
}

int monitor(char* const* command,
            const std::filesystem::path& reportPath,
            MonitorResult& result)
{
  const auto executable = std::filesystem::canonical(command[0]);
  result.executable = executable.string();
  result.executableSha256 = sha256(executable);

  const pid_t child = fork();
  if (child < 0) fail("cannot fork monitored child");
  if (child == 0)
  {
    if (setenv("QUICPERF_RUNTIME_OWNERSHIP_AUDIT", "1", 1) != 0 ||
        setenv("QUICPERF_EXTERNAL_RUNTIME_MONITOR", "1", 1) != 0 ||
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0)
      _exit(125);
    raise(SIGSTOP);
    execv(command[0], command);
    _exit(126);
  }

  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status))
    fail("monitored child did not enter its initial trace stop");
  constexpr unsigned long options =
      PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
      PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACESECCOMP;
  if (ptrace(PTRACE_SETOPTIONS, child, nullptr, options) != 0 ||
      ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0)
    fail("cannot start monitored child tracing");

  std::map<pid_t, Tracee> tracees {{child, {}}};
  std::vector<uintptr_t> vdsoAddresses;
  bool targetExited = false;
  while (!tracees.empty())
  {
    const pid_t tid = waitpid(-1, &status, __WALL);
    if (tid < 0)
    {
      if (errno == EINTR) continue;
      if (errno == ECHILD) break;
      fail("waitpid failed while monitoring runtime boundary");
    }
    auto tracee = tracees.find(tid);
    if (tracee == tracees.end()) tracee = tracees.emplace(tid, Tracee {}).first;

    if (WIFEXITED(status) || WIFSIGNALED(status))
    {
      if (tracee->second.scopeDepth && result.violation.empty())
        result.violation = "unbalanced_adapter_scope";
      if (tid == child)
      {
        targetExited = true;
        result.targetExitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        result.targetSignal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
      }
      tracees.erase(tracee);
      continue;
    }
    if (!WIFSTOPPED(status)) continue;
    const int signal = WSTOPSIG(status);
    const unsigned event = static_cast<unsigned>(status) >> 16;

    if (event == PTRACE_EVENT_EXEC)
    {
      vdsoAddresses = vdsoClockSymbols(tid);
      result.vdsoSymbols = vdsoAddresses.size();
      if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) != 0)
        fail("cannot continue tracee after exec");
      continue;
    }
    if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK ||
        event == PTRACE_EVENT_VFORK)
    {
      unsigned long created = 0;
      if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &created) != 0)
        fail("cannot identify created tracee");
      tracees.try_emplace(static_cast<pid_t>(created));
      if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) != 0)
        fail("cannot continue tracee after creation");
      continue;
    }
    if (event == PTRACE_EVENT_SECCOMP)
    {
      ++result.tracedEvents;
      user_regs_struct registers {};
      if (ptrace(PTRACE_GETREGS, tid, nullptr, &registers) != 0)
        fail("cannot read tracee registers at seccomp event");
      const long number = static_cast<long>(registers.orig_rax);
      if (number == SYS_gettid && registers.rdi == quicperf::runtime_monitor::markerMagic)
      {
        const auto marker = static_cast<quicperf::runtime_monitor::Marker>(registers.rsi);
        if (marker == quicperf::runtime_monitor::Marker::scopeEnter)
        {
          if (tracee->second.scopeDepth++ == 0)
          {
            configureBreakpoints(tid, vdsoAddresses, true);
            tracee->second.breakpointsEnabled = true;
          }
          ++result.scopeEntries;
        }
        else if (marker == quicperf::runtime_monitor::Marker::scopeExit)
        {
          if (!tracee->second.scopeDepth)
          {
            result.violation = "unbalanced_adapter_scope";
          }
          else
          {
            --tracee->second.scopeDepth;
            if (!tracee->second.scopeDepth)
            {
              configureBreakpoints(tid, vdsoAddresses, false);
              tracee->second.breakpointsEnabled = false;
            }
          }
          ++result.scopeExits;
        }
        else if (marker == quicperf::runtime_monitor::Marker::ownership)
        {
          ++result.ownershipAttestations;
          const size_t observedTasks = directoryCount(
              "/proc/" + std::to_string(child) + "/task", true);
          const size_t observedFds = directoryCount(
              "/proc/" + std::to_string(child) + "/fd", false);
          if (observedTasks != registers.rdx)
            result.violation = "ownership_thread_mismatch";
          else if (observedFds != registers.r10)
            result.violation = "ownership_fd_mismatch";
        }
      }
      else if (tracee->second.scopeDepth)
      {
        result.violation = syscallViolation(number, registers);
        if (!result.violation.empty())
          result.violationDetail = syscallDetail(tid, number, registers) +
              executableStackCandidates(
                  tid, registers.rsp, result.executable);
      }
      if (!result.violation.empty())
      {
        terminateTracees(child);
      }
      if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) != 0 && errno != ESRCH)
        fail("cannot continue tracee after seccomp event");
      continue;
    }
    if (signal == SIGTRAP)
    {
      siginfo_t info {};
      if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) == 0 &&
          info.si_code == TRAP_HWBKPT && tracee->second.scopeDepth)
      {
        result.violation = "vdso_private_clock";
        std::ostringstream detail;
        detail << "address=0x" << std::hex
               << reinterpret_cast<uintptr_t>(info.si_addr);
        user_regs_struct registers {};
        result.violationDetail = detail.str();
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &registers) == 0)
          result.violationDetail += executableStackCandidates(
              tid, registers.rsp, result.executable);
        terminateTracees(child);
      }
      if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) != 0 && errno != ESRCH)
        fail("cannot continue tracee after breakpoint");
      continue;
    }
    const int delivered = signal == SIGSTOP ? 0 : signal;
    if (ptrace(PTRACE_CONT, tid, nullptr, delivered) != 0 && errno != ESRCH)
      fail("cannot continue stopped tracee");
  }

  if (!targetExited && result.violation.empty())
    result.violation = "target_exit_not_observed";
  if (result.violation.empty() && result.targetExitCode == 0 &&
      result.scopeEntries && result.scopeEntries == result.scopeExits &&
      result.ownershipAttestations && result.vdsoSymbols >= 3)
    result.status = "passed";
  else if (!result.violation.empty())
    result.status = "violation_detected";
  else
    result.status = "target_failed";
  writeReport(reportPath, result);
  if (result.status == "passed") return 0;
  if (result.status == "violation_detected") return 3;
  return result.targetExitCode > 0 && result.targetExitCode < 125 ?
      result.targetExitCode : 4;
}

} // namespace

int main(int argc, char** argv)
{
  try
  {
    if (argc < 5 || std::string_view(argv[1]) != "--report" ||
        std::string_view(argv[3]) != "--")
      fail("usage: quicperf-runtime-monitor --report PATH -- EXECUTABLE [ARG ...]");
    MonitorResult result;
    return monitor(argv + 4, argv[2], result);
  }
  catch (const std::exception& error)
  {
    std::cerr << "quicperf runtime monitor: " << error.what() << '\n';
    return 5;
  }
}
