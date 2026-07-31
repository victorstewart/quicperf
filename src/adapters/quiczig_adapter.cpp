#include "zig_packet_adapter.h"
namespace quicperf { std::unique_ptr<Adapter> makeTransportAdapter() { return std::make_unique<ZigPacketAdapter>(); } }
