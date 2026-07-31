#include "rust_packet_adapter.h"
namespace quicperf { std::unique_ptr<Adapter> makeTransportAdapter() { return std::make_unique<RustPacketAdapter>(QPF_LIBRARY_QUINN, "quinn"); } }
