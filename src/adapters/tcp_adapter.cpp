#include "declared_adapter.h"
namespace quicperf { std::unique_ptr<Adapter> makeTransportAdapter() { return std::make_unique<DeclaredAdapter>("tcp_tls"); } }
