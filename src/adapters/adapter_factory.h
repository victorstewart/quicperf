#pragma once

#include "core/adapter.h"

#include <memory>

namespace quicperf {

std::unique_ptr<Adapter> makeTransportAdapter();

} // namespace quicperf
