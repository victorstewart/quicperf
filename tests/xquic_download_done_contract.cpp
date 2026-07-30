#include "perf.benchmark.h"

int main()
{
  if (!benchmarkServerObservedDownloadDoneMarker(false, true, false, 0, 8, 9))
  {
    return 1;
  }
  if (!benchmarkServerObservedDownloadDoneMarker(false, true, true, 42, 8, 9))
  {
    return 2;
  }
  if (benchmarkServerObservedDownloadDoneMarker(true, true, false, 0, 8, 9) ||
      benchmarkServerObservedDownloadDoneMarker(false, false, false, 0, 8, 9) ||
      benchmarkServerObservedDownloadDoneMarker(false, true, false, 1, 8, 9) ||
      benchmarkServerObservedDownloadDoneMarker(false, true, false, 0, 9, 9))
  {
    return 3;
  }
  return 0;
}
