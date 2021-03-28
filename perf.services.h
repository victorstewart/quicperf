#pragma once

static const char * modeToString(Mode mode)
{
	if (mode & Mode::server) 	return "server";
	else 								return "client";
}

#ifdef LSPERF
	#include "perf.tls.h"
	#include "perf.lsquic.h"
#endif

#ifdef PICOPERF
	#include "perf.picoquic.h"
#endif

#ifdef QUICHEPERF
	#include "perf.tls.h"
	#include "perf.quiche.h"
#endif

template <Mode mode>
static void globalSetup(void)
{
#ifdef LSPERF
	Lsquic<mode>::globalSetup();
#endif
}

template <Mode mode>
static QuicLibrary<mode>* libraryForChoice(void)
{
#ifdef LSPERF
	return new Lsquic<mode>();
#endif

#ifdef PICOPERF
	return new Picoquic<mode>();
#endif

#ifdef QUICHEPERF
	return new Quiche<mode>();
#endif
}
