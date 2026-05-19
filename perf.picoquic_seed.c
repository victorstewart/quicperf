#include "picoquic.h"
#include "picoquic_internal.h"

#include <stdint.h>

void quicperf_picoquic_seed_sender_now(
    picoquic_cnx_t *cnx,
    uint64_t cwin,
    uint64_t pacing_rate,
    uint64_t current_time)
{
  if (cnx == NULL ||
      cnx->path[0] == NULL ||
      cnx->congestion_alg == NULL ||
      cnx->congestion_alg->alg_notify == NULL ||
      cwin == 0)
  {
    return;
  }

  picoquic_path_t *path_x = cnx->path[0];
  picoquic_per_ack_state_t ack_state = {0};
  ack_state.pc = picoquic_packet_context_application;
  ack_state.nb_bytes_acknowledged = cwin;

  cnx->congestion_alg->alg_notify(cnx, path_x,
                                  picoquic_congestion_notification_seed_cwin, &ack_state, current_time);

  if (path_x->cwin < cwin)
  {
    path_x->cwin = cwin;
  }
  path_x->is_ssthresh_initialized = 1;

  if (pacing_rate != 0)
  {
    uint64_t quantum = 10 * (uint64_t)path_x->send_mtu;
    uint64_t max_quantum = 64 * (uint64_t)path_x->send_mtu;
    if (quantum > cwin)
    {
      quantum = cwin;
    }
    if (quantum > max_quantum)
    {
      quantum = max_quantum;
    }
    if (quantum < (uint64_t)path_x->send_mtu)
    {
      quantum = (uint64_t)path_x->send_mtu;
    }
    picoquic_update_pacing_rate(path_x, (double)pacing_rate, quantum);
  }
}
