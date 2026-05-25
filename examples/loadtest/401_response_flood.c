/*
 * Saturating UDP generator for the TURN 401 Unauthorized challenge path.
 *
 * Build:
 *   cc -O3 -pthread -Wall -Wextra -o 401_response_flood 401_response_flood.c
 *
 * Run:
 *   ./401_response_flood --host 10.116.0.2 --duration 30 --threads 4
 *
 * Each worker continuously sends valid unauthenticated Allocate requests.
 * With long-term authentication enabled, turnserver replies with 401 until
 * its optional 401 response rate-limit suppresses the response. A dedicated
 * generator avoids measuring successful allocations or relay traffic.
 */

#define _GNU_SOURCE

#if !defined(__linux__)
#error "401_response_flood is Linux-only because it uses sendmmsg/recvmmsg"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define STUN_ALLOCATE_REQUEST 0x0003u
#define STUN_ERROR_CODE 0x0009u
#define STUN_REQUESTED_TRANSPORT 0x0019u
#define STUN_COOKIE 0x2112A442u
#define STUN_REQUEST_BYTES 28u
#define RESPONSE_BYTES_MAX 2048u
#define DEFAULT_PORT 3478u
#define DEFAULT_DURATION 30u
#define DEFAULT_THREADS 4u
#define DEFAULT_BATCH 64u
#define MAX_BATCH 1024u

typedef struct {
  struct sockaddr_in destination;
  double finish_at;
  uint32_t worker_id;
  uint32_t batch;
  uint64_t sent_packets;
  uint64_t sent_bytes;
  uint64_t recv_packets;
  uint64_t recv_bytes;
  uint64_t responses_401;
  uint64_t send_wouldblock;
  int error;
} worker_state;

static volatile sig_atomic_t stop_requested = 0;

static void stop_handler(int sig) {
  (void)sig;
  stop_requested = 1;
}

static double monotonic_seconds(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0.0;
  }
  return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static void put_u16(uint8_t *p, uint16_t value) {
  uint16_t n = htons(value);
  memcpy(p, &n, sizeof(n));
}

static void put_u32(uint8_t *p, uint32_t value) {
  uint32_t n = htonl(value);
  memcpy(p, &n, sizeof(n));
}

static void make_allocate_request(uint8_t request[STUN_REQUEST_BYTES], uint32_t worker_id, uint64_t sequence) {
  memset(request, 0, STUN_REQUEST_BYTES);
  put_u16(request, STUN_ALLOCATE_REQUEST);
  put_u16(request + 2, 8u);
  put_u32(request + 4, STUN_COOKIE);
  put_u32(request + 8, worker_id);
  put_u32(request + 12, (uint32_t)(sequence >> 32));
  put_u32(request + 16, (uint32_t)sequence);
  put_u16(request + 20, STUN_REQUESTED_TRANSPORT);
  put_u16(request + 22, 4u);
  request[24] = 17u; /* UDP requested transport. */
}

static bool response_is_401(const uint8_t *response, size_t length) {
  if (length < 20u) {
    return false;
  }
  size_t attr_offset = 20u;
  while (attr_offset + 4u <= length) {
    uint16_t type;
    uint16_t attr_length;
    memcpy(&type, response + attr_offset, sizeof(type));
    memcpy(&attr_length, response + attr_offset + 2u, sizeof(attr_length));
    type = ntohs(type);
    attr_length = ntohs(attr_length);
    if (attr_offset + 4u + attr_length > length) {
      return false;
    }
    if (type == STUN_ERROR_CODE && attr_length >= 4u) {
      unsigned int code = ((unsigned int)(response[attr_offset + 6u] & 0x07u) * 100u) +
                          (unsigned int)response[attr_offset + 7u];
      return code == 401u;
    }
    attr_offset += 4u + ((attr_length + 3u) & ~3u);
  }
  return false;
}

static void drain_responses(int fd, worker_state *state, struct mmsghdr *messages, struct iovec *iovecs,
                            uint8_t *buffers) {
  for (;;) {
    if (stop_requested || monotonic_seconds() >= state->finish_at) {
      return;
    }
    for (uint32_t i = 0; i < state->batch; ++i) {
      memset(&messages[i], 0, sizeof(messages[i]));
      iovecs[i].iov_base = buffers + (i * RESPONSE_BYTES_MAX);
      iovecs[i].iov_len = RESPONSE_BYTES_MAX;
      messages[i].msg_hdr.msg_iov = &iovecs[i];
      messages[i].msg_hdr.msg_iovlen = 1;
    }
    int received = recvmmsg(fd, messages, state->batch, MSG_DONTWAIT, NULL);
    if (received <= 0) {
      if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        state->error = errno;
      }
      return;
    }
    state->recv_packets += (uint64_t)received;
    for (int i = 0; i < received; ++i) {
      state->recv_bytes += messages[i].msg_len;
      if (response_is_401((const uint8_t *)iovecs[i].iov_base, messages[i].msg_len)) {
        state->responses_401++;
      }
    }
  }
}

static void *run_worker(void *opaque) {
  worker_state *state = (worker_state *)opaque;
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    state->error = errno;
    return NULL;
  }
  int buffer_bytes = 16 * 1024 * 1024;
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer_bytes, sizeof(buffer_bytes));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer_bytes, sizeof(buffer_bytes));
  if (connect(fd, (const struct sockaddr *)&state->destination, sizeof(state->destination)) != 0) {
    state->error = errno;
    close(fd);
    return NULL;
  }

  struct mmsghdr *send_messages = calloc(state->batch, sizeof(*send_messages));
  struct iovec *send_iovecs = calloc(state->batch, sizeof(*send_iovecs));
  uint8_t *requests = calloc(state->batch, STUN_REQUEST_BYTES);
  struct mmsghdr *recv_messages = calloc(state->batch, sizeof(*recv_messages));
  struct iovec *recv_iovecs = calloc(state->batch, sizeof(*recv_iovecs));
  uint8_t *responses = calloc(state->batch, RESPONSE_BYTES_MAX);
  if (!send_messages || !send_iovecs || !requests || !recv_messages || !recv_iovecs || !responses) {
    state->error = ENOMEM;
    goto out;
  }

  uint64_t sequence = 0;
  while (!stop_requested && monotonic_seconds() < state->finish_at && state->error == 0) {
    for (uint32_t i = 0; i < state->batch; ++i) {
      uint8_t *request = requests + (i * STUN_REQUEST_BYTES);
      make_allocate_request(request, state->worker_id, sequence++);
      memset(&send_messages[i], 0, sizeof(send_messages[i]));
      send_iovecs[i].iov_base = request;
      send_iovecs[i].iov_len = STUN_REQUEST_BYTES;
      send_messages[i].msg_hdr.msg_iov = &send_iovecs[i];
      send_messages[i].msg_hdr.msg_iovlen = 1;
    }
    int sent = sendmmsg(fd, send_messages, state->batch, MSG_DONTWAIT);
    if (sent > 0) {
      state->sent_packets += (uint64_t)sent;
      state->sent_bytes += (uint64_t)sent * STUN_REQUEST_BYTES;
    } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      state->send_wouldblock++;
    } else if (sent < 0 && errno != EINTR) {
      state->error = errno;
    }
    drain_responses(fd, state, recv_messages, recv_iovecs, responses);
  }

  /* Collect responses already queued at the end without extending the test. */
  drain_responses(fd, state, recv_messages, recv_iovecs, responses);

out:
  free(send_messages);
  free(send_iovecs);
  free(requests);
  free(recv_messages);
  free(recv_iovecs);
  free(responses);
  close(fd);
  return NULL;
}

static void usage(const char *program) {
  fprintf(stderr,
          "Usage: %s --host <ipv4> [--port N] [--duration S] [--threads N] [--batch N]\n"
          "Send valid unauthenticated UDP Allocate requests and count TURN 401 responses.\n",
          program);
}

static uint32_t parse_u32(const char *value, const char *name, uint32_t min, uint32_t max) {
  char *end = NULL;
  unsigned long parsed = strtoul(value, &end, 10);
  if (!value[0] || (end && *end) || parsed < min || parsed > max) {
    fprintf(stderr, "Invalid %s: %s\n", name, value);
    exit(2);
  }
  return (uint32_t)parsed;
}

int main(int argc, char **argv) {
  const char *host = NULL;
  uint32_t port = DEFAULT_PORT;
  uint32_t duration = DEFAULT_DURATION;
  uint32_t threads = DEFAULT_THREADS;
  uint32_t batch = DEFAULT_BATCH;
  const struct option options[] = {{"host", required_argument, NULL, 'H'},
                                   {"port", required_argument, NULL, 'p'},
                                   {"duration", required_argument, NULL, 'd'},
                                   {"threads", required_argument, NULL, 't'},
                                   {"batch", required_argument, NULL, 'b'},
                                   {"help", no_argument, NULL, 'h'},
                                   {NULL, 0, NULL, 0}};
  int option;
  while ((option = getopt_long(argc, argv, "H:p:d:t:b:h", options, NULL)) != -1) {
    switch (option) {
    case 'H':
      host = optarg;
      break;
    case 'p':
      port = parse_u32(optarg, "port", 1u, 65535u);
      break;
    case 'd':
      duration = parse_u32(optarg, "duration", 1u, 86400u);
      break;
    case 't':
      threads = parse_u32(optarg, "threads", 1u, 256u);
      break;
    case 'b':
      batch = parse_u32(optarg, "batch", 1u, MAX_BATCH);
      break;
    default:
      usage(argv[0]);
      return option == 'h' ? 0 : 2;
    }
  }
  if (!host) {
    usage(argv[0]);
    return 2;
  }

  struct sockaddr_in destination = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
  if (inet_pton(AF_INET, host, &destination.sin_addr) != 1) {
    fprintf(stderr, "Invalid IPv4 destination: %s\n", host);
    return 2;
  }

  signal(SIGINT, stop_handler);
  signal(SIGTERM, stop_handler);
  pthread_t *thread_ids = calloc(threads, sizeof(*thread_ids));
  worker_state *workers = calloc(threads, sizeof(*workers));
  if (!thread_ids || !workers) {
    fprintf(stderr, "Cannot allocate worker state\n");
    return 1;
  }

  const double started = monotonic_seconds();
  const double finish_at = started + duration;
  for (uint32_t i = 0; i < threads; ++i) {
    workers[i].destination = destination;
    workers[i].finish_at = finish_at;
    workers[i].worker_id = i + 1u;
    workers[i].batch = batch;
    int create_error = pthread_create(&thread_ids[i], NULL, run_worker, &workers[i]);
    if (create_error != 0) {
      workers[i].error = create_error;
      stop_requested = 1;
      threads = i;
      break;
    }
  }
  for (uint32_t i = 0; i < threads; ++i) {
    pthread_join(thread_ids[i], NULL);
  }
  const double elapsed = monotonic_seconds() - started;

  uint64_t sent_packets = 0;
  uint64_t sent_bytes = 0;
  uint64_t recv_packets = 0;
  uint64_t recv_bytes = 0;
  uint64_t responses_401 = 0;
  uint64_t send_wouldblock = 0;
  int error = 0;
  for (uint32_t i = 0; i < threads; ++i) {
    sent_packets += workers[i].sent_packets;
    sent_bytes += workers[i].sent_bytes;
    recv_packets += workers[i].recv_packets;
    recv_bytes += workers[i].recv_bytes;
    responses_401 += workers[i].responses_401;
    send_wouldblock += workers[i].send_wouldblock;
    if (workers[i].error && !error) {
      error = workers[i].error;
    }
  }
  printf("duration_seconds=%.3f threads=%" PRIu32 " batch=%" PRIu32 "\n", elapsed, threads, batch);
  printf("sent_packets=%" PRIu64 " sent_pps=%.0f sent_bytes=%" PRIu64 " sent_mbps=%.3f\n", sent_packets,
         (double)sent_packets / elapsed, sent_bytes, ((double)sent_bytes * 8.0) / elapsed / 1000000.0);
  printf("recv_packets=%" PRIu64 " recv_pps=%.0f recv_bytes=%" PRIu64 " recv_mbps=%.3f responses_401=%" PRIu64
         " response_ratio=%.6f\n",
         recv_packets, (double)recv_packets / elapsed, recv_bytes, ((double)recv_bytes * 8.0) / elapsed / 1000000.0,
         responses_401, sent_packets ? (double)responses_401 / (double)sent_packets : 0.0);
  printf("send_wouldblock=%" PRIu64 " worker_error=%d\n", send_wouldblock, error);
  free(thread_ids);
  free(workers);
  return error ? 1 : 0;
}
