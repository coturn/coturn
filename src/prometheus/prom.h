/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2026 coturn project
 *
 * Minimal, self-contained Prometheus client used by coturn.
 *
 * This is a drop-in replacement for the small subset of the
 * digitalocean/prometheus-client-c ("prom") API that coturn consumes.
 * The upstream library is no longer maintained, so the pieces coturn
 * actually needs -- counters, gauges, a single default registry, and the
 * text-exposition "bridge" -- are reimplemented here and built straight
 * from coturn's own sources. The public names and signatures match the
 * upstream library so prom_server.c does not need to change.
 *
 * Out of scope on purpose (coturn never used them): histograms, summaries,
 * process/collector plugins, custom registries beyond the default one, and
 * the bundled promhttp HTTP handler (coturn ships its own microhttpd
 * handler in prom_server.c).
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef COTURN_PROM_H
#define COTURN_PROM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque metric handle. Counters and gauges share one representation and are
 * distinguished by an internal type tag, matching upstream's prom_metric_t. */
typedef struct prom_metric prom_metric_t;
typedef struct prom_metric prom_counter_t;
typedef struct prom_metric prom_gauge_t;

typedef struct prom_collector_registry prom_collector_registry_t;

/* The process-wide default registry. NULL until
 * prom_collector_registry_default_init() succeeds. */
extern prom_collector_registry_t *PROM_COLLECTOR_REGISTRY_DEFAULT;

/* Create (idempotently) the default registry. Returns 0 on success. */
int prom_collector_registry_default_init(void);

/* Register a metric into the default registry and return it unchanged so the
 * call can wrap prom_counter_new()/prom_gauge_new() inline. On failure the
 * metric is destroyed and NULL is returned. */
prom_metric_t *prom_collector_registry_must_register_metric(prom_metric_t *metric);

/* Render every registered metric in Prometheus text-exposition format. Returns
 * a heap-allocated NUL-terminated string the caller must free(), or NULL on
 * allocation failure. */
const char *prom_collector_registry_bridge(prom_collector_registry_t *registry);

/* Counters: monotonically increasing values. label_keys may be NULL when
 * label_key_count is 0. */
prom_counter_t *prom_counter_new(const char *name, const char *help, size_t label_key_count, const char **label_keys);
int prom_counter_add(prom_counter_t *self, double r_value, const char **label_values);
int prom_counter_inc(prom_counter_t *self, const char **label_values);

/* Gauges: values that can go up and down. */
prom_gauge_t *prom_gauge_new(const char *name, const char *help, size_t label_key_count, const char **label_keys);
int prom_gauge_add(prom_gauge_t *self, double r_value, const char **label_values);
int prom_gauge_inc(prom_gauge_t *self, const char **label_values);
int prom_gauge_dec(prom_gauge_t *self, const char **label_values);
int prom_gauge_set(prom_gauge_t *self, double r_value, const char **label_values);

#ifdef __cplusplus
}
#endif

#endif /* COTURN_PROM_H */
