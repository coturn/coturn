/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2026 coturn project
 *
 * Minimal Prometheus client implementation for coturn. See prom.h for the
 * rationale and the scope of the supported API.
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

#include "prom.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { PROM_COUNTER, PROM_GAUGE } prom_metric_type_t;

/* One time-series: a metric plus a specific set of label values. */
typedef struct prom_sample {
  char **label_values; /* label_count owned strings, NULL when label_count==0 */
  double value;
  struct prom_sample *next;
} prom_sample_t;

struct prom_metric {
  prom_metric_type_t type;
  char *name;
  char *help;
  size_t label_count;
  char **label_keys; /* owned copies */
  prom_sample_t *samples;
  pthread_mutex_t mutex; /* guards samples and sample values */
  struct prom_metric *next;
};

struct prom_collector_registry {
  prom_metric_t *metrics; /* singly linked, registration order reversed */
  pthread_mutex_t mutex;
};

prom_collector_registry_t *PROM_COLLECTOR_REGISTRY_DEFAULT = NULL;

/* Guards the one-shot creation of the default registry. */
static pthread_mutex_t g_default_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static char *prom_strdup(const char *s) {
  if (s == NULL) {
    return NULL;
  }
  size_t n = strlen(s) + 1;
  char *p = malloc(n);
  if (p != NULL) {
    memcpy(p, s, n);
  }
  return p;
}

/* -------------------------------------------------------------------------- */
/* Metric lifecycle                                                           */
/* -------------------------------------------------------------------------- */

static prom_metric_t *prom_metric_new(prom_metric_type_t type, const char *name, const char *help,
                                      size_t label_key_count, const char **label_keys) {
  if (name == NULL) {
    return NULL;
  }

  prom_metric_t *m = calloc(1, sizeof(*m));
  if (m == NULL) {
    return NULL;
  }

  m->type = type;
  m->name = prom_strdup(name);
  m->help = prom_strdup(help != NULL ? help : "");
  m->label_count = label_key_count;
  if (m->name == NULL || m->help == NULL) {
    goto fail;
  }

  if (label_key_count > 0) {
    m->label_keys = calloc(label_key_count, sizeof(char *));
    if (m->label_keys == NULL) {
      goto fail;
    }
    for (size_t i = 0; i < label_key_count; i++) {
      m->label_keys[i] = prom_strdup(label_keys != NULL ? label_keys[i] : "");
      if (m->label_keys[i] == NULL) {
        goto fail;
      }
    }
  }

  if (pthread_mutex_init(&m->mutex, NULL) != 0) {
    goto fail;
  }
  return m;

fail:
  if (m->label_keys != NULL) {
    for (size_t i = 0; i < label_key_count; i++) {
      free(m->label_keys[i]);
    }
    free(m->label_keys);
  }
  free(m->name);
  free(m->help);
  free(m);
  return NULL;
}

static void prom_metric_destroy(prom_metric_t *m) {
  if (m == NULL) {
    return;
  }
  prom_sample_t *s = m->samples;
  while (s != NULL) {
    prom_sample_t *next = s->next;
    if (s->label_values != NULL) {
      for (size_t i = 0; i < m->label_count; i++) {
        free(s->label_values[i]);
      }
      free(s->label_values);
    }
    free(s);
    s = next;
  }
  if (m->label_keys != NULL) {
    for (size_t i = 0; i < m->label_count; i++) {
      free(m->label_keys[i]);
    }
    free(m->label_keys);
  }
  pthread_mutex_destroy(&m->mutex);
  free(m->name);
  free(m->help);
  free(m);
}

prom_counter_t *prom_counter_new(const char *name, const char *help, size_t label_key_count, const char **label_keys) {
  return prom_metric_new(PROM_COUNTER, name, help, label_key_count, label_keys);
}

prom_gauge_t *prom_gauge_new(const char *name, const char *help, size_t label_key_count, const char **label_keys) {
  return prom_metric_new(PROM_GAUGE, name, help, label_key_count, label_keys);
}

/* -------------------------------------------------------------------------- */
/* Sample lookup / mutation (caller holds m->mutex)                           */
/* -------------------------------------------------------------------------- */

static int label_values_equal(const prom_metric_t *m, char *const *a, const char *const *b) {
  for (size_t i = 0; i < m->label_count; i++) {
    const char *av = a[i] != NULL ? a[i] : "";
    const char *bv = (b != NULL && b[i] != NULL) ? b[i] : "";
    if (strcmp(av, bv) != 0) {
      return 0;
    }
  }
  return 1;
}

static prom_sample_t *prom_metric_find_or_create_sample(prom_metric_t *m, const char **label_values) {
  for (prom_sample_t *s = m->samples; s != NULL; s = s->next) {
    if (label_values_equal(m, s->label_values, label_values)) {
      return s;
    }
  }

  prom_sample_t *s = calloc(1, sizeof(*s));
  if (s == NULL) {
    return NULL;
  }
  if (m->label_count > 0) {
    s->label_values = calloc(m->label_count, sizeof(char *));
    if (s->label_values == NULL) {
      free(s);
      return NULL;
    }
    for (size_t i = 0; i < m->label_count; i++) {
      const char *v = (label_values != NULL && label_values[i] != NULL) ? label_values[i] : "";
      s->label_values[i] = prom_strdup(v);
      if (s->label_values[i] == NULL) {
        for (size_t j = 0; j < i; j++) {
          free(s->label_values[j]);
        }
        free(s->label_values);
        free(s);
        return NULL;
      }
    }
  }
  s->value = 0.0;
  s->next = m->samples;
  m->samples = s;
  return s;
}

static int prom_metric_add(prom_metric_t *self, prom_metric_type_t expected, double r_value,
                           const char **label_values) {
  if (self == NULL || self->type != expected) {
    return 1;
  }
  pthread_mutex_lock(&self->mutex);
  prom_sample_t *s = prom_metric_find_or_create_sample(self, label_values);
  int rc = 1;
  if (s != NULL) {
    s->value += r_value;
    rc = 0;
  }
  pthread_mutex_unlock(&self->mutex);
  return rc;
}

static int prom_metric_set(prom_metric_t *self, prom_metric_type_t expected, double r_value,
                           const char **label_values) {
  if (self == NULL || self->type != expected) {
    return 1;
  }
  pthread_mutex_lock(&self->mutex);
  prom_sample_t *s = prom_metric_find_or_create_sample(self, label_values);
  int rc = 1;
  if (s != NULL) {
    s->value = r_value;
    rc = 0;
  }
  pthread_mutex_unlock(&self->mutex);
  return rc;
}

int prom_counter_add(prom_counter_t *self, double r_value, const char **label_values) {
  /* Counters are monotonic; silently ignore negative deltas like upstream. */
  if (r_value < 0) {
    return 1;
  }
  return prom_metric_add(self, PROM_COUNTER, r_value, label_values);
}

int prom_counter_inc(prom_counter_t *self, const char **label_values) {
  return prom_metric_add(self, PROM_COUNTER, 1.0, label_values);
}

int prom_gauge_add(prom_gauge_t *self, double r_value, const char **label_values) {
  return prom_metric_add(self, PROM_GAUGE, r_value, label_values);
}

int prom_gauge_inc(prom_gauge_t *self, const char **label_values) {
  return prom_metric_add(self, PROM_GAUGE, 1.0, label_values);
}

int prom_gauge_dec(prom_gauge_t *self, const char **label_values) {
  return prom_metric_add(self, PROM_GAUGE, -1.0, label_values);
}

int prom_gauge_set(prom_gauge_t *self, double r_value, const char **label_values) {
  return prom_metric_set(self, PROM_GAUGE, r_value, label_values);
}

/* -------------------------------------------------------------------------- */
/* Registry                                                                   */
/* -------------------------------------------------------------------------- */

int prom_collector_registry_default_init(void) {
  int rc = 0;
  pthread_mutex_lock(&g_default_init_mutex);
  if (PROM_COLLECTOR_REGISTRY_DEFAULT == NULL) {
    prom_collector_registry_t *r = calloc(1, sizeof(*r));
    if (r == NULL || pthread_mutex_init(&r->mutex, NULL) != 0) {
      free(r);
      rc = 1;
    } else {
      PROM_COLLECTOR_REGISTRY_DEFAULT = r;
    }
  }
  pthread_mutex_unlock(&g_default_init_mutex);
  return rc;
}

prom_metric_t *prom_collector_registry_must_register_metric(prom_metric_t *metric) {
  if (metric == NULL) {
    return NULL;
  }
  prom_collector_registry_t *r = PROM_COLLECTOR_REGISTRY_DEFAULT;
  if (r == NULL) {
    /* Match upstream's "must" contract: a registration failure is fatal. */
    fprintf(stderr, "prom: default registry not initialized before registering '%s'\n", metric->name);
    prom_metric_destroy(metric);
    abort();
  }
  pthread_mutex_lock(&r->mutex);
  metric->next = r->metrics;
  r->metrics = metric;
  pthread_mutex_unlock(&r->mutex);
  return metric;
}

/* -------------------------------------------------------------------------- */
/* Text exposition format                                                     */
/* -------------------------------------------------------------------------- */

typedef struct {
  char *data;
  size_t len;
  size_t cap;
  int oom;
} prom_buf_t;

static void prom_buf_append(prom_buf_t *b, const char *s, size_t n) {
  if (b->oom) {
    return;
  }
  if (b->len + n + 1 > b->cap) {
    size_t cap = b->cap ? b->cap : 4096;
    while (b->len + n + 1 > cap) {
      cap *= 2;
    }
    char *p = realloc(b->data, cap);
    if (p == NULL) {
      b->oom = 1;
      return;
    }
    b->data = p;
    b->cap = cap;
  }
  memcpy(b->data + b->len, s, n);
  b->len += n;
  b->data[b->len] = '\0';
}

static void prom_buf_append_str(prom_buf_t *b, const char *s) { prom_buf_append(b, s, strlen(s)); }

/* Escape a label value per the Prometheus text format: backslash, double-quote
 * and newline are escaped; everything else passes through. */
static void prom_buf_append_label_value(prom_buf_t *b, const char *s) {
  for (const char *p = s != NULL ? s : ""; *p != '\0'; p++) {
    switch (*p) {
    case '\\':
      prom_buf_append(b, "\\\\", 2);
      break;
    case '"':
      prom_buf_append(b, "\\\"", 2);
      break;
    case '\n':
      prom_buf_append(b, "\\n", 2);
      break;
    default:
      prom_buf_append(b, p, 1);
      break;
    }
  }
}

static void prom_buf_append_value(prom_buf_t *b, double v) {
  char tmp[64];
  int n;
  /* Print integral values within a double's exact-integer range (2^53) without
   * a fractional part for clean, exact output of packet/byte counters; fall
   * back to %g for the rare fractional gauge or an out-of-range/NaN value.
   * Integrality is tested with a round-trip cast so no <math.h> (and no libm
   * link) is needed. */
  if (v >= -9007199254740992.0 && v <= 9007199254740992.0 && v == (double)(long long)v) {
    n = snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
  } else {
    n = snprintf(tmp, sizeof(tmp), "%g", v);
  }
  if (n > 0) {
    prom_buf_append(b, tmp, (size_t)n);
  }
}

static void prom_metric_render(prom_buf_t *b, prom_metric_t *m) {
  const char *type_str = (m->type == PROM_COUNTER) ? "counter" : "gauge";

  prom_buf_append_str(b, "# HELP ");
  prom_buf_append_str(b, m->name);
  prom_buf_append(b, " ", 1);
  prom_buf_append_str(b, m->help);
  prom_buf_append(b, "\n", 1);

  prom_buf_append_str(b, "# TYPE ");
  prom_buf_append_str(b, m->name);
  prom_buf_append(b, " ", 1);
  prom_buf_append_str(b, type_str);
  prom_buf_append(b, "\n", 1);

  pthread_mutex_lock(&m->mutex);
  for (prom_sample_t *s = m->samples; s != NULL; s = s->next) {
    prom_buf_append_str(b, m->name);
    if (m->label_count > 0) {
      prom_buf_append(b, "{", 1);
      for (size_t i = 0; i < m->label_count; i++) {
        if (i > 0) {
          prom_buf_append(b, ",", 1);
        }
        prom_buf_append_str(b, m->label_keys[i]);
        prom_buf_append(b, "=\"", 2);
        prom_buf_append_label_value(b, s->label_values != NULL ? s->label_values[i] : "");
        prom_buf_append(b, "\"", 1);
      }
      prom_buf_append(b, "}", 1);
    }
    prom_buf_append(b, " ", 1);
    prom_buf_append_value(b, s->value);
    prom_buf_append(b, "\n", 1);
  }
  pthread_mutex_unlock(&m->mutex);
}

char *prom_collector_registry_bridge(prom_collector_registry_t *registry) {
  if (registry == NULL) {
    return NULL;
  }

  prom_buf_t b = {0};

  /* Render in registration order. Metrics are prepended on register, so walk a
   * reversed snapshot of the list to keep output stable across scrapes. */
  pthread_mutex_lock(&registry->mutex);
  size_t count = 0;
  for (prom_metric_t *m = registry->metrics; m != NULL; m = m->next) {
    count++;
  }
  prom_metric_t **ordered = count ? calloc(count, sizeof(*ordered)) : NULL;
  if (count && ordered == NULL) {
    pthread_mutex_unlock(&registry->mutex);
    return NULL;
  }
  size_t idx = count;
  for (prom_metric_t *m = registry->metrics; m != NULL; m = m->next) {
    ordered[--idx] = m;
  }
  pthread_mutex_unlock(&registry->mutex);

  for (size_t i = 0; i < count; i++) {
    prom_metric_render(&b, ordered[i]);
  }
  free(ordered);

  if (b.oom) {
    free(b.data);
    return NULL;
  }
  if (b.data == NULL) {
    /* No metrics registered: still return a valid empty, freeable string. */
    b.data = prom_strdup("");
  }
  return b.data;
}
