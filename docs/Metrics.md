# Introduction

The option **--prom** enables more or less coarse grained data collection for
life monitoring the the running turnserver instances - per default one per
CPU thread or strand or whatever is configured via the option **relay-threads**.
The label pair **tid="inctanceNumber"** allows one to determine, to which
turnserver instance the related metric is associated.

Just monitoring at turnserver instance level is pretty save wrt. to the number
of generated metrics and the thread, which generates and delivers the related
report formatted as plain text in the
[Prometheus/OpenMetrics exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/)
via **http://your-turnserver.do.main/metrics** . Collecting the data itself
is pretty light weight (just atomic add, sub, or set). The related metrics are described in the next section.

# Metrics

## version
The TURN server software name and version.

## bind\_requests
The number of valid STUN binding requests (RFC 5780) a turnserver instance
received so far.  If a binding request contains one or more unrecognized
attributes, or other errors (see below), it gets counted via bind\_errors,
not here. If `no-stun-backward-compatibility` is set, old STUN binding requests
are ignored and thus not counted. If `no-stun` is set, all STUN binding
requests are ignored and thus not counted, excluded from reports.

## bind\_responses
The number of STUN binding responses to valid STUN binding requests (RFC 5780)
the turnserver instance sent so far. It obviously gets sent only if the related
request had no errors and a proper answer could be constructed. The response
gets counted as soon as it has been put into the server's "sent-queue", i.e.
takes not into account, whether the delivery was successful. Excluded from
reports if `no-stun` is set.


## bind\_errors
The number of errors related to STUN binding occurred so far. The label pair
**code="number"** can be used to distinguish the errors. The error codes used
so far are:
  - 420
    - unknown attribute
    - Unknown attribute: TURN server was configured without RFC 5780 support
  - 400
    - wrong response format
    - Wrong request: applicable only to UDP protocol
    - Wrong request format: you cannot use PADDING and RESPONSE\_PORT together
    - Wrong request: padding applicable only to UDP and DTLS protocols

NOTE: If no binding errors occured so far, excluded from reports.

## rx\_msgs, rx\_bytes
Messages and bytes received from turn clients or peers. The label pair
**peer="value"** is used to specify, whether the metric refers to
the turn client (`0`) or the the peer (`1`).

## tx\_msgs, tx\_bytes
Messages and bytes sent to turn clients or peers. The label pair
**peer="value"** is used to specify, whether the metric refers to
to the turn client (`0`) or the the peer (`1`).

## allocations
The number of created allocations (label `created="1"`) and the number of
active, i.e. not yet deleted allocations (label `created="0"`).  Wrt. to the
turnserver this is usually what matters and since there is a 1:1 relation to
the owning session, sessions are not yet tracked in a separate metric. But
note, that a session may exists without a [not yet created] allocation.

## lifetime
The lifetime of current allocations in seconds. This metric gets automatically
enabled, if monitoring at the session level is enabled (at turnserver level it
does not make any sense). Because per contract there is max. one allocation
between a client and the turnserver, and the allocation is always related to
the session between both, the related allocation can be identified by the
**tid="inctanceNumber"** and **"sid=sessionID"**. When an allocation gets
deleted (usually when the session gets closed), the lifetime is set to `-1`
to get a marker for the allocation/session end.

## session\_state
The current state of a session. This metric gets automatically enabled, if
monitoring at the session level is enabled (at turnserver level it does not
make any sense). Sessions can be
distinguished by the labels **tid="inctanceNumber"** and **"sid=sessionID"**.
The metric value denotes the following states:
  - 0 .. session is closed.
  - 1 .. allocation got deleted. Because this usually happen on a session
    shutdown, and the time between an allocation got deleted and the session
    closed is very short, you probably will not see it very often.
  - 2 .. session shutdown initiated. Because the time between the shutdown init
    and the session end is very short, you probably will not see it very often.
  - 3 .. session is open, however no allocation request has been seen so far.
  - 4 .  an allocation got created, however, no refresh for it has been seen
    so far. The **lifetime** metric can be used to check the allocation's
    lifetime in seconds.
  - 5 .. an allocation exist and has been refreshed by the client at least once.
    On each refresh the related **lifetime** metric gets an update.

## process\_\*
For now 17 metrics about the coturn process itself. Most relevant are probably
the total number of threads (threads\_total), the physical RAM in use
(resident\_memory\_bytes), and the number of open file descriptors (open\_fds)
vs. the maximum number of  open file descriptors (max\_fds). If they are too
close, you may adjust this limit by adding e.g. `LimitNOFILE=64535` to the
`[Service]` section of the systemd service or using `ulimit -S -n 64535` in
your coturn service startup script. Last but not least: if there are too many
major page faults (major\_pagefaults) there might be a memory related problem
on the box running the app.

## scrape\_duration\_seconds
The metric labeled with `collector="default"` reports how long it took to collect
and format the turnserver related metrics (i.e. all except `process` and
`scrape_duration_seconds`). If this takes longer than 1 second, you probably
have either a "too many metrics" or "not enough CPU resources" problem.

The metric labeled `collector="process"` reports how long it took to collect
and format the coturn process related data exposed via the `process_*` metrics.

Last but not least the `collector="libprom"` tells you, how long it took to
collect the reports from all other collectors (default and process) and to
create the final report exposed via HTTP.

## Summary
So monitoring at turnserver level (the default) produces max.
`1 + (1 + 1 + 2 + 2*2 + 2*2 + 2) * relay-threads + 17 + 3 = 14 * relay-threads + 21`
metrics.
This means for a box with 2x Xeon(R) CPU E5-2690 v4 per default max.
`56 * 14 + 21 = 805` metrics.
This is not a big deal and easy to handle by the coturn application as
well as metrics agents like VictoriaMetric's vmagent or Prometheus, 
time series databases like VictoriaMetric's vmdb or Prometheus Mimir, and
visualizers like Grafana or Netdata. Should be also sufficient to monitor
the health of your coturn applications.


# Metrics at session level
Logging at session level may help:
  - in development to debug traffic issues
  - to understand your traffic patterns
  - to discover bottlenecks
  - support better troubleshooting

Using the option **--prom-uniq-sid** or **--prom-sid** enables monitoring
at the session label. The difference between both options is, that `--prom-sid`
recycles used session IDs by putting the session IDs of closed session back
into a pool and tries to reuse them for new sessions after a certain time has
passed (see option **--prom-sid-retain**).

If any of the sid options is enabled, the **session\_state** and **lifetime**
metrics get enabled automatically and all metrics get a **"sid=sessionID"**
label pair. This means the max. number of metrics is now for `--prom-sid`:
`21 + (14 + 2) * relay-threads * sum(countPerPool(unique(sessionIDs)))/relay-threads`
or assuming that coturn distributes requests/sessions evenly over the running
relay-threads as rule of thumb:
`21 + 16 * relay-threads * averageSessionIdPoolSize` or
`21 + 16 * relay-threads * max(concurrentSessionsAtATime)`
and for `--prom-uniq-sid`:
`21 + 16 * relay-threads * all_sessions_handled_so_far_by_the_app`.

So it is pretty obvious, that these options possibly open the door for
**DoS attacks**!  Therefore one should think at least twice and understand
the impact on produced metrics as described below, before using it. Having a
pretty good control over the clients (authentication, session frequency,
kindness of your clients) may help as well ;-).

If enabled, it is certainly a good idea to setup an alert manager, which
monitors the scrapetime or size of the metrics reports and alerts you, if it
takes too long or gets too big, which indicates that there are probably too
many metrics and may get you into trouble. In case you monitor the coturn log,
watch out for entries containing `grew rsid pool`: `maxId` says, how many
unique session IDs the relay-thread with id `tid` has seen so far. So the
current number of metrics for this thread is about `16 * maxSid`.

BTW: Usually a separate single thread per request generates and delivers the
metric report (using libmicrohttp), not the turnserver threads themselves.
However, it needs some CPU cycles to get the work done and thus may have an
impact on other tasks running on the box, if CPU resources are not sufficient.

Anyway, as you deduce from the calculations above, one should definitely avoid
using the `--prom-uniq-sid` option unless you really know, what you are doing.
If you really need it, enable it only for the time needed and make sure, that
scraping agents use a separate time series DB or storage place, where the
metrics data can be easily discarded, when the work is done and have
not really an impact on your other services in production.

## Tuning
As already said, to mitigate a possible "too many metrics" problem, the option
**--prom-sid** got introduced, which basically uses a dynamic pool of session
IDs per turnserver instance, where the IDs of closed sessions get put back and
reused by new sessions. So if you have per average only 100 sessions or
allocations concurrently running, it would result at least into
`56 * 16 * ceil(100/40)) + 21 = 2709` metrics.
Still easy to handle by coturn and not really a problem for report collectors,
time series DBs and visualizers.
**BUT** if one decides to challenge your server,
the numbers may change dramatically. So there might be a desire to adjust the
time a session ID has to stay in the ID pool before it can be reused.  The
option **--prom-sid-retain=num** allows you to adjust this parameter measured
in seconds. For now it defaults to 60 - a more or less conservative value,
depending on the environment. To get a feeling, how it works out for you,
the following test may reveal data for more or less proper settings:

## Testing
- setup a coturn test instance
- ensure that `lt-cred-mech` is enabled and no other mechanism
- ensure that a realm is configured, e.g. `realm = test.do.main`
- set `relay-threads = 5`
- add a user to the coturn db you wanna use for your tests, e.g. if you have
  `userdb=/data/coturn/db` set, use:
  `turnadmin -a -b /data/coturn/db -u foo -p bar -r test.do.main`
- make sure, your firewall allows the related traffic on the server as well
  as the client zone/container.
- run the test on the client machine, e.g.:
  `time turnutils_uclient -p 3478 -DgXv -y -c -u foo -w bar -m 40 server_hostname`.
  If you have changed the `listening-port`, adjust the `-p` option accordingly.
  Only simulate as many clients as CPU threads/strands are available on the
  client machine (option `-m`).
- when finished:
    - have a look at the log file (defaults to /var/log/coturn.log)
    - get the metrics report, e.g. `curl -o /tmp/report.om http://localhost:9641/metrics`
    - to find out the number of metrics and size of the report, one may run:
      `grep ^coturn_ /tmp/report.om |wc -lc`. The first number in the output
      is the number of lines and thus number of metrics in the report, the
      2nd number is the size of the report without any `# TYPE` or `# HELP`
      comments.
    - to find out, how many bytes you can drop from transmission of each report
      using the option **--prom-compact**, one may run:
      `grep -v ^coturn_ /tmp/report.om |wc -lc`.

- you may also try the same test using an invalid password or running a test
  peer e.g. on machineC (`turnutils_peer -v -p 16384`) and add the options
  `-e machineC -r 16384`to the `turnutils_uclient` command.


# Misc options

## **--prom-compact**
Should be used on all production systems to avoid the inclusion of the `HELP`
and `TYPE` comments for each metric in each report.
Usually it is sufficient to get and record them once, when a demo is required
or Grafana charts get setup. There is no need to send them again and again in
each report - would just waste bandwidth and demands more resources to parse
and process the report. At least on production systems it is recommended to
enable this option.

## **--prom-realm**
Label the `session_state` metric with the session realm. If one uses different
realms for user authentication it could make sense to add a realm label, so one
may select the interested time series by the realm. If you only use one and the
same realm it is usually just overhead and should be skipped. Because rarely
used, it is not taken into account in the calculations of number of metrics
above.

## **--prom-usernames**
Label the `session_state` metric with client usernames. One should not do this,
unless really needed: Modern apps often generate usernames on the fly (e.g.
hash(currentTimeAsString + `:` + username)) and thus all the names are
different or even unique for a long time. This in turn means, that a new state
metric gets created for each new session. This stresses the server resources
the same way as `--prom-uniq-sid` does, because a sample for each metric gets
kept in memory and needs to be formatted and transferred on each /metric
request. When the report gets collected and stored in a time series DB, this
would in turn create a new time series for each new session
(metricName + label:value pairs form the key for a time series) and would let
your DB "explode", get it performance and resource wise probably into trouble,
because it has to dig into such a huge set of time series (high cardinality)
and replace "active/cached" ones (high churn rate). So do NOT use it, unless
you known what you are doing!


# More Information
More information related to labels and cardinality can be found e.g. via:
- https://docs.victoriametrics.com/keyConcepts.html
- https://docs.victoriametrics.com/FAQ.html#what-is-high-cardinality
- https://docs.victoriametrics.com/FAQ.html#what-is-high-churn-rate

