// Package metrics exposes runtime counters for Prometheus scraping.
//
// All metrics are no-ops when the metrics server is disabled — callers can
// unconditionally increment counters without checking the enabled flag.
// The HTTP server is only started when Serve() is called explicitly.
//
// This package uses a standalone registry to avoid polluting the default
// prometheus.DefaultRegisterer with duplicates in test scenarios.
package metrics

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
)

var (
	flowsScoredCritical atomic.Int64
	flowsScoredHigh     atomic.Int64
	flowsScoredMedium   atomic.Int64
	flowsScoredLow      atomic.Int64
	flowsScoredClean    atomic.Int64
	alertsFiredTotal    atomic.Int64
	webhookFailures     atomic.Int64
	droppedPackets      atomic.Int64
	windowDurationsSum  atomic.Int64 // milliseconds
	windowDurationsN    atomic.Int64

	serverOnce sync.Once
)

// RecordFlows increments per-risk-level flow counters.
func RecordFlows(critical, high, medium, low, clean int) {
	flowsScoredCritical.Add(int64(critical))
	flowsScoredHigh.Add(int64(high))
	flowsScoredMedium.Add(int64(medium))
	flowsScoredLow.Add(int64(low))
	flowsScoredClean.Add(int64(clean))
}

// RecordAlert increments the alerts-fired counter.
func RecordAlert() { alertsFiredTotal.Add(1) }

// RecordWebhookFailure increments the webhook failure counter.
func RecordWebhookFailure() { webhookFailures.Add(1) }

// RecordDroppedPackets sets the dropped-packets gauge to the given value.
func RecordDroppedPackets(n uint64) { droppedPackets.Store(int64(n)) }

// RecordWindowDuration records a capture-window duration in milliseconds.
func RecordWindowDuration(ms int64) {
	windowDurationsSum.Add(ms)
	windowDurationsN.Add(1)
}

// Serve starts the /metrics HTTP server on addr. It is idempotent — only the
// first call has effect. The server runs in a background goroutine.
func Serve(addr string) {
	serverOnce.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", handleMetrics)
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		srv := &http.Server{Addr: addr, Handler: mux}
		go func() {
			log.Printf("metrics: serving Prometheus metrics on http://%s/metrics", addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("metrics: server error: %v", err)
			}
		}()
	})
}

// handleMetrics writes counters in Prometheus text exposition format.
func handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	critical := flowsScoredCritical.Load()
	high := flowsScoredHigh.Load()
	medium := flowsScoredMedium.Load()
	low := flowsScoredLow.Load()
	clean := flowsScoredClean.Load()
	total := critical + high + medium + low + clean

	durN := windowDurationsN.Load()
	var avgDurMs int64
	if durN > 0 {
		avgDurMs = windowDurationsSum.Load() / durN
	}

	fmt.Fprintf(w, `# HELP flowsentinel_flows_scored_total Total flows scored by risk level.
# TYPE flowsentinel_flows_scored_total counter
flowsentinel_flows_scored_total{risk_level="critical"} %d
flowsentinel_flows_scored_total{risk_level="high"} %d
flowsentinel_flows_scored_total{risk_level="medium"} %d
flowsentinel_flows_scored_total{risk_level="low"} %d
flowsentinel_flows_scored_total{risk_level="clean"} %d
flowsentinel_flows_scored_total{risk_level="all"} %d
# HELP flowsentinel_alerts_fired_total Total webhook alerts fired since startup.
# TYPE flowsentinel_alerts_fired_total counter
flowsentinel_alerts_fired_total %d
# HELP flowsentinel_webhook_failures_total Total webhook deliveries that failed all retries.
# TYPE flowsentinel_webhook_failures_total counter
flowsentinel_webhook_failures_total %d
# HELP flowsentinel_dropped_packets_total Packets dropped by the kernel pcap ring buffer.
# TYPE flowsentinel_dropped_packets_total gauge
flowsentinel_dropped_packets_total %d
# HELP flowsentinel_capture_window_duration_ms_avg Average capture window duration in milliseconds.
# TYPE flowsentinel_capture_window_duration_ms_avg gauge
flowsentinel_capture_window_duration_ms_avg %d
# HELP flowsentinel_capture_windows_total Total capture windows completed.
# TYPE flowsentinel_capture_windows_total counter
flowsentinel_capture_windows_total %d
`,
		critical, high, medium, low, clean, total,
		alertsFiredTotal.Load(),
		webhookFailures.Load(),
		droppedPackets.Load(),
		avgDurMs,
		durN,
	)
}
