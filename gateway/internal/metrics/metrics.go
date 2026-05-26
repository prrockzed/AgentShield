package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	RunsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentshield_runs_total",
		Help: "Total agent runs by status and agent_type.",
	}, []string{"status", "agent_type"})

	SecurityEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentshield_security_events_total",
		Help: "Total security events by event_type, decision, severity.",
	}, []string{"event_type", "decision", "severity"})

	RunDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "agentshield_run_duration_seconds",
		Help:    "Histogram of agent run execution time in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	SandboxActiveCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "agentshield_sandbox_active_count",
		Help: "Number of agent runs currently in flight.",
	})

	ThreatsBlockedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentshield_threats_blocked_total",
		Help: "Total blocked threats by category.",
	}, []string{"category"})

	PromptInjectionScore = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "agentshield_prompt_injection_score",
		Help:    "Histogram of prompt injection scores (0-1).",
		Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
	})

	DlpDetectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentshield_dlp_detections_total",
		Help: "Total DLP detections by category type.",
	}, []string{"type"})

	RedteamPassRate = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "agentshield_redteam_pass_rate",
		Help: "Latest red-team suite pass rate (0-1).",
	})
)

func Register() {
	prometheus.MustRegister(
		RunsTotal, SecurityEventsTotal, RunDurationSeconds,
		SandboxActiveCount, ThreatsBlockedTotal, PromptInjectionScore,
		DlpDetectionsTotal, RedteamPassRate,
	)
}
