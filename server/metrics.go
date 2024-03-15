package server

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds Prometheus metrics handles.
type Metrics struct {
	path     string
	bindAddr string

	registry *prometheus.Registry

	registerValidatorTime   *prometheus.HistogramVec
	failedRegisterValidator *prometheus.GaugeVec

	getHeaderTime   *prometheus.HistogramVec
	failedGetHeader *prometheus.GaugeVec

	getPayloadTime   *prometheus.HistogramVec
	failedGetPayload *prometheus.GaugeVec
}

// NewMetricsServer returns a new Metrics instance with the given path and bind address.
func NewMetricsServer(path string, bindAddr string) (*Metrics, error) {
	m := &Metrics{
		path:     path,
		bindAddr: bindAddr,
	}

	if err := m.registerMetrics(); err != nil {
		return nil, fmt.Errorf("can't register metric, %w", err)
	}

	return m, nil
}

// Run runs a Prometheus metrics server at the given path, on the given bind address.
// This function blocks forever, unless there is an error.
func (m *Metrics) Run() error {
	if m.bindAddr == "" {
		return nil // don't run metrics if no bind address is provided
	}

	metricsHandler := promhttp.InstrumentMetricHandler(
		m.registry, promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
			Registry: m.registry,
		}),
	)

	server := http.NewServeMux()
	server.Handle(m.path, metricsHandler)

	err := http.ListenAndServe(m.bindAddr, server)

	if err != nil {
		return err
	}

	return nil
}

func (m *Metrics) registerMetrics() error {
	const namespace string = "mev_boost"

	m.registry = prometheus.NewRegistry()

	factory := promauto.With(m.registry)

	err := m.registry.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if err != nil {
		return fmt.Errorf("register process collector, %w", err)
	}

	err = m.registry.Register(collectors.NewGoCollector())
	if err != nil {
		return fmt.Errorf("register go collector, %w", err)
	}

	m.registerValidatorTime = factory.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "register_validator",
		Help:      "Time elapsed for each registerValidator call, indexed by relay.",
	}, []string{"relay"})

	m.failedRegisterValidator = factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "failed_register_validator",
		Help:      "Count of all the failed attepts to register a validator, indexed by relay",
	}, []string{"relay"})

	m.getHeaderTime = factory.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "get_header",
		Help:      "Time elapsed for each getHeader call, indexed by relay, validator public key and slot.",
	}, []string{"relay", "validator_pubkey"})

	m.failedGetHeader = factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "failed_get_header",
		Help:      "Count of all the failed attepts to getHeader, indexed by relay, at the boundary of the HTTP relay call (not counting bad data, etc).",
	}, []string{"relay"})

	m.getPayloadTime = factory.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "get_payload",
		Help:      "Time elapsed for each getPayload call, indexed by relay, hardfork, and slot.",
	}, []string{"relay", "hardfork"})

	m.failedGetPayload = factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "failed_get_payload",
		Help:      "Count of all the failed attepts to getPayload, indexed by relay, at the boundary of the HTTP relay call (not counting bad data, etc).",
	}, []string{"relay", "hardfork"})

	return nil
}
