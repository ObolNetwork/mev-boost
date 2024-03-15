package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds Prometheus metrics handles.
type Metrics struct {
	path     string
	bindAddr string

	registerValidatorTime   *prometheus.HistogramVec
	failedRegisterValidator *prometheus.GaugeVec

	getHeaderTime   *prometheus.HistogramVec
	failedGetHeader *prometheus.GaugeVec

	getPayloadTime   *prometheus.HistogramVec
	failedGetPayload *prometheus.GaugeVec
}

// RunMetrics runs a Prometheus metrics server at the given path, on the given bind address.
// This function blocks forever, unless there is an error.
func (m *Metrics) Run() error {
	m.registerMetrics()

	http.Handle(m.path, promhttp.Handler())
	err := http.ListenAndServe(m.bindAddr, nil)

	if err != nil {
		return err
	}

	return nil
}

func (m *Metrics) registerMetrics() {
	const namespace string = "mev_boost"

	m.registerValidatorTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "register_validator",
		Help:      "Time elapsed for each registerValidator call, indexed by relay.",
	}, []string{"relay"})

	m.failedRegisterValidator = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "failed_register_validator",
		Help:      "Count of all the failed attepts to register a validator, indexed by relay",
	}, []string{"relay"})

	m.getHeaderTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "get_header",
		Help:      "Time elapsed for each getHeader call, indexed by relay, validator public key and slot.",
	}, []string{"relay", "validator_pubkey"})

	m.failedGetHeader = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "failed_get_header",
		Help:      "Count of all the failed attepts to getHeader, indexed by relay, at the boundary of the HTTP relay call (not counting bad data, etc).",
	}, []string{"relay"})

	m.getPayloadTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "get_payload",
		Help:      "Time elapsed for each getPayload call, indexed by relay, hardfork, and slot.",
	}, []string{"relay", "hardfork"})

	m.failedGetPayload = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "failed_get_payload",
		Help:      "Count of all the failed attepts to getPayload, indexed by relay, at the boundary of the HTTP relay call (not counting bad data, etc).",
	}, []string{"relay", "hardfork"})
}
