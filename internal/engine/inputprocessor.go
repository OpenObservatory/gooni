package engine

import (
	"context"

	"github.com/ooni/probe-cli/v3/internal/engine/model"
)

// InputProcessorExperiment is the Experiment
// according to InputProcessor.
type InputProcessorExperiment interface {
	MeasureWithContext(
		ctx context.Context, input string) (*model.Measurement, error)
}

// InputProcessorExperimentWrapper is a wrapper for an
// Experiment that also allow to pass around the input index.
type InputProcessorExperimentWrapper interface {
	MeasureWithContext(
		ctx context.Context, idx int, input string) (*model.Measurement, error)
}

// NewInputProcessorExperimentWrapper creates a new
// instance of InputProcessorExperimentWrapper.
func NewInputProcessorExperimentWrapper(
	exp InputProcessorExperiment) InputProcessorExperimentWrapper {
	return inputProcessorExperimentWrapper{exp: exp}
}

type inputProcessorExperimentWrapper struct {
	exp InputProcessorExperiment
}

func (ipew inputProcessorExperimentWrapper) MeasureWithContext(
	ctx context.Context, idx int, input string) (*model.Measurement, error) {
	return ipew.exp.MeasureWithContext(ctx, input)
}

var _ InputProcessorExperimentWrapper = inputProcessorExperimentWrapper{}

// InputProcessor processes inputs. We perform a Measurement
// for each input using the given Experiment.
type InputProcessor struct {
	// Annotations contains the measurement annotations
	Annotations map[string]string

	// Experiment is the code that will run the experiment.
	Experiment InputProcessorExperimentWrapper

	// Inputs is the list of inputs to measure.
	Inputs []model.URLInfo

	// Options contains command line options for this experiment.
	Options []string

	// Saver is the code that will save measurement results
	// on persistent storage (e.g. the file system).
	Saver InputProcessorSaverWrapper

	// Submitter is the code that will submit measurements
	// to the OONI collector.
	Submitter InputProcessorSubmitterWrapper
}

// InputProcessorSaverWrapper is InputProcessor's
// wrapper for a Saver implementation.
type InputProcessorSaverWrapper interface {
	SaveMeasurement(idx int, m *model.Measurement) error
}

type inputProcessorSaverWrapper struct {
	saver Saver
}

// NewInputProcessorSaverWrapper wraps a Saver for InputProcessor.
func NewInputProcessorSaverWrapper(saver Saver) InputProcessorSaverWrapper {
	return inputProcessorSaverWrapper{saver: saver}
}

func (ipsw inputProcessorSaverWrapper) SaveMeasurement(
	idx int, m *model.Measurement) error {
	return ipsw.saver.SaveMeasurement(m)
}

// InputProcessorSubmitterWrapper is InputProcessor's
// wrapper for a Submitter implementation.
type InputProcessorSubmitterWrapper interface {
	Submit(ctx context.Context, idx int, m *model.Measurement) error
}

type inputProcessorSubmitterWrapper struct {
	submitter Submitter
}

// NewInputProcessorSubmitterWrapper wraps a Submitter
// for the InputProcessor.
func NewInputProcessorSubmitterWrapper(submitter Submitter) InputProcessorSubmitterWrapper {
	return inputProcessorSubmitterWrapper{submitter: submitter}
}

func (ipsw inputProcessorSubmitterWrapper) Submit(
	ctx context.Context, idx int, m *model.Measurement) error {
	return ipsw.submitter.Submit(ctx, m)
}

// Run processes all the input subject to the duration of the
// context. The code will perform measurements using the given
// experiment; submit measurements using the given submitter;
// save measurements using the given saver.
//
// Annotations and Options will be saved in the measurement.
//
// The default behaviour of this code is that an error while
// measuring, while submitting, or while saving a measurement
// is always causing us to break out of the loop. The user
// though is free to choose different policies by configuring
// the Experiment, Submitter, and Saver fields properly.
func (ip InputProcessor) Run(ctx context.Context) error {
	for idx, url := range ip.Inputs {
		input := url.URL
		meas, err := ip.Experiment.MeasureWithContext(ctx, idx, input)
		if err != nil {
			return err
		}
		meas.AddAnnotations(ip.Annotations)
		meas.Options = ip.Options
		err = ip.Submitter.Submit(ctx, idx, meas)
		if err != nil {
			return err
		}
		// Note: must be after submission because submission modifies
		// the measurement to include the report ID.
		err = ip.Saver.SaveMeasurement(idx, meas)
		if err != nil {
			return err
		}
	}
	return nil
}
