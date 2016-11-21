package trustedlabels

// Mocker contains a mock implementation of Retriever. This is only useful in testing.
type Mocker struct {
	labels map[string]struct{}
}

func NewMocker(labels map[string]struct{}) *Mocker {
	return &Mocker{labels: labels}
}

func (m *Mocker) LabelsForPID(int) (map[string]struct{}, error) {
	return m.labels, nil
}
