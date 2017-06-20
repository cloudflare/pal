package trustedlabels

// A Retriever is a type capable of looking up the docker image labels for a
// given PID. In other words, if a docker image, I, is used to launch a
// container, C, and that container contains a process with PID P, then calling
// LabelsForPID(P) will return all of the labels associated with I.
type Retriever interface {
	LabelsForPID(pid int) (map[string]struct{}, error)
}

type mock struct {
	labels map[string]struct{}
}

// NewMock returns a mocked Retriever which always responds with the given set
// of labels to any request.
func NewMock(labels map[string]struct{}) Retriever {
	return &mock{labels: labels}
}

func (m *mock) LabelsForPID(int) (map[string]struct{}, error) {
	return m.labels, nil
}
