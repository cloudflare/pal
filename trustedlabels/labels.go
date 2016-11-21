package trustedlabels

// Retriever allows user to retrieve trusted labels for a container
type Retriever interface {
	// LabelsForPID allows caller to retrieve labels associated with a PID. The PID
	// must belongs to a process inside a running container and is usually pid 1
	// inside the container namespace.
	LabelsForPID(pid int) (map[string]struct{}, error)
}
