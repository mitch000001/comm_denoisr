package distribution

import (
	"io"
)

type DistributionChannel interface {
	Sender
	Receiver
}

type Sender interface {
	Send(io.Reader) (string, error)
}

type Receiver interface {
	Receive() ([]io.Reader, error)
}

type composedDistributionChannel struct {
	Sender
	Receiver
}

func NewDistributionChannel(sender Sender, receiver Receiver) DistributionChannel {
	return &composedDistributionChannel{sender, receiver}
}
