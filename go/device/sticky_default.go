//go:build !linux

package device

import (
	"github.com/ivlev-dev/umbrawg/go/conn"
	"github.com/ivlev-dev/umbrawg/go/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
