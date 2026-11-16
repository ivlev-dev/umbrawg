//go:build !linux

package device

import (
	"github.com/ivlev-dev/umbrawg-rs/conn"
	"github.com/ivlev-dev/umbrawg-rs/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
