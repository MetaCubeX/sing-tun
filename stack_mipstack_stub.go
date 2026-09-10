//go:build !with_mipstack

package tun

import E "github.com/metacubex/sing/common/exceptions"

const WithMIPStack = false

var ErrMIPStackNotIncluded = E.New("mipstack is not included in this build, rebuild with -tags with_mipstack")

func NewMIPStack(options StackOptions) (Stack, error) {
	return nil, ErrMIPStackNotIncluded
}
