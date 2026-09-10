//go:build !with_mipstack

package tun

import (
	"errors"
	"testing"
)

func TestMIPStackNotIncluded(t *testing.T) {
	stack, err := NewStack("mipstack", StackOptions{})
	if stack != nil || !errors.Is(err, ErrMIPStackNotIncluded) || WithMIPStack {
		t.Fatalf("unexpected result: stack=%v err=%v included=%v", stack, err, WithMIPStack)
	}
}
