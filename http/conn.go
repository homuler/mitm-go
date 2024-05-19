// Copyright (c) 2024 homuler
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package http

import (
	"net"
	"net/url"

	"github.com/homuler/mitm-go"
)

func NewURLAddr(network string, u *url.URL) net.Addr {
	return mitm.NewAddr(network, u.Host)
}
