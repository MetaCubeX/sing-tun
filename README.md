# sing-tun

Simple transparent proxy library.

For Linux, Windows, macOS and iOS.

## Optional mipstack backend

Build with `-tags with_mipstack` to enable the pure-Go
[mipstack](https://github.com/MetaCubeX/mipstack) backend, then select it with
`NewStack("mipstack", options)` (or call `NewMIPStack(options)` directly).
Call `Start()` on the returned stack after construction. Without the build tag,
selecting this backend returns `ErrMIPStackNotIncluded`.

The tag can be combined with `with_gvisor`; the default stack selection and the
existing `system`, `gvisor`, and `mixed` modes are unchanged.


## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```
