# deus

> [!WARNING]
> I'm not a security engineer--this was half a learning exercise! `deus` is not recommended for production use, nor to replace `sudo` or `doas` without formal security review & scrutiny.

![Tuor meeting the Vala Ulmo - by Ted Nasmith](./deus.webp)

`deus` is a setuid tool to execute commands as another user, similar to Ted Unangst's `doas` or the venerable `sudo`. It is specifically made for Linux.

## How to use

```
deus [-s] [-C config] [-u user] command [args]
```

Rules are in `/etc/deus.conf`:

```ini
users = michael zora userthree
groups = wheel
keepenv = WAYLAND_DISPLAY EDITOR
```

Full documentation can be found in `deus(1)`, `deus.conf(5)`.

## Why another tool?

### Compared to `sudo`

`deus` is incredibly simple; intentional *anti-features* are NSS support and anything else not intended for single-user workstations, which makes the attack surface *much smaller*.

### Compared to `doas`

`deus` is written in Rust, officially supports Linux, and reuses code where possible from the `sudo-rs` project (which has been independently security reviewed).

`deus` is simpler than `doas`.

## TODO

- `deus` currently does not support timestamping; thus, you need to authenticate
  every time.

- `deus` should have a more robust testing framework, ala "integration tests."

## Acknowledgements

`deus` is distributed under the GPL-3.0 license, and is a heavily modified fork
of the [rsudoas](https://github.com/DcodingTheWeb/rsudoas) project.

```
deus - Privilege escalation utility

Copyright (c) 2015 Ted Unangst
Copyright (c) 2015 Nathan Holstein
Copyright (c) 2016 Duncan Overbruck
Copyright (c) 2023 TheDcoder <TheDcoder@protonmail.com>
Copyright (c) 2022-2024 Trifecta Tech Foundation
Copyright (c) 2025 Michael Bullington

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
