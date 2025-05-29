deus.conf(5)

; Copyright (c) 2015 Ted Unangst
; Copyright (c) 2015 Nathan Holstein
; Copyright (c) 2016 Duncan Overbruck
; Copyright (c) 2023 TheDcoder <TheDcoder@protonmail.com>
; Copyright (c) 2022-2024 Trifecta Tech Foundation
; Copyright (c) 2025 Michael Bullington
; 
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
; 
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
; 
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <https://www.gnu.org/licenses/>.

# NAME

deus.conf - deus configuration file

# EXAMPLES

The following example permits user _aja_ and group _wheel_ to use deus(1);
while forwarding the environment variables _WAYLAND\_DISPLAY_ and _EDITOR_ in
addition to the built-in variables described in deus(1).

```
users = aja
groups = wheel
keepenv = WAYLAND_DISPLAY EDITOR
```

# DESCRIPTION

The deus(1) utility executes commands as other users according to the
deus.conf configuration file.

Configuration is defined in an INI-like format.

```
key = value1 value2 value 3
```

## OPTIONS

Configuration files may have the following options:

*users*
	The list of users to allow access to the deus(1) utility.

*groups*
	The list of groups to allow access to the deus(1) utility.

*keepenv*
	Contains _keys_ to be passed through to the new environment.
	This option is processed after the default environment has been created.

## CORRECTNESS

Be advised that it is best to specify absolute paths. If a relative path is
specified, only a restricted _PATH_ will be searched.

# FILES

/etc/deus.conf deus(1) configuration file.

# SEE ALSO

deus(1)

# AUTHORS

Originally based on rsudoas, which is based on doas.

- Ted Unangst <tedu@openbsd.org>
- TheDcoder <TheDcoder@protonmail.com>

Maintained by Michael Bullington <hello@mbullington.net>
