#![allow(dead_code)]

/*
The code in this module was taken from 'e0fff403da522f31c54395c615bbb4486fed4e79'
of the sudo-rs project.

We make very minimal modifications and tend to copy files as is, so we can
easily update to newer versions of sudo-rs.

# Why from sudo-rs?

What we forked deus from (rsudoas) had a lot of Rust dependencies that were
unnecessary.

sudo-rs already solved this problem and is a high quality codebase that has
been independently security tested.

https://tweedegolf.nl/en/blog/119/sudo-rs-depencencies-when-less-is-better

# Why not use sudo-rs directly

We chose to base deus on rsudoas (derived from doas) because it is simpler in
design, has a smaller attack surface, and avoids PAM (which we don't support).

--------------------------------------------------------------------------------

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
*/

pub mod cutils;
pub mod interface;
pub mod rpassword;
pub mod securemem;
pub mod string;
pub mod system;
