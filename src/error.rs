/*
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
*/

use core::fmt;

use crate::auth::SudoStringError;

#[derive(Debug)]
pub enum Error {
    NotPermitted,
    AuthenticationFailed,

    ConfigUnknownKey(String),
    PasswdCorrupt(String),
    UserNotFound(String),

    Io(std::io::Error),
    IoSyscall(&'static str, std::io::Error),

    StringValidation(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotPermitted => f.write_str("not permitted"),
            Error::AuthenticationFailed => f.write_str("authentication failed"),
            Error::ConfigUnknownKey(k) => write!(f, "unknown config key: {k}"),
            Error::PasswdCorrupt(s) => {
                write!(f, "passwd corrupt for user: {s}")
            }
            Error::UserNotFound(u) => write!(f, "user '{u}' not found"),
            Error::Io(e) => {
                write!(f, "IO error: {e}")
            }
            Error::IoSyscall(syscall, e) => {
                write!(f, "IO error in syscall '{syscall}': {e}")
            }
            Error::StringValidation(string) => {
                write!(f, "invalid string: {string:?}")
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<SudoStringError> for Error {
    fn from(err: SudoStringError) -> Self {
        match err {
            SudoStringError::StringValidation(str) => Error::StringValidation(str),
        }
    }
}
