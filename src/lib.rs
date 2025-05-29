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

mod error;
mod sudo_rs;

pub use crate::error::Error;

pub mod system {
    use crate::{auth::SudoString, error::Error, sudo_rs::cutils::os_string_from_ptr};

    #[link(name = "crypt")]
    extern "C" {
        fn crypt(phrase: *const libc::c_char, setting: *const libc::c_char) -> *const libc::c_char;
    }

    pub fn shadow_by_name(user: &str) -> Result<String, Error> {
        let c_user = SudoString::new(user.to_string())?;

        // SAFETY: If getspnam returns NULL, it means the user does not exist.
        // We will return the corresponding error in that case.
        //
        // After this call, if `spwd_ptr` is not NULL, we will clone any contents.
        let spwd_ptr = unsafe { libc::getspnam(c_user.as_cstr().as_ptr()) };

        if spwd_ptr.is_null() {
            Err(std::io::Error::last_os_error().into())
        } else {
            // SAFETY: The `sp_pwdp` field of `spwd` is a pointer to a null-terminated string.
            // We will convert this to a Rust string.
            unsafe {
                Ok(os_string_from_ptr((*spwd_ptr).sp_pwdp)
                    .to_str()
                    .ok_or_else(|| Error::PasswdCorrupt(user.to_string()))?
                    .to_owned())
            }
        }
    }

    pub fn safe_crypt(hash: String, response: String) -> Result<bool, Error> {
        let hash = SudoString::new(hash)?;
        let response = SudoString::new(response)?;

        // SAFETY: crypt varies between implementations, but generally returns a pointer to a
        // static buffer. We will convert this to a Rust string and compare it with the hash.
        //
        // If crypt returns NULL, it means an error occurred.
        let result = unsafe {
            let result = crypt(response.as_cstr().as_ptr(), hash.as_cstr().as_ptr());
            if result.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }

            // crypt may also return a garbage value if the hash is invalid.
            os_string_from_ptr(result)
        };

        Ok(result == hash.as_str())
    }
}

pub mod auth {
    use std::io::Write;

    use crate::error::Error;

    pub use crate::sudo_rs::interface::*;
    pub use crate::sudo_rs::string::*;
    pub use crate::sudo_rs::system::*;

    use crate::sudo_rs::rpassword::Terminal;
    use crate::system::{safe_crypt, shadow_by_name};

    pub fn challenge_user(user: &User) -> Result<bool, Error> {
        print!("deus ({}) password: ", &user.name);
        std::io::stdout().flush().unwrap();

        let mut term = Terminal::open_tty()?;
        let response = term
            .read_password()?
            .iter()
            .map(|&b| b as char)
            .take_while(|&x| x != '\0')
            .collect::<String>();

        let mut hash = &user.passwd;
        let shadow;
        if hash == "x" {
            shadow = shadow_by_name(&user.name)?;
            hash = &shadow;
        }

        safe_crypt(hash.to_string(), response)
    }
}

pub mod command {
    use std::collections::VecDeque;

    #[derive(Debug)]
    pub struct Execute {
        pub config_file: Option<String>,
        pub user: String,
        pub cmd: Option<String>,
        pub args: Vec<String>,
    }

    impl Execute {
        pub fn new_from(args: impl Iterator<Item = String>) -> Self {
            let mut exec_cmd = Execute {
                config_file: None,
                user: "root".into(),
                cmd: None,
                args: Vec::new(),
            };

            let mut args: VecDeque<_> = args.collect();
            let mut exec_shell = false;

            // Get rid of the first argument which is the program name.
            args.pop_front();

            // Since we don't have any shorthand options, we can write a simple
            // loop to parse the arguments.
            loop {
                if args.is_empty() || !args[0].starts_with('-') {
                    break;
                }

                let arg = match args.pop_front() {
                    Some(arg) => arg,
                    None => print_help_and_exit(1),
                };

                match arg.as_str() {
                    "-s" => exec_shell = true,
                    "-C" => {
                        let arg = match args.pop_front() {
                            Some(arg) => arg,
                            None => print_help_and_exit(1),
                        };
                        exec_cmd.config_file = Some(arg);
                    }
                    "-u" => {
                        let arg = match args.pop_front() {
                            Some(arg) => arg,
                            None => print_help_and_exit(1),
                        };
                        exec_cmd.user = arg;
                    }
                    "-h" => print_help_and_exit(0),
                    _ => print_help_and_exit(1),
                }
            }

            if args.is_empty() {
                if !exec_shell {
                    print_help_and_exit(1);
                }
            } else {
                match args.pop_front() {
                    Some(cmd) => exec_cmd.cmd = Some(cmd),
                    None => print_help_and_exit(1),
                }
                exec_cmd.args = Vec::from(args);
            }

            exec_cmd
        }
    }

    pub fn print_help_and_exit(code: i32) -> ! {
        eprintln!("usage: deus [-s] [-C config] [-u user] command [args]");
        std::process::exit(code);
    }

    pub fn print_error_and_exit(msg: &str, code: i32) -> ! {
        eprintln!("deus: {}", msg);
        std::process::exit(code);
    }
}

pub mod config {
    use crate::{
        auth::{Group, SudoString, User},
        error::Error,
    };

    #[derive(Clone, Debug)]
    pub struct Config {
        pub users: Vec<String>,
        pub groups: Vec<String>,
        pub keepenv: Vec<String>,
    }

    impl Config {
        pub fn r#match(&self, user: &User) -> Result<bool, Error> {
            // Check users naively by name.
            if self.users.iter().any(|u| u.as_str() == user.name.as_str()) {
                return Ok(true);
            }

            // Check groups by GID association.
            for group in &self.groups {
                let group_id = Group::from_name(SudoString::new(group.clone())?.as_cstr())?;

                if let Some(group_id) = group_id {
                    if user.groups.iter().any(|x| x == &group_id.gid) {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        }
    }

    impl TryFrom<&str> for Config {
        type Error = Error;

        fn try_from(file_contents: &str) -> Result<Self, Self::Error> {
            let mut config = Self {
                users: Vec::new(),
                groups: Vec::new(),
                keepenv: Vec::new(),
            };

            // We parse a simple, INI-like format.
            // key = value1 value2 value3
            for line in file_contents.lines() {
                if line.trim().is_empty() {
                    continue;
                }

                let mut keyvalue = line.splitn(2, '=');
                let key = match keyvalue.next() {
                    Some(key) => key.trim(),
                    None => unreachable!(),
                };
                let value = match keyvalue.next() {
                    Some(key) => key.trim(),
                    None => continue,
                };
                let values: Vec<&str> = value
                    .split(" ")
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.trim())
                    .collect();

                match key {
                    "users" => config.users.extend(values.iter().map(|&s| s.to_string())),
                    "groups" => config.groups.extend(values.iter().map(|&s| s.to_string())),
                    "keepenv" => config.keepenv.extend(values.iter().map(|&s| s.to_string())),
                    _ => return Err(Error::ConfigUnknownKey(key.to_string())),
                }
            }
            Ok(config)
        }
    }
}
