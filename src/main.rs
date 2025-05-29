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

use deus::{auth::*, command::*, config::*, Error};
use std::{env::set_var, os::unix::process::CommandExt, process::Command};

const SAFE_PATH: &str = env!("SAFE_PATH");

fn main() {
    let opts = Execute::new_from(std::env::args());
    if let Err(e) = execute(opts) {
        print_error_and_exit(&format!("{}", &e), 1);
    }
}

fn execute(opts: Execute) -> Result<(), Error> {
    let only_check;
    let config_file;
    match opts.config_file {
        None => {
            only_check = false;
            config_file = String::from("/etc/deus.conf");
        }
        Some(file) => {
            only_check = true;
            config_file = file;
        }
    }
    let config = std::fs::read_to_string(config_file)?;
    let config = Config::try_from(&*config)?;

    let user = User::real().unwrap().unwrap();

    let user_target = match User::from_name(SudoString::new(opts.user.clone())?.as_cstr()) {
        Err(e) => return Err(e.into()),
        Ok(o) => match o {
            None => return Err(Error::UserNotFound(opts.user)),
            Some(x) => x,
        },
    };

    let group_target = Group::from_gid(user_target.gid).unwrap().unwrap();

    let cmd = match opts.cmd {
        Some(x) => x,
        None => user_target.shell.to_string_lossy().to_string(),
    };

    let permitted = config.r#match(&user)?;
    if only_check {
        if permitted {
            println!("permit")
        } else {
            println!("deny")
        }
        return Ok(());
    }

    fn get_cmdline(cmd: &str, args: &[String]) -> String {
        let mut cmdline = cmd.to_string();
        if !args.is_empty() {
            cmdline.push(' ');
            let args = args.join(" ");
            cmdline.push_str(&args);
        }
        cmdline
    }

    if !permitted {
        let cmdline = get_cmdline(&cmd, &opts.args);
        let msg = format!("command not permitted for {}: {}", &user.name, &cmdline);
        syslog(
            libc::LOG_AUTHPRIV,
            libc::LOG_NOTICE,
            SudoString::new(msg)?.as_cstr(),
        );

        return Err(Error::NotPermitted);
    }

    if !challenge_user(&user)? {
        return Err(Error::AuthenticationFailed);
    }

    // Log to syslog.
    {
        let cmdline = get_cmdline(&cmd, &opts.args);
        let cwd = std::env::current_dir();
        let cwd = match &cwd {
            Ok(dir) => dir.to_str().unwrap_or("(invalid utf8)"),
            Err(_) => "(failed)",
        };
        let msg = format!(
            "{} ran command {} as {} from {}",
            &user.name, &cmdline, &opts.user, &cwd
        );
        syslog(
            libc::LOG_AUTHPRIV,
            libc::LOG_INFO,
            SudoString::new(msg)?.as_cstr(),
        );
    }

    // SAFETY: set_var is not thread safe, but we are in the main thread.
    unsafe {
        set_var("PATH", SAFE_PATH);
    }

    let mut env_target = vec![
        ("DEUS_USER".to_string(), user.name.to_string()),
        ("HOME".to_string(), user_target.home.to_string()),
        ("LOGNAME".to_string(), user_target.name.to_string()),
        ("PATH".to_string(), SAFE_PATH.to_string()),
        (
            "SHELL".to_string(),
            user_target.shell.to_string_lossy().to_string(),
        ),
        ("USER".to_string(), user_target.name.to_string()),
    ];

    for var in ["DISPLAY", "TERM"] {
        if let Ok(value) = std::env::var(var) {
            env_target.push((var.to_string(), value));
        }
    }

    for var in config.keepenv.iter() {
        if let Ok(value) = std::env::var(var) {
            env_target.push((var.to_string(), value));
        }
    }

    let mut command = Command::new(cmd);
    // Reset env and set filtered environment.
    command.args(opts.args).env_clear().envs(env_target);

    set_target_user(&mut command, user_target, group_target);

    Err(command.exec().into())
}
