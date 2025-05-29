deus(1)

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

deus - execute commands as another user

# SYNOPSIS

deus [-s] [-C _config_] [-u _user_] [_command_] [_args_]

# DESCRIPTION

The deus utility executes the given command as another user. The command
argument is mandatory unless -C or -s is specified.

The user will be required to authenticate by entering their password, unless
configured otherwise.

By default, a new environment is created. The variables HOME, LOGNAME, PATH,
SHELL, and USER are set to values appropriate for the target user. DEUS_USER is
set to the name of the user executing . The variables DISPLAY and TERM are
inherited from the current environment. This behavior may be modified by the
config file. The working directory is not changed.

All commands are logged using syslogd(8).

# OPTIONS

*-C* _config_
	Parse and check the configuration file config, then exit. If command is
	supplied, deus will also perform command matching. In the latter case
	either `permit` or `deny` will be printed on standard
	output, depending on command matching results. No command is executed.

*-s*
	Execute the shell from SHELL or /etc/passwd.

*-u* _user_
	Execute the command as user. The default is root.

# EXIT STATUS

deus may fail for one of the following reasons:

- The config file /etc/deus.conf could not be parsed.
- The user attempted to run a command which is not permitted.
- The password was incorrect.
- The specified command was not found or is not executable.

# SEE ALSO

deus.conf(5), syslog.d(8)

# AUTHORS

Originally based on rsudoas, which is based on doas.

- Ted Unangst <tedu@openbsd.org>
- TheDcoder <TheDcoder@protonmail.com>

Maintained by Michael Bullington <hello@mbullington.net>
