#![allow(dead_code)]

/*
deus - Privilege escalation utility

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

use std::{ffi::CStr, mem::MaybeUninit, path::PathBuf};

use super::{
    cutils::{cerr, os_string_from_ptr, string_from_ptr, sysconf},
    interface::*,
    string::SudoString,
};

pub(crate) const ROOT_GROUP_NAME: &str = "root";

type Error = std::io::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub uid: UserId,
    pub gid: GroupId,
    pub name: SudoString,
    pub gecos: String,
    // MBULLINGTON: Changed from pub home: SudoPath,
    pub home: SudoString,
    pub shell: PathBuf,
    pub passwd: String,
    pub groups: Vec<GroupId>,
}

impl User {
    /// # Safety
    /// This function expects `pwd` to be a result from a succesful call to `getpwXXX_r`.
    /// (It can cause UB if any of `pwd`'s pointed-to strings does not have a null-terminator.)
    unsafe fn from_libc(pwd: &libc::passwd) -> Result<User, Error> {
        let mut buf_len: libc::c_int = 32;
        let mut groups_buffer: Vec<libc::gid_t>;

        while {
            groups_buffer = vec![0; buf_len as usize];
            // SAFETY: getgrouplist is passed valid pointers
            // in particular `groups_buffer` is an array of `buf.len()` bytes, as required
            let result = unsafe {
                libc::getgrouplist(
                    pwd.pw_name,
                    pwd.pw_gid,
                    groups_buffer.as_mut_ptr(),
                    &mut buf_len,
                )
            };

            result == -1
        } {
            if buf_len >= 65536 {
                panic!("user has too many groups (> 65536), this should not happen");
            }

            buf_len *= 2;
        }

        groups_buffer.resize_with(buf_len as usize, || {
            panic!("invalid groups count returned from getgrouplist, this should not happen")
        });

        Ok(User {
            uid: UserId::new(pwd.pw_uid),
            gid: GroupId::new(pwd.pw_gid),
            // MBULLINGTON: Changed to cast to std::io::Error
            name: SudoString::new(string_from_ptr(pwd.pw_name)).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "User name contained a null byte",
                )
            })?,
            gecos: string_from_ptr(pwd.pw_gecos),
            home: SudoString::new(string_from_ptr(pwd.pw_dir)).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "User name contained a null byte",
                )
            })?,
            shell: os_string_from_ptr(pwd.pw_shell).into(),
            passwd: string_from_ptr(pwd.pw_passwd),
            groups: groups_buffer
                .iter()
                .map(|id| GroupId::new(*id))
                .collect::<Vec<_>>(),
        })
    }

    pub fn from_uid(uid: UserId) -> Result<Option<User>, Error> {
        let max_pw_size = sysconf(libc::_SC_GETPW_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_pw_size as usize];
        let mut pwd = MaybeUninit::uninit();
        let mut pwd_ptr = std::ptr::null_mut();
        // SAFETY: getpwuid_r is passed valid (although partly uninitialized) pointers to memory,
        // in particular `buf` points to an array of `buf.len()` bytes, as required.
        // After this call, if `pwd_ptr` is not NULL, `*pwd_ptr` and `pwd` will be aliased;
        // but we never dereference `pwd_ptr`.
        cerr(unsafe {
            libc::getpwuid_r(
                uid.inner(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut pwd_ptr,
            )
        })?;
        if pwd_ptr.is_null() {
            Ok(None)
        } else {
            // SAFETY: pwd_ptr was not null, and getpwuid_r succeeded, so we have assurances that
            // the `pwd` structure was written to by getpwuid_r
            let pwd = unsafe { pwd.assume_init() };
            // SAFETY: `pwd` was obtained by a call to getpwXXX_r, as required.
            unsafe { Self::from_libc(&pwd).map(Some) }
        }
    }

    pub fn effective_uid() -> UserId {
        // SAFETY: this function cannot cause memory safety issues
        UserId::new(unsafe { libc::geteuid() })
    }

    pub fn effective_gid() -> GroupId {
        // SAFETY: this function cannot cause memory safety issues
        GroupId::new(unsafe { libc::getegid() })
    }

    pub fn real_uid() -> UserId {
        // SAFETY: this function cannot cause memory safety issues
        UserId::new(unsafe { libc::getuid() })
    }

    pub fn real_gid() -> GroupId {
        // SAFETY: this function cannot cause memory safety issues
        GroupId::new(unsafe { libc::getgid() })
    }

    pub fn real() -> Result<Option<User>, Error> {
        Self::from_uid(Self::real_uid())
    }

    pub fn from_name(name_c: &CStr) -> Result<Option<User>, Error> {
        let max_pw_size = sysconf(libc::_SC_GETPW_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_pw_size as usize];
        let mut pwd = MaybeUninit::uninit();
        let mut pwd_ptr = std::ptr::null_mut();

        // SAFETY: analogous to getpwuid_r above
        cerr(unsafe {
            libc::getpwnam_r(
                name_c.as_ptr(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut pwd_ptr,
            )
        })?;
        if pwd_ptr.is_null() {
            Ok(None)
        } else {
            // SAFETY: pwd_ptr was not null, and getpwnam_r succeeded, so we have assurances that
            // the `pwd` structure was written to by getpwnam_r
            let pwd = unsafe { pwd.assume_init() };
            // SAFETY: `pwd` was obtained by a call to getpwXXX_r, as required.
            unsafe { Self::from_libc(&pwd).map(Some) }
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Group {
    pub gid: GroupId,
    pub name: String,
}

impl Group {
    /// # Safety
    /// This function expects `grp` to be a result from a succesful call to `getgrXXX_r`.
    /// In particular the grp.gr_mem pointer is assumed to be non-null, and pointing to a
    /// null-terminated list; the pointed-to strings are expected to be null-terminated.
    unsafe fn from_libc(grp: &libc::group) -> Group {
        Group {
            gid: GroupId::new(grp.gr_gid),
            name: string_from_ptr(grp.gr_name),
        }
    }

    pub fn from_gid(gid: GroupId) -> std::io::Result<Option<Group>> {
        let max_gr_size = sysconf(libc::_SC_GETGR_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_gr_size as usize];
        let mut grp = MaybeUninit::uninit();
        let mut grp_ptr = std::ptr::null_mut();
        // SAFETY: analogous to getpwuid_r above
        cerr(unsafe {
            libc::getgrgid_r(
                gid.inner(),
                grp.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut grp_ptr,
            )
        })?;
        if grp_ptr.is_null() {
            Ok(None)
        } else {
            // SAFETY: grp_ptr was not null, and getgrgid_r succeeded, so we have assurances that
            // the `grp` structure was written to by getgrgid_r
            let grp = unsafe { grp.assume_init() };
            // SAFETY: `pwd` was obtained by a call to getgrXXX_r, as required.
            Ok(Some(unsafe { Group::from_libc(&grp) }))
        }
    }

    pub fn from_name(name_c: &CStr) -> std::io::Result<Option<Group>> {
        let max_gr_size = sysconf(libc::_SC_GETGR_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_gr_size as usize];
        let mut grp = MaybeUninit::uninit();
        let mut grp_ptr = std::ptr::null_mut();
        // SAFETY: analogous to getpwuid_r above
        cerr(unsafe {
            libc::getgrnam_r(
                name_c.as_ptr(),
                grp.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut grp_ptr,
            )
        })?;
        if grp_ptr.is_null() {
            Ok(None)
        } else {
            // SAFETY: grp_ptr was not null, and getgrgid_r succeeded, so we have assurances that
            // the `grp` structure was written to by getgrgid_r
            let grp = unsafe { grp.assume_init() };
            // SAFETY: `pwd` was obtained by a call to getgrXXX_r, as required.
            Ok(Some(unsafe { Group::from_libc(&grp) }))
        }
    }
}

pub fn syslog(priority: libc::c_int, facility: libc::c_int, message: &CStr) {
    const MSG: *const libc::c_char = match CStr::from_bytes_until_nul(b"%s\0") {
        Ok(cstr) => cstr.as_ptr(),
        Err(_) => panic!("syslog formatting string is not null-terminated"),
    };

    // SAFETY:
    // - "MSG" is a constant expression that is a null-terminated C string that represents "%s";
    //   this also means that to achieve safety we MUST pass one more argument to syslog that is a proper
    //   pointer to a null-terminated C string
    // - message.as_ptr() is a pointer to a proper null-terminated C string (message being a &CStr)
    // for more info: read the manpage for syslog(2)
    unsafe {
        libc::syslog(priority | facility, MSG, message.as_ptr());
    }
}

/// set target user and groups (uid, gid, additional groups) for a command
pub fn set_target_user(
    cmd: &mut std::process::Command,
    mut target_user: User,
    target_group: Group,
) {
    use std::os::unix::process::CommandExt;

    if let Some(index) = target_user
        .groups
        .iter()
        .position(|id| id == &target_group.gid)
    {
        // make sure the requested group id is the first in the list (necessary on FreeBSD)
        target_user.groups.swap(0, index)
    } else {
        // add target group to list of additional groups if not present
        target_user.groups.insert(0, target_group.gid);
    }

    // we need to do this in a `pre_exec` call since the `groups` method in `process::Command` is unstable
    // see https://github.com/rust-lang/rust/blob/a01b4cc9f375f1b95fa8195daeea938d3d9c4c34/library/std/src/sys/unix/process/process_unix.rs#L329-L352
    // for the std implementation of the libc calls to `setgroups`, `setgid` and `setuid`
    unsafe {
        cmd.pre_exec(move || {
            cerr(libc::setgroups(
                target_user.groups.len() as _,
                // We can cast to gid_t because `GroupId` is marked as transparent
                target_user.groups.as_ptr().cast::<libc::gid_t>(),
            ))?;
            // setgid and setuid set the real, effective and saved version of the gid and uid
            // respectively rather than just the real gid and uid. The original sudo uses setresgid
            // and setresuid instead with all three arguments equal, but as this does the same as
            // setgid and setuid using the latter is fine too.
            cerr(libc::setgid(target_group.gid.inner()))?;
            cerr(libc::setuid(target_user.uid.inner()))?;

            Ok(())
        });
    }
}
