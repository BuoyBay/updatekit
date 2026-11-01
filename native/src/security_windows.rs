//! Owner-and-SYSTEM-only ACLs for transaction directories and lock files.
use crate::model::Result;
use std::{
    ffi::c_void,
    fs::File,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::*,
};

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn wide(path: &Path) -> Result<Vec<u16>> {
    let value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err("invalid updater path".into());
    }
    Ok(value.into_iter().chain(Some(0)).collect())
}
fn with_user<T>(operation: impl FnOnce(PSID) -> Result<T>) -> Result<T> {
    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err("cannot read current Windows identity".into());
        }
        let mut needed = 0;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
        if needed == 0 || needed > 1024 * 1024 {
            CloseHandle(token);
            return Err("invalid Windows identity size".into());
        }
        let mut words = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            words.as_mut_ptr().cast(),
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if ok == 0 {
            return Err("cannot read Windows user SID".into());
        }
        operation((*(words.as_ptr() as *const TOKEN_USER)).User.Sid)
    }
}
fn descriptor() -> Result<Local> {
    with_user(|user| unsafe {
        let mut text = ptr::null_mut();
        if ConvertSidToStringSidW(user, &mut text) == 0 {
            return Err("cannot encode Windows identity".into());
        }
        let owned = Local(text.cast());
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        let sid = String::from_utf16(std::slice::from_raw_parts(text, length))
            .map_err(|_| "invalid Windows SID")?;
        drop(owned);
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut security = ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut security,
            ptr::null_mut(),
        ) == 0
        {
            return Err("cannot create private updater ACL".into());
        }
        Ok(Local(security))
    })
}
pub(crate) fn validate_private(path: &Path) -> Result<()> {
    let path = wide(path)?;
    with_user(|user| unsafe {
        let mut owner = ptr::null_mut();
        let mut acl = ptr::null_mut();
        let mut security = ptr::null_mut();
        if GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut security,
        ) != ERROR_SUCCESS
        {
            return Err("cannot inspect updater ownership and ACL".into());
        }
        let _owned = Local(security);
        // Elevated Windows tokens commonly create files owned by the
        // Administrators group. Administrators and SYSTEM are already trusted
        // principals in the private ACL; ordinary other-user owners are rejected.
        if owner.is_null()
            || acl.is_null()
            || (EqualSid(owner, user) == 0
                && IsWellKnownSid(owner, WinBuiltinAdministratorsSid) == 0
                && IsWellKnownSid(owner, WinLocalSystemSid) == 0)
        {
            return Err("updater path must have a trusted Windows owner and a private ACL".into());
        }
        for i in 0..u32::from((*acl).AceCount) {
            let mut ace = ptr::null_mut();
            if GetAce(acl, i, &mut ace) == 0 || ace.is_null() {
                return Err("invalid updater ACL".into());
            }
            let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
            // Accept only ordinary allow ACEs naming this user or LocalSystem.
            if (*allowed).Header.AceType != 0 {
                return Err("unsupported updater ACL entry".into());
            }
            let sid = ptr::addr_of_mut!((*allowed).SidStart).cast();
            if EqualSid(sid, user) == 0
                && IsWellKnownSid(sid, WinLocalSystemSid) == 0
                && IsWellKnownSid(sid, WinBuiltinAdministratorsSid) == 0
                && !(IsWellKnownSid(sid, WinCreatorOwnerSid) != 0
                    && (*allowed).Header.AceFlags & 0x08 != 0)
            {
                return Err("updater path grants access to another Windows principal".into());
            }
        }
        Ok(())
    })
}
pub(crate) fn create_directory(path: &Path) -> Result<()> {
    let name = wide(path)?;
    let security = descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        return Err("cannot create private transaction directory".into());
    }
    validate_private(path)
}
pub(crate) fn open_lock(path: &Path) -> Result<File> {
    let name = wide(path)?;
    let security = descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err("cannot open private update lock".into());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    validate_private(path)?;
    Ok(file)
}
