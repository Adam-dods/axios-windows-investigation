use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticodeVerification {
    pub checked: bool,
    pub trusted: bool,
    pub status: String,
    pub status_code: Option<i32>,
    pub source: String,
}

impl AuthenticodeVerification {
    pub fn not_checked() -> Self {
        Self {
            checked: false,
            trusted: false,
            status: "NotChecked".to_string(),
            status_code: None,
            source: "not_checked".to_string(),
        }
    }
}

#[cfg(windows)]
mod windows_native {
    use super::{map_status, member_tag, should_try_catalog, AuthenticodeVerification};
    use std::{
        ffi::{c_char, c_void},
        mem::{size_of, transmute_copy, zeroed},
        os::windows::ffi::OsStrExt,
        path::Path,
        ptr::{null, null_mut},
    };

    type Handle = *mut c_void;
    type Bool = i32;

    const GENERIC_READ: u32 = 0x80000000;
    const FILE_SHARE_READ: u32 = 0x00000001;
    const FILE_SHARE_WRITE: u32 = 0x00000002;
    const FILE_SHARE_DELETE: u32 = 0x00000004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;

    const WTD_UI_NONE: u32 = 2;
    const WTD_REVOKE_NONE: u32 = 0;
    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_CHOICE_CATALOG: u32 = 2;
    const WTD_STATEACTION_IGNORE: u32 = 0;
    const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x00001000;
    const WTD_UICONTEXT_EXECUTE: u32 = 0;

    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
        data1: 0x00AAC56B,
        data2: 0xCD44,
        data3: 0x11D0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    const DRIVER_ACTION_VERIFY: Guid = Guid {
        data1: 0xF750E6C3,
        data2: 0x38EE,
        data3: 0x11D1,
        data4: [0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    #[repr(C)]
    struct WintrustFileInfo {
        cb_struct: u32,
        file_path: *const u16,
        file_handle: Handle,
        known_subject: *const Guid,
    }

    #[repr(C)]
    struct WintrustCatalogInfo {
        cb_struct: u32,
        catalog_version: u32,
        catalog_file_path: *const u16,
        member_tag: *const u16,
        member_file_path: *const u16,
        member_file: Handle,
        calculated_file_hash: *mut u8,
        calculated_file_hash_size: u32,
        catalog_context: *const c_void,
        catalog_admin: Handle,
    }

    #[repr(C)]
    union WintrustObject {
        file: *mut WintrustFileInfo,
        catalog: *mut WintrustCatalogInfo,
    }

    #[repr(C)]
    struct WintrustData {
        cb_struct: u32,
        policy_callback_data: *mut c_void,
        sip_client_data: *mut c_void,
        ui_choice: u32,
        revocation_checks: u32,
        union_choice: u32,
        object: WintrustObject,
        state_action: u32,
        state_data: Handle,
        url_reference: *mut u16,
        provider_flags: u32,
        ui_context: u32,
        signature_settings: *mut c_void,
    }

    #[repr(C)]
    struct CatalogInfo {
        cb_struct: u32,
        catalog_file: [u16; 260],
    }

    type AcquireContext2 =
        unsafe extern "system" fn(*mut Handle, *const Guid, *const u16, *const c_void, u32) -> Bool;

    type CalcHashFromFileHandle2 =
        unsafe extern "system" fn(Handle, Handle, *mut u32, *mut u8, u32) -> Bool;

    type EnumCatalogFromHash =
        unsafe extern "system" fn(Handle, *mut u8, u32, u32, *mut Handle) -> Handle;

    type CatalogInfoFromContext = unsafe extern "system" fn(Handle, *mut CatalogInfo, u32) -> Bool;

    type ReleaseCatalogContext = unsafe extern "system" fn(Handle, Handle, u32) -> Bool;

    type ReleaseContext = unsafe extern "system" fn(Handle, u32) -> Bool;

    struct CatalogApi {
        acquire_context: AcquireContext2,
        calculate_hash: CalcHashFromFileHandle2,
        enumerate_catalog: EnumCatalogFromHash,
        catalog_info: CatalogInfoFromContext,
        release_catalog: ReleaseCatalogContext,
        release_context: ReleaseContext,
    }

    #[link(name = "wintrust")]
    unsafe extern "system" {
        fn WinVerifyTrust(window: Handle, action: *mut Guid, data: *mut c_void) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;

        fn CloseHandle(object: Handle) -> Bool;

        fn GetModuleHandleW(module_name: *const u16) -> Handle;

        fn GetProcAddress(module: Handle, procedure_name: *const c_char) -> *mut c_void;
    }

    impl CatalogApi {
        unsafe fn load() -> Option<Self> {
            let wintrust_name: Vec<u16> = "wintrust.dll".encode_utf16().chain(Some(0)).collect();

            let module = GetModuleHandleW(wintrust_name.as_ptr());

            if module.is_null() {
                return None;
            }

            Some(Self {
                acquire_context: load_function(module, b"CryptCATAdminAcquireContext2\0")?,
                calculate_hash: load_function(module, b"CryptCATAdminCalcHashFromFileHandle2\0")?,
                enumerate_catalog: load_function(module, b"CryptCATAdminEnumCatalogFromHash\0")?,
                catalog_info: load_function(module, b"CryptCATCatalogInfoFromContext\0")?,
                release_catalog: load_function(module, b"CryptCATAdminReleaseCatalogContext\0")?,
                release_context: load_function(module, b"CryptCATAdminReleaseContext\0")?,
            })
        }
    }

    unsafe fn load_function<T: Copy>(module: Handle, name: &'static [u8]) -> Option<T> {
        let address = GetProcAddress(module, name.as_ptr().cast());

        if address.is_null() {
            return None;
        }

        if size_of::<T>() != size_of::<*mut c_void>() {
            return None;
        }

        Some(transmute_copy(&address))
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn wide_text(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn result(status_code: i32, source: String) -> AuthenticodeVerification {
        let (status, trusted) = map_status(status_code);

        AuthenticodeVerification {
            checked: true,
            trusted,
            status: status.to_string(),
            status_code: Some(status_code),
            source,
        }
    }

    unsafe fn verify_embedded(path: &Path) -> AuthenticodeVerification {
        let path_wide = wide_path(path);

        let mut file_info: WintrustFileInfo = zeroed();

        file_info.cb_struct = size_of::<WintrustFileInfo>() as u32;
        file_info.file_path = path_wide.as_ptr();

        let mut trust_data: WintrustData = zeroed();

        trust_data.cb_struct = size_of::<WintrustData>() as u32;
        trust_data.ui_choice = WTD_UI_NONE;
        trust_data.revocation_checks = WTD_REVOKE_NONE;
        trust_data.union_choice = WTD_CHOICE_FILE;
        trust_data.object = WintrustObject {
            file: &mut file_info,
        };
        trust_data.state_action = WTD_STATEACTION_IGNORE;
        trust_data.provider_flags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        trust_data.ui_context = WTD_UICONTEXT_EXECUTE;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        let status_code = WinVerifyTrust(
            null_mut(),
            &mut action,
            &mut trust_data as *mut WintrustData as *mut c_void,
        );

        result(status_code, "winverifytrust_embedded".to_string())
    }

    unsafe fn verify_catalog_algorithm(
        path: &Path,
        algorithm: &str,
        api: &CatalogApi,
    ) -> Option<AuthenticodeVerification> {
        let path_wide = wide_path(path);

        let file = CreateFileW(
            path_wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );

        if file == INVALID_HANDLE_VALUE || file.is_null() {
            return None;
        }

        let algorithm_wide = wide_text(algorithm);

        let mut catalog_admin: Handle = null_mut();

        let acquired = (api.acquire_context)(
            &mut catalog_admin,
            &DRIVER_ACTION_VERIFY,
            algorithm_wide.as_ptr(),
            null(),
            0,
        );

        if acquired == 0 || catalog_admin.is_null() {
            CloseHandle(file);
            return None;
        }

        let catalog_result = (|| {
            let mut hash_size = 0u32;

            if (api.calculate_hash)(catalog_admin, file, &mut hash_size, null_mut(), 0) == 0
                || hash_size == 0
                || hash_size > 128
            {
                return None;
            }

            let mut hash = vec![0u8; hash_size as usize];

            if (api.calculate_hash)(catalog_admin, file, &mut hash_size, hash.as_mut_ptr(), 0) == 0
            {
                return None;
            }

            hash.truncate(hash_size as usize);

            let catalog_handle =
                (api.enumerate_catalog)(catalog_admin, hash.as_mut_ptr(), hash_size, 0, null_mut());

            if catalog_handle.is_null() {
                return None;
            }

            let verification = (|| {
                let mut catalog_info: CatalogInfo = zeroed();

                catalog_info.cb_struct = size_of::<CatalogInfo>() as u32;

                if (api.catalog_info)(catalog_handle, &mut catalog_info, 0) == 0 {
                    return None;
                }

                let member_tag = member_tag(&hash);

                let mut trust_catalog: WintrustCatalogInfo = zeroed();

                trust_catalog.cb_struct = size_of::<WintrustCatalogInfo>() as u32;

                trust_catalog.catalog_file_path = catalog_info.catalog_file.as_ptr();

                trust_catalog.member_tag = member_tag.as_ptr();

                trust_catalog.member_file_path = path_wide.as_ptr();

                trust_catalog.member_file = file;

                trust_catalog.calculated_file_hash = hash.as_mut_ptr();

                trust_catalog.calculated_file_hash_size = hash_size;

                trust_catalog.catalog_admin = catalog_admin;

                let mut trust_data: WintrustData = zeroed();

                trust_data.cb_struct = size_of::<WintrustData>() as u32;

                trust_data.ui_choice = WTD_UI_NONE;

                trust_data.revocation_checks = WTD_REVOKE_NONE;

                trust_data.union_choice = WTD_CHOICE_CATALOG;

                trust_data.object = WintrustObject {
                    catalog: &mut trust_catalog,
                };

                trust_data.state_action = WTD_STATEACTION_IGNORE;

                trust_data.provider_flags = WTD_CACHE_ONLY_URL_RETRIEVAL;

                trust_data.ui_context = WTD_UICONTEXT_EXECUTE;

                let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

                let status_code = WinVerifyTrust(
                    null_mut(),
                    &mut action,
                    &mut trust_data as *mut WintrustData as *mut c_void,
                );

                Some(result(
                    status_code,
                    format!("winverifytrust_catalog_{}", algorithm.to_ascii_lowercase()),
                ))
            })();

            (api.release_catalog)(catalog_admin, catalog_handle, 0);

            verification
        })();

        (api.release_context)(catalog_admin, 0);

        CloseHandle(file);

        catalog_result
    }

    unsafe fn verify_catalog(path: &Path) -> Option<AuthenticodeVerification> {
        let api = CatalogApi::load()?;

        for algorithm in ["SHA256", "SHA1"] {
            if let Some(result) = verify_catalog_algorithm(path, algorithm, &api) {
                return Some(result);
            }
        }

        None
    }

    pub(super) fn verify(path: &Path) -> AuthenticodeVerification {
        if !path.is_file() {
            return AuthenticodeVerification {
                checked: false,
                trusted: false,
                status: "FileNotFound".to_string(),
                status_code: None,
                source: "winverifytrust".to_string(),
            };
        }

        unsafe {
            let embedded = verify_embedded(path);

            let embedded_code = embedded.status_code.unwrap_or_default();

            if should_try_catalog(embedded_code) {
                if let Some(catalog) = verify_catalog(path) {
                    return catalog;
                }
            }

            embedded
        }
    }

    #[cfg(target_pointer_width = "64")]
    const _: [(); 16] = [(); size_of::<Guid>()];

    #[cfg(target_pointer_width = "64")]
    const _: [(); 32] = [(); size_of::<WintrustFileInfo>()];

    #[cfg(target_pointer_width = "64")]
    const _: [(); 72] = [(); size_of::<WintrustCatalogInfo>()];

    #[cfg(target_pointer_width = "64")]
    const _: [(); 88] = [(); size_of::<WintrustData>()];

    const _: [(); 524] = [(); size_of::<CatalogInfo>()];
}

#[cfg(windows)]
pub fn verify_file(path: &Path) -> AuthenticodeVerification {
    windows_native::verify(path)
}

#[cfg(not(windows))]
pub fn verify_file(_path: &Path) -> AuthenticodeVerification {
    AuthenticodeVerification {
        checked: false,
        trusted: false,
        status: "UnsupportedPlatform".to_string(),
        status_code: None,
        source: "unsupported_platform".to_string(),
    }
}

#[cfg(any(windows, test))]
fn should_try_catalog(status_code: i32) -> bool {
    status_code as u32 == 0x800B0100
}

#[cfg(any(windows, test))]
fn member_tag(hash: &[u8]) -> Vec<u16> {
    let mut text = String::with_capacity(hash.len() * 2);

    for byte in hash {
        use std::fmt::Write;

        let _ = write!(text, "{byte:02X}",);
    }

    text.encode_utf16().chain(Some(0)).collect()
}

#[cfg(any(windows, test))]
fn map_status(status_code: i32) -> (&'static str, bool) {
    match status_code as u32 {
        0x00000000 => ("Valid", true),
        0x800B0100 => ("NotSigned", false),
        0x80096010 => ("BadDigest", false),
        0x800B0111 => ("ExplicitDistrust", false),
        0x800B0004 => ("SubjectNotTrusted", false),
        0x80092026 => ("SecuritySettingsBlocked", false),
        0x800B0101 => ("CertificateExpired", false),
        0x800B010C => ("CertificateRevoked", false),
        _ => ("Invalid", false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_signature_is_trusted() {
        assert_eq!(map_status(0), ("Valid", true));
    }

    #[test]
    fn missing_signature_is_not_trusted() {
        assert_eq!(map_status(0x800B0100_u32 as i32), ("NotSigned", false));
    }

    #[test]
    fn bad_digest_is_distinct() {
        assert_eq!(map_status(0x80096010_u32 as i32), ("BadDigest", false));
    }

    #[test]
    fn revoked_certificate_is_distinct() {
        assert_eq!(
            map_status(0x800B010C_u32 as i32),
            ("CertificateRevoked", false,)
        );
    }

    #[test]
    fn not_checked_is_not_a_verdict() {
        let result = AuthenticodeVerification::not_checked();

        assert!(!result.checked);
        assert!(!result.trusted);
        assert_eq!(result.status, "NotChecked");
    }

    #[test]
    fn unsupported_platform_is_not_checked() {
        let result = verify_file(Path::new("unsupported-platform.exe"));

        assert!(!result.checked);
        assert!(!result.trusted);
        assert_eq!(result.status, "UnsupportedPlatform");
    }

    #[test]
    fn catalog_fallback_is_only_for_no_signature() {
        assert!(should_try_catalog(0x800B0100_u32 as i32,));

        assert!(!should_try_catalog(0));

        assert!(!should_try_catalog(0x80096010_u32 as i32,));
    }

    #[test]
    fn catalog_member_tag_is_uppercase_hex() {
        assert_eq!(
            member_tag(&[0x01, 0xAB, 0xFF,]),
            vec!['0' as u16, '1' as u16, 'A' as u16, 'B' as u16, 'F' as u16, 'F' as u16, 0,]
        );
    }
}
