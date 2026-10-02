#[cfg(windows)]
use anyhow::Context;
use anyhow::{bail, Result};
#[cfg(windows)]
use chrono::Utc;
#[cfg(windows)]
use serde_json::json;
#[cfg(any(windows, test))]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    process::Command,
};

#[cfg(windows)]
const PBKDF2_ITERATIONS: u32 = 200_000;
#[cfg(windows)]
const FILE_MAGIC: &[u8] = b"AXIOSCRED\x01";
#[cfg(windows)]
const MINIMUM_ARCHIVE_PASSWORD_BYTES: usize = 12;
#[cfg(windows)]
const STD_INPUT_HANDLE: u32 = (-10_i32) as u32;
#[cfg(windows)]
const ENABLE_ECHO_INPUT: u32 = 0x0004;
#[cfg(windows)]
const INVALID_HANDLE_VALUE: isize = -1;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "GetStdHandle"]
    fn get_std_handle(standard_handle: u32) -> isize;

    #[link_name = "GetConsoleMode"]
    fn get_console_mode(console_handle: isize, mode: *mut u32) -> i32;

    #[link_name = "SetConsoleMode"]
    fn set_console_mode(console_handle: isize, mode: u32) -> i32;
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
struct WifiCredential {
    ssid: String,
    authentication: String,
    cipher: String,
    password: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("AXIOS_PRIVATE_NETWORK_ACCESS_ERROR={error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    #[cfg(not(windows))]
    bail!("developer credential view is available only on Windows");

    #[cfg(windows)]
    {
        let arguments: Vec<_> = env::args_os().skip(1).collect();
        if arguments.len() > 1
            || arguments
                .first()
                .is_some_and(|argument| argument != "--decrypt")
        {
            bail!("usage: axios-developer-credential-view.exe [--decrypt]");
        }

        if !arguments.is_empty() {
            return decrypt_saved_credential();
        }

        let credential = collect_active_wifi_credential()?;

        print_heading("PRIVATE NETWORK CREDENTIAL ACCESS");
        println!("SSID                   : {}", credential.ssid);
        println!("Authentication         : {}", credential.authentication);
        println!("Cipher                 : {}", credential.cipher);
        println!("Wi-Fi password         : {}", credential.password);
        println!();

        print!("Save an encrypted copy? [Y/N]: ");
        io::stdout().flush()?;
        let answer = read_line()?;

        if !answer.trim().eq_ignore_ascii_case("y") {
            println!("File saved             : no");
            println!("Files created          : 0");
            return Ok(());
        }

        let mut file_password = read_secret_line("Enter file encryption password: ")?.into_bytes();

        if file_password.len() < MINIMUM_ARCHIVE_PASSWORD_BYTES {
            file_password.fill(0);
            bail!(
                "file encryption password must contain at least {} bytes",
                MINIMUM_ARCHIVE_PASSWORD_BYTES
            );
        }

        let mut confirmation = read_secret_line("Confirm file encryption password: ")?.into_bytes();

        if file_password != confirmation {
            file_password.fill(0);
            confirmation.fill(0);
            bail!("file encryption passwords do not match");
        }

        confirmation.fill(0);

        let output_result = encrypt_and_save(&credential, &file_password);

        file_password.fill(0);
        let output = output_result?;

        println!("Encrypted file saved   : yes");
        println!("Encryption             : AES-256-GCM");
        println!("File integrity         : authenticated");
        println!("Plaintext file created : no");
        println!("Output                  : {}", output.display());
        Ok(())
    }
}

#[cfg(windows)]
fn downloads_directory() -> Result<PathBuf> {
    Ok(
        PathBuf::from(env::var("USERPROFILE").context("USERPROFILE is unavailable")?)
            .join("Downloads"),
    )
}

#[cfg(windows)]
fn decrypt_saved_credential() -> Result<()> {
    let downloads = downloads_directory()?;
    let mut files = Vec::new();

    for entry in fs::read_dir(&downloads)
        .with_context(|| format!("cannot read Downloads: {}", downloads.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("dat") {
            continue;
        }

        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(_) => continue,
        };
        if data.starts_with(FILE_MAGIC) {
            files.push(path);
        }
    }

    files.sort();
    if files.is_empty() {
        bail!("no AXIOS encrypted credential files were found in Downloads");
    }

    print_heading("ENCRYPTED CREDENTIAL ARCHIVE");
    for (index, path) in files.iter().enumerate() {
        println!(
            "[{}] {}",
            index + 1,
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("unknown.dat")
        );
    }
    println!();
    print!("Select file [1-{}]: ", files.len());
    io::stdout().flush()?;
    let selection = read_line()?
        .trim()
        .parse::<usize>()
        .context("file selection must be a number")?;
    let path = files
        .get(
            selection
                .checked_sub(1)
                .context("file selection must be at least 1")?,
        )
        .context("file selection is outside the displayed range")?;

    let mut password = read_secret_line("Enter file encryption password: ")?.into_bytes();

    if password.is_empty() {
        bail!("file encryption password cannot be empty");
    }
    let result = decrypt_file(path, &password);
    password.fill(0);
    let mut plaintext = result?;
    let document: serde_json::Value = serde_json::from_slice(&plaintext)
        .context("decrypted content is not valid credential JSON")?;

    let fields = document
        .as_object()
        .context("decrypted credential JSON is not an object")?;

    println!();
    print_heading("PRIVATE NETWORK CREDENTIAL ACCESS");

    for (name, value) in fields {
        let display = match value {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Null => "Not available".to_string(),
            other => other.to_string(),
        };

        println!("{name:<22}: {display}");
    }

    println!("Decryption status      : authenticated");
    println!("Plaintext file created : no");
    plaintext.fill(0);
    Ok(())
}

#[cfg(windows)]
fn decrypt_file(path: &PathBuf, password: &[u8]) -> Result<Vec<u8>> {
    let data = fs::read(path)
        .with_context(|| format!("cannot read encrypted file: {}", path.display()))?;
    let header_length = FILE_MAGIC.len() + 4 + 16 + 12;
    if data.len() < header_length + 16 || !data.starts_with(FILE_MAGIC) {
        bail!("invalid AXIOS encrypted credential file");
    }

    let mut offset = FILE_MAGIC.len();
    let iterations = u32::from_le_bytes(data[offset..offset + 4].try_into()?);
    offset += 4;
    if iterations != PBKDF2_ITERATIONS {
        bail!("unsupported credential-file key derivation parameters");
    }
    let salt = &data[offset..offset + 16];
    offset += 16;
    let nonce = &data[offset..offset + 12];
    offset += 12;
    let header = &data[..offset];
    let tag = &data[offset..offset + 16];
    let ciphertext = &data[offset + 16..];

    let mut key = pbkdf2_hmac_sha256(password, salt, iterations);
    let result = cng::aes_256_gcm_decrypt(&key, nonce, header, tag, ciphertext);
    key.fill(0);
    result.context("wrong password or encrypted file was modified")
}

#[cfg(windows)]
fn print_heading(title: &str) {
    println!("{title}");
    println!("{}", "=".repeat(title.chars().count()));
}

#[cfg(windows)]
fn read_secret_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    let input = unsafe { get_std_handle(STD_INPUT_HANDLE) };

    if input == 0 || input == INVALID_HANDLE_VALUE {
        bail!("Windows console input handle is unavailable");
    }

    let mut original_mode = 0_u32;

    if unsafe { get_console_mode(input, &mut original_mode) } == 0 {
        bail!("Windows console input mode is unavailable");
    }

    let protected_mode = original_mode & !ENABLE_ECHO_INPUT;

    if unsafe { set_console_mode(input, protected_mode) } == 0 {
        bail!("cannot disable console input echo");
    }

    let read_result = read_line();
    let restored = unsafe { set_console_mode(input, original_mode) };

    println!();

    if restored == 0 {
        bail!("cannot restore console input mode");
    }

    let mut value = read_result?;
    trim_line_ending(&mut value);

    Ok(value)
}

#[cfg(windows)]
fn read_line() -> Result<String> {
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value)
}

#[cfg(windows)]
fn trim_line_ending(value: &mut String) {
    while matches!(value.as_bytes().last(), Some(b'\n' | b'\r')) {
        value.pop();
    }
}

#[cfg(windows)]
fn collect_active_wifi_credential() -> Result<WifiCredential> {
    let interfaces = netsh(&["wlan", "show", "interfaces"])?;
    let ssid =
        field(&interfaces, &["ssid"], &["bssid"]).context("no active Wi-Fi SSID was found")?;
    let authentication = field(&interfaces, &["authentication", "authentification"], &[])
        .unwrap_or_else(|| "unknown".to_string());
    let cipher = field(&interfaces, &["cipher", "chiffrement"], &[])
        .unwrap_or_else(|| "unknown".to_string());

    let profile_argument = format!("name={ssid}");
    let profile = netsh(&[
        "wlan",
        "show",
        "profile",
        profile_argument.as_str(),
        "key=clear",
    ])?;
    let password = field(
        &profile,
        &["key content", "contenu de la clé", "contenu de la cle"],
        &[],
    )
    .context("the active Wi-Fi profile did not expose a stored credential")?;

    Ok(WifiCredential {
        ssid,
        authentication,
        cipher,
        password,
    })
}

#[cfg(windows)]
fn netsh(arguments: &[&str]) -> Result<String> {
    let output = Command::new("netsh.exe")
        .args(arguments)
        .output()
        .context("failed to start netsh.exe")?;

    if !output.status.success() {
        bail!(
            "netsh.exe failed with exit code {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(windows)]
fn field(output: &str, accepted: &[&str], rejected: &[&str]) -> Option<String> {
    output.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        let normalized = name.trim().to_lowercase();
        let accepted = accepted.iter().any(|item| normalized == *item);
        let rejected = rejected.iter().any(|item| normalized == *item);
        let value = value.trim();

        (accepted && !rejected && !value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(windows)]
fn encrypt_and_save(credential: &WifiCredential, password: &[u8]) -> Result<PathBuf> {
    let computer = env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string());
    let user = env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
    let mut plaintext = serde_json::to_vec_pretty(&json!({
        "SSID": credential.ssid,
        "Authentication": credential.authentication,
        "Cipher": credential.cipher,
        "Wi-Fi password": credential.password,
        "Export date": Utc::now().to_rfc3339(),
        "Computer identity": computer,
        "Windows user": user,
    }))?;

    let random = cng::random_bytes(44)?;
    let salt = &random[0..16];
    let nonce = &random[16..28];
    let mut uuid_bytes = [0_u8; 16];
    uuid_bytes.copy_from_slice(&random[28..44]);
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40;
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;

    let mut key = pbkdf2_hmac_sha256(password, salt, PBKDF2_ITERATIONS);
    let mut authenticated_header = Vec::with_capacity(FILE_MAGIC.len() + 4 + 16 + 12);
    authenticated_header.extend_from_slice(FILE_MAGIC);
    authenticated_header.extend_from_slice(&PBKDF2_ITERATIONS.to_le_bytes());
    authenticated_header.extend_from_slice(salt);
    authenticated_header.extend_from_slice(nonce);
    let encryption_result =
        cng::aes_256_gcm_encrypt(&key, nonce, &authenticated_header, &plaintext);
    key.fill(0);
    plaintext.fill(0);
    let (ciphertext, tag) = encryption_result?;

    let downloads = downloads_directory()?;
    fs::create_dir_all(&downloads)?;
    let output = downloads.join(format_uuid(uuid_bytes) + ".dat");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .with_context(|| format!("cannot create encrypted output: {}", output.display()))?;
    file.write_all(&authenticated_header)?;
    file.write_all(&tag)?;
    file.write_all(&ciphertext)?;
    file.flush()?;
    Ok(output)
}

#[cfg(any(windows, test))]
fn format_uuid(bytes: [u8; 16]) -> String {
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(any(windows, test))]
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut initial = Vec::with_capacity(salt.len() + 4);
    initial.extend_from_slice(salt);
    initial.extend_from_slice(&1_u32.to_be_bytes());
    let mut u = hmac_sha256(password, &initial);
    let mut result = u;

    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (destination, value) in result.iter_mut().zip(u) {
            *destination ^= value;
        }
    }

    result
}

#[cfg(any(windows, test))]
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut normalized = [0_u8; 64];
    if key.len() > normalized.len() {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..64 {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

#[cfg(windows)]
mod cng {
    use anyhow::{bail, Result};
    use std::{ffi::c_void, mem, ptr};

    type Handle = *mut c_void;
    type NtStatus = i32;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    const AUTH_INFO_VERSION: u32 = 1;

    #[repr(C)]
    struct AuthenticatedCipherModeInfo {
        cb_size: u32,
        dw_info_version: u32,
        pb_nonce: *mut u8,
        cb_nonce: u32,
        pb_auth_data: *mut u8,
        cb_auth_data: u32,
        pb_tag: *mut u8,
        cb_tag: u32,
        pb_mac_context: *mut u8,
        cb_mac_context: u32,
        cb_aad: u32,
        cb_data: u64,
        dw_flags: u32,
    }

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, size: u32, flags: u32) -> NtStatus;
        fn BCryptOpenAlgorithmProvider(
            algorithm: *mut Handle,
            algorithm_id: *const u16,
            implementation: *const u16,
            flags: u32,
        ) -> NtStatus;
        fn BCryptSetProperty(
            object: Handle,
            property: *const u16,
            input: *mut u8,
            input_size: u32,
            flags: u32,
        ) -> NtStatus;
        fn BCryptGetProperty(
            object: Handle,
            property: *const u16,
            output: *mut u8,
            output_size: u32,
            result_size: *mut u32,
            flags: u32,
        ) -> NtStatus;
        fn BCryptGenerateSymmetricKey(
            algorithm: Handle,
            key: *mut Handle,
            key_object: *mut u8,
            key_object_size: u32,
            secret: *mut u8,
            secret_size: u32,
            flags: u32,
        ) -> NtStatus;
        fn BCryptEncrypt(
            key: Handle,
            input: *mut u8,
            input_size: u32,
            padding_info: *mut c_void,
            initialization_vector: *mut u8,
            initialization_vector_size: u32,
            output: *mut u8,
            output_size: u32,
            result_size: *mut u32,
            flags: u32,
        ) -> NtStatus;
        fn BCryptDecrypt(
            key: Handle,
            input: *mut u8,
            input_size: u32,
            padding_info: *mut c_void,
            initialization_vector: *mut u8,
            initialization_vector_size: u32,
            output: *mut u8,
            output_size: u32,
            result_size: *mut u32,
            flags: u32,
        ) -> NtStatus;
        fn BCryptDestroyKey(key: Handle) -> NtStatus;
        fn BCryptCloseAlgorithmProvider(algorithm: Handle, flags: u32) -> NtStatus;
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn ensure(status: NtStatus, operation: &str) -> Result<()> {
        if status < 0 {
            bail!("{operation} failed with NTSTATUS 0x{:08x}", status as u32);
        }
        Ok(())
    }

    pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
        let mut output = vec![0_u8; size];
        unsafe {
            ensure(
                BCryptGenRandom(
                    ptr::null_mut(),
                    output.as_mut_ptr(),
                    output.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                ),
                "BCryptGenRandom",
            )?;
        }
        Ok(output)
    }

    pub fn aes_256_gcm_encrypt(
        key_bytes: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16])> {
        let algorithm_name = wide("AES");
        let chaining_mode = wide("ChainingMode");
        let chaining_gcm = wide("ChainingModeGCM");
        let object_length_name = wide("ObjectLength");
        let mut algorithm = ptr::null_mut();
        let mut key = ptr::null_mut();

        unsafe {
            ensure(
                BCryptOpenAlgorithmProvider(
                    &mut algorithm,
                    algorithm_name.as_ptr(),
                    ptr::null(),
                    0,
                ),
                "BCryptOpenAlgorithmProvider",
            )?;

            let result = (|| -> Result<(Vec<u8>, [u8; 16])> {
                ensure(
                    BCryptSetProperty(
                        algorithm,
                        chaining_mode.as_ptr(),
                        chaining_gcm.as_ptr() as *mut u8,
                        (chaining_gcm.len() * 2) as u32,
                        0,
                    ),
                    "BCryptSetProperty(ChainingModeGCM)",
                )?;

                let mut object_length = 0_u32;
                let mut returned = 0_u32;
                ensure(
                    BCryptGetProperty(
                        algorithm,
                        object_length_name.as_ptr(),
                        (&mut object_length as *mut u32).cast(),
                        mem::size_of::<u32>() as u32,
                        &mut returned,
                        0,
                    ),
                    "BCryptGetProperty(ObjectLength)",
                )?;
                let mut key_object = vec![0_u8; object_length as usize];
                let mut secret = *key_bytes;
                ensure(
                    BCryptGenerateSymmetricKey(
                        algorithm,
                        &mut key,
                        key_object.as_mut_ptr(),
                        object_length,
                        secret.as_mut_ptr(),
                        secret.len() as u32,
                        0,
                    ),
                    "BCryptGenerateSymmetricKey",
                )?;
                secret.fill(0);

                let mut tag = [0_u8; 16];
                let mut nonce_buffer = nonce.to_vec();
                let mut aad_buffer = aad.to_vec();
                let mut input = plaintext.to_vec();
                let mut output = vec![0_u8; plaintext.len()];
                let mut output_size = 0_u32;
                let mut auth = AuthenticatedCipherModeInfo {
                    cb_size: mem::size_of::<AuthenticatedCipherModeInfo>() as u32,
                    dw_info_version: AUTH_INFO_VERSION,
                    pb_nonce: nonce_buffer.as_mut_ptr(),
                    cb_nonce: nonce_buffer.len() as u32,
                    pb_auth_data: aad_buffer.as_mut_ptr(),
                    cb_auth_data: aad_buffer.len() as u32,
                    pb_tag: tag.as_mut_ptr(),
                    cb_tag: tag.len() as u32,
                    pb_mac_context: ptr::null_mut(),
                    cb_mac_context: 0,
                    cb_aad: 0,
                    cb_data: 0,
                    dw_flags: 0,
                };
                ensure(
                    BCryptEncrypt(
                        key,
                        input.as_mut_ptr(),
                        input.len() as u32,
                        (&mut auth as *mut AuthenticatedCipherModeInfo).cast(),
                        ptr::null_mut(),
                        0,
                        output.as_mut_ptr(),
                        output.len() as u32,
                        &mut output_size,
                        0,
                    ),
                    "BCryptEncrypt(AES-256-GCM)",
                )?;
                output.truncate(output_size as usize);
                input.fill(0);
                Ok((output, tag))
            })();

            if !key.is_null() {
                BCryptDestroyKey(key);
            }
            if !algorithm.is_null() {
                BCryptCloseAlgorithmProvider(algorithm, 0);
            }
            result
        }
    }

    pub fn aes_256_gcm_decrypt(
        key_bytes: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        tag: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        crypt(false, key_bytes, nonce, aad, tag, ciphertext).map(|(output, _)| output)
    }

    fn crypt(
        _encrypt: bool,
        key_bytes: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        input_tag: &[u8],
        input_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16])> {
        let algorithm_name = wide("AES");
        let chaining_mode = wide("ChainingMode");
        let chaining_gcm = wide("ChainingModeGCM");
        let object_length_name = wide("ObjectLength");
        let mut algorithm = ptr::null_mut();
        let mut key = ptr::null_mut();

        unsafe {
            ensure(
                BCryptOpenAlgorithmProvider(
                    &mut algorithm,
                    algorithm_name.as_ptr(),
                    ptr::null(),
                    0,
                ),
                "BCryptOpenAlgorithmProvider",
            )?;
            let result = (|| -> Result<(Vec<u8>, [u8; 16])> {
                ensure(
                    BCryptSetProperty(
                        algorithm,
                        chaining_mode.as_ptr(),
                        chaining_gcm.as_ptr() as *mut u8,
                        (chaining_gcm.len() * 2) as u32,
                        0,
                    ),
                    "BCryptSetProperty(ChainingModeGCM)",
                )?;
                let mut object_length = 0_u32;
                let mut returned = 0_u32;
                ensure(
                    BCryptGetProperty(
                        algorithm,
                        object_length_name.as_ptr(),
                        (&mut object_length as *mut u32).cast(),
                        mem::size_of::<u32>() as u32,
                        &mut returned,
                        0,
                    ),
                    "BCryptGetProperty(ObjectLength)",
                )?;
                let mut key_object = vec![0_u8; object_length as usize];
                let mut secret = *key_bytes;
                ensure(
                    BCryptGenerateSymmetricKey(
                        algorithm,
                        &mut key,
                        key_object.as_mut_ptr(),
                        object_length,
                        secret.as_mut_ptr(),
                        secret.len() as u32,
                        0,
                    ),
                    "BCryptGenerateSymmetricKey",
                )?;
                secret.fill(0);
                let mut tag = [0_u8; 16];
                tag.copy_from_slice(input_tag);
                let mut nonce_buffer = nonce.to_vec();
                let mut aad_buffer = aad.to_vec();
                let mut input = input_data.to_vec();
                let mut output = vec![0_u8; input.len()];
                let mut output_size = 0_u32;
                let mut auth = AuthenticatedCipherModeInfo {
                    cb_size: mem::size_of::<AuthenticatedCipherModeInfo>() as u32,
                    dw_info_version: AUTH_INFO_VERSION,
                    pb_nonce: nonce_buffer.as_mut_ptr(),
                    cb_nonce: nonce_buffer.len() as u32,
                    pb_auth_data: aad_buffer.as_mut_ptr(),
                    cb_auth_data: aad_buffer.len() as u32,
                    pb_tag: tag.as_mut_ptr(),
                    cb_tag: tag.len() as u32,
                    pb_mac_context: ptr::null_mut(),
                    cb_mac_context: 0,
                    cb_aad: 0,
                    cb_data: 0,
                    dw_flags: 0,
                };
                ensure(
                    BCryptDecrypt(
                        key,
                        input.as_mut_ptr(),
                        input.len() as u32,
                        (&mut auth as *mut AuthenticatedCipherModeInfo).cast(),
                        ptr::null_mut(),
                        0,
                        output.as_mut_ptr(),
                        output.len() as u32,
                        &mut output_size,
                        0,
                    ),
                    "BCryptDecrypt(AES-256-GCM)",
                )?;
                output.truncate(output_size as usize);
                input.fill(0);
                Ok((output, tag))
            })();
            if !key.is_null() {
                BCryptDestroyKey(key);
            }
            if !algorithm.is_null() {
                BCryptCloseAlgorithmProvider(algorithm, 0);
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_rfc_6070_style_sha256_vector() {
        assert_eq!(
            hex::encode(pbkdf2_hmac_sha256(b"password", b"salt", 1)),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn generated_name_has_uuid_shape() {
        let name = format_uuid([0_u8; 16]);
        assert_eq!(name.len(), 36);
        assert_eq!(&name[8..9], "-");
        assert_eq!(&name[13..14], "-");
        assert_eq!(&name[18..19], "-");
        assert_eq!(&name[23..24], "-");
    }
}
