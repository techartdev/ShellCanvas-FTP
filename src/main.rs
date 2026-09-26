// SPDX-License-Identifier: MPL-2.0
//! Read-only FTP/explicit FTPS Files provider for ShellCanvas.
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Seek, SeekFrom},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use shellcanvas_adapter_sdk::{
    async_trait, json, run, Adapter, CallError, RequestContext, ServiceDescriptor,
};
use suppaftp::{
    list::{File, ListParser},
    native_tls::TlsConnector,
    types::FileType,
    FtpError, NativeTlsConnector, NativeTlsFtpStream,
};
use tempfile::NamedTempFile;

const TIMEOUT: Duration = Duration::from_secs(12);
const MAX_PREVIEW: usize = 64 * 1024;

#[derive(Clone, Deserialize)]
struct Config {
    host: String,
    port: u16,
    username: String,
    password: String,
    #[serde(default = "default_tls")]
    tls: bool,
    #[serde(default, rename = "trustCertificate")]
    trust_certificate: bool,
}

fn default_tls() -> bool {
    true
}

impl Config {
    fn validate(&self) -> Result<(), CallError> {
        if self.host.trim().is_empty()
            || self.username.is_empty()
            || self.port == 0
            || self
                .host
                .chars()
                .any(|c| c.is_control() || c == '/' || c == '\\')
            || self.username.chars().any(char::is_control)
            || self.password.chars().any(char::is_control)
        {
            return Err(invalid("Invalid FTP connection settings"));
        }
        Ok(())
    }

    fn connect(&self) -> Result<NativeTlsFtpStream, CallError> {
        let addresses = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|_| unavailable("Could not resolve FTP host"))?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, TIMEOUT) {
                Ok(socket) => {
                    socket.set_read_timeout(Some(TIMEOUT)).ok();
                    socket.set_write_timeout(Some(TIMEOUT)).ok();
                    let mut ftp = NativeTlsFtpStream::connect_with_stream(socket)
                        .map_err(|_| unavailable("FTP server did not respond"))?
                        .passive_stream_builder(|address| {
                            let data = TcpStream::connect_timeout(&address, TIMEOUT)
                                .map_err(FtpError::ConnectionError)?;
                            data.set_read_timeout(Some(TIMEOUT))
                                .map_err(FtpError::ConnectionError)?;
                            data.set_write_timeout(Some(TIMEOUT))
                                .map_err(FtpError::ConnectionError)?;
                            Ok(data)
                        });
                    ftp.set_passive_nat_workaround(true);
                    if self.tls {
                        let tls = TlsConnector::builder()
                            .danger_accept_invalid_certs(self.trust_certificate)
                            .build()
                            .map_err(|_| unavailable("Could not initialize TLS"))?;
                        ftp = ftp
                            .into_secure(NativeTlsConnector::from(tls), &self.host)
                            .map_err(|_| {
                                unavailable("FTPS negotiation or certificate validation failed")
                            })?;
                    }
                    ftp.login(&self.username, &self.password)
                        .map_err(|_| denied("FTP login was rejected"))?;
                    ftp.transfer_type(FileType::Binary)
                        .map_err(|_| unavailable("FTP server rejected binary transfer mode"))?;
                    return Ok(ftp);
                }
                Err(error) => last_error = Some(error),
            }
        }
        let _ = last_error;
        Err(unavailable("Could not connect to FTP server"))
    }
}

fn invalid(message: &str) -> CallError {
    CallError::new("invalid", message)
}
fn denied(message: &str) -> CallError {
    CallError::new("denied", message)
}
fn unavailable(message: &str) -> CallError {
    CallError::new("unavailable", message)
}
fn failed(message: &str) -> CallError {
    CallError::new("failed", message)
}

fn valid_path(path: &str, home: &str) -> Result<(), CallError> {
    if !path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| part == "." || part == "..")
        || (home != "/" && path != home && !path.starts_with(&format!("{home}/")))
    {
        return Err(invalid("Path is outside this FTP connection"));
    }
    Ok(())
}

fn parent(path: &str, home: &str) -> Option<String> {
    if path == home {
        return None;
    }
    let stripped = path.trim_end_matches('/');
    let index = stripped.rfind('/')?;
    Some(if index == 0 {
        "/".into()
    } else {
        stripped[..index].into()
    })
}

fn join(path: &str, name: &str) -> Result<String, CallError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return Err(invalid("FTP listing contains an invalid name"));
    }
    Ok(format!("{}/{}", path.trim_end_matches('/'), name))
}

fn hash(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    hex::encode(digest.finalize())
}

fn location(path: &str, home: &str) -> Value {
    let name = if path == home {
        "FTP home"
    } else {
        path.rsplit('/').next().unwrap_or(path)
    };
    json!({"path":path,"name":name,"parent":parent(path, home)})
}

fn entries(ftp: &mut NativeTlsFtpStream, path: &str) -> Result<Vec<Value>, CallError> {
    ftp.cwd(path)
        .map_err(|_| invalid("FTP folder is unavailable"))?;
    let (lines, machine) = match ftp.mlsd(None) {
        Ok(lines) => (lines, true),
        Err(_) => (
            ftp.list(None)
                .map_err(|_| unavailable("FTP server cannot list this folder"))?,
            false,
        ),
    };
    let mut result = Vec::with_capacity(lines.len());
    for line in lines {
        let parsed: File = if machine {
            ListParser::parse_mlsd(&line)
        } else {
            ListParser::parse_posix(&line).or_else(|_| ListParser::parse_dos(&line))
        }
        .map_err(|_| unavailable("FTP server returned an unsupported directory listing"))?;
        if parsed.name() == "." || parsed.name() == ".." || parsed.is_symlink() {
            continue;
        }
        let item_path = join(path, parsed.name())?;
        let kind = if parsed.is_directory() {
            "directory"
        } else {
            "file"
        };
        let modified = parsed
            .modified()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u32::try_from(time.as_secs()).ok());
        let size = if parsed.is_directory() {
            0
        } else {
            parsed.size() as u64
        };
        let revision = hash(&[
            &item_path,
            kind,
            &size.to_string(),
            &format!("{modified:?}"),
        ]);
        result.push(json!({"path":item_path,"name":parsed.name(),"kind":kind,
            "size":size,"modified":modified,"revision":revision}));
    }
    result.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(result)
}

fn entry(ftp: &mut NativeTlsFtpStream, path: &str, home: &str) -> Result<Value, CallError> {
    let folder = parent(path, home).ok_or_else(|| invalid("FTP home is not a file"))?;
    entries(ftp, &folder)?
        .into_iter()
        .find(|item| item["path"] == path)
        .ok_or_else(|| invalid("FTP item was not found"))
}

fn string<'a>(params: &'a Value, field: &str) -> Result<&'a str, CallError> {
    params
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Missing request field"))
}

struct Download {
    file: NamedTempFile,
    path: String,
    revision: String,
    size: u64,
}
#[derive(Default)]
struct Transfers {
    active: HashMap<String, Download>,
    opening: HashSet<String>,
    retired: HashSet<String>,
}

#[derive(Default)]
struct Device {
    connection: Mutex<Option<(Config, String)>>,
    transfers: Arc<Mutex<Transfers>>,
}

impl Device {
    fn connected(&self) -> Result<(Config, String), CallError> {
        self.connection
            .lock()
            .map_err(|_| failed("FTP state is unavailable"))?
            .clone()
            .ok_or_else(|| unavailable("FTP is not connected"))
    }
}

#[async_trait]
impl Adapter for Device {
    async fn initialize(
        &self,
        configuration: Value,
        context: RequestContext,
    ) -> Result<Vec<ServiceDescriptor>, CallError> {
        let config: Config = serde_json::from_value(configuration)
            .map_err(|_| invalid("Invalid FTP connection settings"))?;
        config.validate()?;
        let setup = config.clone();
        let home = tokio::task::spawn_blocking(move || {
            let mut ftp = setup.connect()?;
            let home = ftp
                .pwd()
                .map_err(|_| unavailable("FTP server did not provide a home folder"))?;
            if !home.starts_with('/') {
                return Err(unavailable(
                    "FTP server returned a non-absolute home folder",
                ));
            }
            Ok::<_, CallError>(home.trim_end_matches('/').to_owned())
        })
        .await
        .map_err(|_| failed("FTP setup failed"))??;
        if context.is_canceled() {
            return Err(CallError::new("aborted", "FTP setup canceled"));
        }
        let home = if home.is_empty() { "/".into() } else { home };
        *self
            .connection
            .lock()
            .map_err(|_| failed("FTP state is unavailable"))? = Some((config, home));
        Ok(vec![ServiceDescriptor {
            id: "files".into(),
            version: 1,
            methods: [
                "files.list",
                "files.locate",
                "files.preview",
                "files.readText",
                "files.download.open",
                "files.download.read",
                "files.download.finish",
                "files.transfer.abort",
            ]
            .map(String::from)
            .into(),
        }])
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        context: RequestContext,
    ) -> Result<Value, CallError> {
        if context.is_canceled() {
            return Err(CallError::new("aborted", "FTP request canceled"));
        }
        let (config, home) = self.connected()?;
        match method {
            "files.transfer.abort" => {
                let id = string(&params, "id")?.to_owned();
                let mut transfers = self
                    .transfers
                    .lock()
                    .map_err(|_| failed("FTP state is unavailable"))?;
                transfers.active.remove(&id);
                transfers.opening.remove(&id);
                transfers.retired.insert(id);
                Ok(Value::Null)
            }
            "files.download.read" => {
                let id = string(&params, "id")?;
                let offset = params["offset"]
                    .as_u64()
                    .ok_or_else(|| invalid("Invalid download offset"))?;
                let max = params["maxBytes"]
                    .as_u64()
                    .filter(|n| (1..=32768).contains(n))
                    .ok_or_else(|| invalid("Invalid download size"))?
                    as usize;
                let mut transfers = self
                    .transfers
                    .lock()
                    .map_err(|_| failed("FTP state is unavailable"))?;
                let download = transfers
                    .active
                    .get_mut(id)
                    .ok_or_else(|| invalid("Unknown download"))?;
                if offset > download.size {
                    return Err(invalid("Download offset exceeds file size"));
                }
                download
                    .file
                    .as_file_mut()
                    .seek(SeekFrom::Start(offset))
                    .map_err(|_| failed("Could not seek staged download"))?;
                let mut bytes = vec![0; max.min((download.size - offset) as usize)];
                let count = download
                    .file
                    .as_file_mut()
                    .read(&mut bytes)
                    .map_err(|_| failed("Could not read staged download"))?;
                bytes.truncate(count);
                Ok(json!(bytes))
            }
            "files.download.finish" => {
                let id = string(&params, "id")?.to_owned();
                let download = self
                    .transfers
                    .lock()
                    .map_err(|_| failed("FTP state is unavailable"))?
                    .active
                    .remove(&id)
                    .ok_or_else(|| invalid("Unknown download"))?;
                tokio::task::spawn_blocking(move || {
                    let mut ftp = config.connect()?;
                    let current = entry(&mut ftp, &download.path, &home)?;
                    if current["revision"] != download.revision {
                        return Err(failed("FTP source changed during download"));
                    }
                    Ok(Value::Null)
                })
                .await
                .map_err(|_| failed("FTP verification failed"))?
            }
            "files.download.open" => {
                let id = string(&params, "id")?.to_owned();
                let path = string(&params, "path")?.to_owned();
                let revision = string(&params, "revision")?.to_owned();
                valid_path(&path, &home)?;
                {
                    let mut transfers = self
                        .transfers
                        .lock()
                        .map_err(|_| failed("FTP state is unavailable"))?;
                    if transfers.retired.contains(&id)
                        || transfers.active.contains_key(&id)
                        || !transfers.opening.insert(id.clone())
                        || transfers.active.len() + transfers.opening.len() > 32
                    {
                        return Err(invalid("Download ID is unavailable"));
                    }
                }
                let staged = tokio::task::spawn_blocking(move || {
                    let mut ftp = config.connect()?;
                    let current = entry(&mut ftp, &path, &home)?;
                    if current["kind"] != "file" || current["revision"] != revision {
                        return Err(failed("FTP source changed before download"));
                    }
                    let size = current["size"]
                        .as_u64()
                        .ok_or_else(|| failed("FTP size is unavailable"))?;
                    let mut file =
                        NamedTempFile::new().map_err(|_| failed("Could not stage FTP download"))?;
                    let mut stream = ftp
                        .retr_as_stream(&path)
                        .map_err(|_| unavailable("FTP server refused download"))?;
                    let copied = std::io::copy(&mut stream, &mut file)
                        .map_err(|_| failed("FTP download was interrupted"))?;
                    stream
                        .finish()
                        .map_err(|_| failed("FTP download did not finish"))?;
                    if copied != size {
                        return Err(failed("FTP download size changed"));
                    }
                    let current = entry(&mut ftp, &path, &home)?;
                    if current["revision"] != revision {
                        return Err(failed("FTP source changed during download"));
                    }
                    Ok::<_, CallError>((file, path, revision, size))
                })
                .await
                .map_err(|_| failed("FTP download failed"))?;
                let mut transfers = self
                    .transfers
                    .lock()
                    .map_err(|_| failed("FTP state is unavailable"))?;
                transfers.opening.remove(&id);
                if transfers.retired.contains(&id) {
                    return Err(CallError::new("aborted", "FTP download canceled"));
                }
                let (file, path, revision, size) = staged?;
                transfers.active.insert(
                    id,
                    Download {
                        file,
                        path: path.clone(),
                        revision,
                        size,
                    },
                );
                Ok(json!({"location":location(&path, &self.connected()?.1),"size":size}))
            }
            "files.list" | "files.locate" | "files.preview" | "files.readText" => {
                let method = method.to_owned();
                tokio::task::spawn_blocking(move || {
                    let mut ftp = config.connect()?;
                    let path = match params.get("path") {
                        None | Some(Value::Null) => home.clone(),
                        Some(Value::String(path)) => path.clone(),
                        _ => return Err(invalid("Invalid FTP path")),
                    };
                    valid_path(&path, &home)?;
                    match method.as_str() {
                        "files.list" => {
                            let limit = params["limit"].as_u64().filter(|n| (1..=128).contains(n))
                                .ok_or_else(|| invalid("Invalid page size"))? as usize;
                            let all = entries(&mut ftp, &path)?;
                            let fingerprint = hash(&[&path, &serde_json::to_string(&all).unwrap_or_default()]);
                            let start = match params.get("cursor") {
                                None | Some(Value::Null) => 0,
                                Some(Value::String(cursor)) => {
                                    let (digest, offset) = cursor.split_once(':').ok_or_else(|| invalid("Invalid FTP page cursor"))?;
                                    let offset = offset.parse::<usize>().map_err(|_| invalid("Invalid FTP page cursor"))?;
                                    if digest != fingerprint || offset == 0 || offset >= all.len() {
                                        return Err(failed("FTP folder changed while browsing"));
                                    }
                                    offset
                                }
                                _ => return Err(invalid("Invalid FTP page cursor")),
                            };
                            let end = (start + limit).min(all.len());
                            let next = (end < all.len()).then(|| format!("{fingerprint}:{end}"));
                            Ok(json!({"directory":{"path":path,"name":location(&path,&home)["name"],
                                "parent":parent(&path,&home),"home":{"path":home,"name":"FTP home"},
                                "roots":[{"path":home,"name":"FTP home"}],"entries":&all[start..end]},"next":next}))
                        }
                        "files.locate" => {
                            if path != home { entry(&mut ftp, &path, &home)?; }
                            Ok(location(&path, &home))
                        }
                        _ => {
                            let item = entry(&mut ftp, &path, &home)?;
                            if item["kind"] != "file" { return Err(invalid("FTP item is not a file")); }
                            let size = item["size"].as_u64().unwrap_or(u64::MAX);
                            let limit = if method == "files.preview" { MAX_PREVIEW } else { 2 * 1024 * 1024 };
                            if size > limit as u64 { return Err(unavailable("FTP text file is too large to open as text")); }
                            let bytes = ftp.retr_as_buffer(&path).map_err(|_| unavailable("FTP server refused file read"))?.into_inner();
                            if bytes.len() > limit { return Err(unavailable("FTP text file is too large to open as text")); }
                            let text = String::from_utf8(bytes).map_err(|_| invalid("FTP file is not UTF-8 text"))?;
                            if method == "files.preview" { Ok(json!(text)) }
                            else { Ok(json!({"path":path,"parent":parent(&path,&home),
                                "name":item["name"],"text":text,"revision":item["revision"],"writable":false})) }
                        }
                    }
                }).await.map_err(|_| failed("FTP request failed"))?
            }
            _ => Err(unavailable("Unsupported FTP operation")),
        }
    }
}

fn main() -> std::io::Result<()> {
    run(Device::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_cannot_escape_or_inject_commands() {
        assert!(valid_path("/home/site/a b", "/home/site").is_ok());
        for bad in [
            "/home/site/../other",
            "/home/site2/file",
            "/home/site/a\r\nDELE x",
            "relative",
        ] {
            assert!(valid_path(bad, "/home/site").is_err(), "{bad}");
        }
        assert!(join("/home/site", "a/b").is_err());
    }
}
