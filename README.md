# ShellCanvas FTP files adapter

This independent connection adapter gives ShellCanvas a read-only Files source for FTP servers. It supports folder browsing, small UTF-8 previews and text reads, and binary file downloads. Upload, rename, deletion, editing and folder transfers are not advertised. It does not use an SSH connection or SSH credentials.

Download the [v0.1.0 preview package](https://github.com/techartdev/ShellCanvas-FTP/releases/tag/v0.1.0) for your platform, extract it, and select `adapter.json` under **App Manager > Connection adapters > Install adapter**. Review the native-code request before installing. ShellCanvas PR #34 also adds a suggested FTP entry that fetches the same version directly.

The default is explicit FTPS with normal server certificate validation. **Trust self-signed FTPS certificate** is an explicit exception for servers you already trust. Uncheck **Use explicit FTPS (TLS)** only when you knowingly need plain FTP. Plain FTP sends credentials and data without encryption. If the server supports only implicit FTPS, this adapter cannot connect yet.

Build and package on the target platform:

```sh
cargo build --release --locked
shellcanvas-adapter pack adapter.source.json target/release/shellcanvas-ftp NEW_PACKAGE_DIRECTORY
shellcanvas-adapter validate NEW_PACKAGE_DIRECTORY/adapter.json
```

On Windows, use `target/release/shellcanvas-ftp.exe`. The ShellCanvas adapter CLI is supplied by `shellcanvas-adapter-sdk` and by the desktop source checkout. In ShellCanvas, open App Manager > Connection adapters > Install adapter and select the package's `adapter.json`. Then choose **Use connection adapters** in the connection dialog and assign this adapter to Files.

The adapter opens a new authenticated FTP connection per operation. Downloads stage data in an OS temporary file before it is exposed to ShellCanvas, so the adapter can return fixed-size chunks and verify the source again at completion. Temporary files are removed on finish, abort, or process exit. The server needs passive data connections in addition to its control port.

This adapter uses [suppaftp](https://github.com/veeso/suppaftp) 12.1 or later and a vendored copy of the MPL-2.0 ShellCanvas adapter SDK. No secrets are packaged or written to its repository.
