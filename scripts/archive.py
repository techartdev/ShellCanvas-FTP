"""Archive CI adapter packages while preserving executable permissions."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo
import sys


def archive(source: Path, output: Path) -> None:
    with ZipFile(output, "w", ZIP_DEFLATED) as package:
        for file in sorted(source.rglob("*")):
            if not file.is_file():
                continue
            name = file.relative_to(source).as_posix()
            info = ZipInfo(name)
            info.create_system = 3
            info.external_attr = (0o100755 if name.startswith("bin/") else 0o100644) << 16
            info.compress_type = ZIP_DEFLATED
            package.writestr(info, file.read_bytes())


if __name__ == "__main__":
    source_root, output_root = map(Path, sys.argv[1:3])
    output_root.mkdir(parents=True, exist_ok=True)
    for source in sorted(source_root.glob("ftp-*")):
        destination = output_root / f"shellcanvas-{source.name}.zip"
        archive(source, destination)
        print(destination)
