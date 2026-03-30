# ALT Hardening Scanner

Native GTK4/libadwaita application for ALT Linux Workstation 11. The utility scans and applies hardening parameters from FSTEC Linux recommendations dated 25.12.2022.

## What was wrong with the old GitHub version

The original repository revision was based on Tauri plus a web UI and was not suitable for the ALT Linux packaging rules used for this project:

- it relied on Tauri instead of native GTK4/libadwaita
- it targeted multiple distributions and bundle formats (`rpm`, `deb`, `appimage`)
- it did not follow the expected ALT RPM project layout
- it did not provide a clean ALT-native `.desktop`, AppStream metadata, or spec-driven build flow

This branch rebuilds the application as a native Rust desktop app intended specifically for ALT Linux packaging.

## Project layout

- `src/` - native Rust application code
- `data/` - desktop file, AppStream metadata, icon, CSS
- `rpm/` - ALT RPM spec and reserved patch slot
- `build/rpmbuild/` - local RPM build root inside the repository
- `deps/` - placeholder for missing ALT dependencies if any are needed later

## Checked ALT dependencies

The packaging rules require verifying ALT repository packages before the rebuild. The current spec expects the following ALT packages in the target branch:

- `rust-cargo`
- `libgtk4-devel`
- `libadwaita-devel`
- `libglib2-devel`
- `pkg-config`
- `desktop-file-utils`
- `appstream`

Runtime:

- `libgtk4`
- `libadwaita`

## Local build on ALT Linux

Install dependencies:

```bash
su -
apt-get update
apt-get install rust-cargo libgtk4-devel libadwaita-devel libglib2-devel pkg-config desktop-file-utils appstream
```

Build the binary:

```bash
cd alt-hardening-scanner
cargo build --release
```

Result:

```text
target/release/alt-hardening-scanner
```

## Build RPM inside the project directory

```bash
cd alt-hardening-scanner
make rpm
```

The package is built in:

```text
build/rpmbuild/RPMS/
```

## Notes

- the current codebase is fully switched to the native GTK4/libadwaita layout and no longer uses the old Tauri/web stack
- package verification was performed against ALT Linux package repositories for the ALT 11 target flow
- PDF export currently relies on `wkhtmltopdf` if available on the target system
- applying hardening parameters still requires root privileges because the tool edits `/etc/sysctl.conf` and `/etc/default/grub`
