Name: alt-hardening-scanner
Version: 1.0.0
Release: alt1

Summary: ALT Linux workstation hardening scanner
License: MIT
Group: Graphical desktop/GNOME
Url: https://github.com/firstbeelancer/alt-hardening-scanner
Source0: %name-%version.tar.gz

BuildRequires: rust-cargo
BuildRequires: libgtk4-devel
BuildRequires: libadwaita-devel
BuildRequires: libglib2-devel
BuildRequires: pkg-config
BuildRequires: desktop-file-utils
BuildRequires: appstream

Requires: libgtk4
Requires: libadwaita

%description
ALT Hardening Scanner is a native GTK4/libadwaita application for scanning
and applying secure configuration parameters for ALT Linux Workstation 11
according to the FSTEC Linux hardening recommendations dated 25.12.2022.

%prep
%setup -q

%build
cargo build --release

%install
install -Dpm0755 target/release/%name %{buildroot}%_bindir/%name
install -Dpm0644 data/alt-hardening-scanner.desktop %{buildroot}%_desktopdir/alt-hardening-scanner.desktop
install -Dpm0644 data/alt-hardening-scanner.metainfo.xml %{buildroot}%_metainfodir/alt-hardening-scanner.metainfo.xml
install -Dpm0644 data/icons/hicolor/48x48/apps/alt-hardening-scanner.png %{buildroot}%_iconsdir/hicolor/48x48/apps/alt-hardening-scanner.png
install -Dpm0644 data/icons/hicolor/128x128/apps/alt-hardening-scanner.png %{buildroot}%_iconsdir/hicolor/128x128/apps/alt-hardening-scanner.png
install -Dpm0644 data/icons/hicolor/scalable/apps/alt-hardening-scanner.svg %{buildroot}%_iconsdir/hicolor/scalable/apps/alt-hardening-scanner.svg

%files
%_bindir/%name
%_desktopdir/alt-hardening-scanner.desktop
%_metainfodir/alt-hardening-scanner.metainfo.xml
%_iconsdir/hicolor/48x48/apps/alt-hardening-scanner.png
%_iconsdir/hicolor/128x128/apps/alt-hardening-scanner.png
%_iconsdir/hicolor/scalable/apps/alt-hardening-scanner.svg

%changelog
* Mon Mar 30 2026 firstbeelancer <noreply@github.com> 1.0.0-alt1
- Initial ALT Linux native GTK4/libadwaita packaging
