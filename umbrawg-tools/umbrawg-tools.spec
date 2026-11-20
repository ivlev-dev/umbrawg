Name:           umbrawg-tools
Version:        0.4.0
Release:        1%{?dist}
Summary:        Rust command-line tools for the UmbraWG VPN
License:        GPL-2.0-only
URL:            https://github.com/ivlev-dev/umbrawg
Source0:        https://github.com/ivlev-dev/umbrawg/archive/refs/tags/tools-v%{version}.tar.gz
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  rust >= 1.85
BuildRequires:  systemd-rpm-macros
Requires:       iproute
Recommends:     (nftables or iptables)
Suggests:       umbrawg
%{?systemd_requires}

%description
UmbraWG is a WireGuard-compatible VPN protocol with an additional
obfuscation layer.

This package provides the Rust utilities:

  * uwg - read and change UmbraWG interface configuration;
  * uwg-quick - bring interfaces up and down from configuration files.

Both kernel netlink and the userspace umbrawg daemon (UAPI sockets) are
supported. Man pages, shell completions, and systemd units are included.

%prep
%autosetup -n umbrawg-tools

%build
cargo build --release -p uwg -p uwg-quick

%install
install -Dpm0755 target/release/uwg %{buildroot}%{_bindir}/uwg
install -Dpm0755 target/release/uwg-quick %{buildroot}%{_bindir}/uwg-quick
install -Dpm0644 man/uwg.8 %{buildroot}%{_mandir}/man8/uwg.8
install -Dpm0644 man/uwg-quick.8 %{buildroot}%{_mandir}/man8/uwg-quick.8
install -Dpm0644 completions/uwg.bash %{buildroot}%{_datadir}/bash-completion/completions/uwg
install -Dpm0644 completions/uwg-quick.bash %{buildroot}%{_datadir}/bash-completion/completions/uwg-quick
install -Dpm0644 completions/_uwg %{buildroot}%{_datadir}/zsh/site-functions/_uwg
install -Dpm0644 completions/_uwg-quick %{buildroot}%{_datadir}/zsh/site-functions/_uwg-quick
install -Dpm0644 completions/uwg.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/uwg.fish
install -Dpm0644 completions/uwg-quick.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/uwg-quick.fish
install -Dpm0644 systemd/uwg-quick@.service %{buildroot}%{_unitdir}/uwg-quick@.service
install -Dpm0644 systemd/uwg-quick.target %{buildroot}%{_unitdir}/uwg-quick.target
install -Dpm0644 systemd/umbrawg@.service %{buildroot}%{_unitdir}/umbrawg@.service
install -d -m0700 %{buildroot}%{_sysconfdir}/umbrawg

%post
%systemd_post uwg-quick@.service uwg-quick.target umbrawg@.service

%preun
%systemd_preun uwg-quick@.service uwg-quick.target umbrawg@.service

%postun
%systemd_postun_with_restart uwg-quick@.service uwg-quick.target umbrawg@.service

%files
%license COPYING
%doc README.md CHANGELOG.md
%{_bindir}/uwg
%{_bindir}/uwg-quick
%dir %attr(0700,root,root) %{_sysconfdir}/umbrawg
%{_mandir}/man8/uwg.8*
%{_mandir}/man8/uwg-quick.8*
%{_datadir}/bash-completion/completions/uwg
%{_datadir}/bash-completion/completions/uwg-quick
%{_datadir}/zsh/site-functions/_uwg
%{_datadir}/zsh/site-functions/_uwg-quick
%{_datadir}/fish/vendor_completions.d/uwg.fish
%{_datadir}/fish/vendor_completions.d/uwg-quick.fish
%{_unitdir}/uwg-quick@.service
%{_unitdir}/uwg-quick.target
%{_unitdir}/umbrawg@.service

%changelog
* Fri Nov 20 2026 Yuri Egorov <ye@umbra.org> - 0.4.0-1
- Add underlay-mtu, bbr-stats and fec-stats to uwg show/set

* Fri Nov 20 2026 Yuri Egorov <ye@umbra.org> - 0.3.0-1
- Add BBRv3 and FEC configuration for kernel and userspace interfaces
- Document netlink BBR/FEC attributes and obfuscation trade-offs

* Mon Nov 16 2026 Yuri Egorov <ye@umbra.org> - 0.2.0-1
- Initial Rust-based package with uwg, uwg-quick, man pages, completions,
  and systemd units
