complete -c uwg -f

complete -c uwg -n '__fish_use_subcommand' -a genkey -d 'Generate a private key'
complete -c uwg -n '__fish_use_subcommand' -a genpsk -d 'Generate a preshared key'
complete -c uwg -n '__fish_use_subcommand' -a pubkey -d 'Derive a public key from stdin'
complete -c uwg -n '__fish_use_subcommand' -a show -d 'Show configuration and runtime state'
complete -c uwg -n '__fish_use_subcommand' -a showconf -d 'Show configuration as an INI file'
complete -c uwg -n '__fish_use_subcommand' -a set -d 'Change interface configuration'
complete -c uwg -n '__fish_use_subcommand' -a setconf -d 'Apply a configuration file'
complete -c uwg -n '__fish_use_subcommand' -a addconf -d 'Append a configuration file'
complete -c uwg -n '__fish_use_subcommand' -a syncconf -d 'Synchronize a configuration file'
complete -c uwg -n '__fish_use_subcommand' -a version -d 'Show the version'
complete -c uwg -n '__fish_use_subcommand' -a help -d 'Show usage information'

function __uwg_interfaces
    uwg show interfaces 2>/dev/null | string split ' '
end

complete -c uwg -n '__fish_seen_subcommand_from show' -a '(__uwg_interfaces) all interfaces' -d 'Interface'
complete -c uwg -n '__fish_seen_subcommand_from showconf set setconf addconf syncconf' -a '(__uwg_interfaces)' -d 'Interface'

complete -c uwg -n '__fish_seen_subcommand_from show; and not __fish_seen_subcommand_from interfaces' -a 'public-key private-key listen-port extra-ports fwmark peers preshared-keys endpoints allowed-ips latest-handshakes persistent-keepalive advanced-security transfer dump jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 header-protection-key content-padding-addition rekey-after-time rekey-timeout reject-after-time keepalive-timeout max-handshake-attempts max_handshake_attempts random-trailers disable-cookies' -d 'Parameter'

complete -c uwg -n '__fish_seen_subcommand_from setconf addconf syncconf' -F

complete -c uwg -n '__fish_seen_subcommand_from set' -a 'listen-port extra-ports fwmark private-key jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 header-protection-key content-padding-addition rekey-after-time rekey-timeout reject-after-time keepalive-timeout max-handshake-attempts random-trailers disable-cookies peer' -d 'Setting'
