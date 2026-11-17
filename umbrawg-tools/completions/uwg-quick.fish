complete -c uwg-quick -f

complete -c uwg-quick -n '__fish_use_subcommand' -a up -d 'Create and configure an interface'
complete -c uwg-quick -n '__fish_use_subcommand' -a down -d 'Tear down an interface'
complete -c uwg-quick -n '__fish_use_subcommand' -a save -d 'Save interface configuration'
complete -c uwg-quick -n '__fish_use_subcommand' -a strip -d 'Print configuration without quick-only keys'

function __uwg_quick_configs
    for file in /etc/umbrawg/*.conf
        basename $file .conf
    end
end

complete -c uwg-quick -n '__fish_seen_subcommand_from up' -a '(__uwg_quick_configs)' -d 'Interface'
complete -c uwg-quick -n '__fish_seen_subcommand_from up' -F
complete -c uwg-quick -n '__fish_seen_subcommand_from down save strip' -a '(uwg show interfaces 2>/dev/null | string split " ")' -d 'Interface'
