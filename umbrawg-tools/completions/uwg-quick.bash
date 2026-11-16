_uwg_quick_completion() {
	local search_paths=( /etc/umbrawg )
	local old_glob file name found

	old_glob="$(shopt -p nullglob)"
	shopt -s nullglob

	if [[ $COMP_CWORD -eq 1 ]]; then
		COMPREPLY+=( $(compgen -W "up down save strip" -- "${COMP_WORDS[1]}") )
	elif [[ $COMP_CWORD -eq 2 ]]; then
		case "${COMP_WORDS[1]}" in
			up)
				for file in "${search_paths[0]}"/*.conf; do
					name="${file##*/}"
					name="${name%.conf}"
					mapfile -t found < <(compgen -W "$name" -- "${COMP_WORDS[2]}")
					COMPREPLY+=( "${found[@]}" )
				done
				mapfile -t found < <(compgen -f -X '!*.conf' -- "${COMP_WORDS[2]}")
				COMPREPLY+=( "${found[@]}" )
				;;
			down|save|strip)
				COMPREPLY+=( $(compgen -W "$(uwg show interfaces 2>/dev/null)" -- "${COMP_WORDS[2]}") )
				;;
		esac
	fi

	eval "$old_glob"
}

complete -o filenames -o nosort -F _uwg_quick_completion uwg-quick
