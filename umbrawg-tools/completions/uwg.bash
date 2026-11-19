_uwg_completion() {
	local commands params interfaces
	commands="help version genkey genpsk pubkey show showconf set setconf addconf syncconf"
	params="public-key private-key listen-port extra-ports fwmark bbr fec peers preshared-keys endpoints allowed-ips latest-handshakes persistent-keepalive advanced-security transfer dump jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 header-protection-key content-padding-addition rekey-after-time rekey-timeout reject-after-time keepalive-timeout max-handshake-attempts max_handshake_attempts random-trailers disable-cookies"
	interfaces="$(uwg show interfaces 2>/dev/null)"

	if [[ $COMP_CWORD -eq 1 ]]; then
		COMPREPLY+=( $(compgen -W "$commands" -- "${COMP_WORDS[1]}") )
		return
	fi

	case "${COMP_WORDS[1]}" in
		help|version|genkey|genpsk|pubkey) return ;;
		show|showconf|set|setconf|addconf|syncconf) ;;
		*) return ;;
	esac

	if [[ $COMP_CWORD -eq 2 ]]; then
		local extra=""
		[[ ${COMP_WORDS[1]} == show ]] && extra="all interfaces"
		COMPREPLY+=( $(compgen -W "$interfaces $extra" -- "${COMP_WORDS[2]}") )
		return
	fi

	if [[ $COMP_CWORD -eq 3 && ${COMP_WORDS[1]} == show && ${COMP_WORDS[2]} != interfaces ]]; then
		COMPREPLY+=( $(compgen -W "$params" -- "${COMP_WORDS[3]}") )
		return
	fi

	if [[ $COMP_CWORD -eq 3 && ( ${COMP_WORDS[1]} == setconf || ${COMP_WORDS[1]} == addconf || ${COMP_WORDS[1]} == syncconf ) ]]; then
		compopt -o filenames
		local files
		mapfile -t files < <(compgen -f -- "${COMP_WORDS[3]}")
		COMPREPLY+=( "${files[@]}" )
		return
	fi

	[[ ${COMP_WORDS[1]} == set ]] || return

	local has_listen_port=0 has_extra_ports=0 has_fwmark=0 has_bbr=0 has_fec=0 has_private_key=0 has_peer=0 words=() i
	for ((i=3;i<COMP_CWORD;i+=2)); do
		case "${COMP_WORDS[i]}" in
			listen-port) has_listen_port=1 ;;
			extra-ports) has_extra_ports=1 ;;
			fwmark) has_fwmark=1 ;;
			bbr) has_bbr=1 ;;
			fec) has_fec=1 ;;
			private-key) has_private_key=1 ;;
			peer) has_peer=$i; break ;;
		esac
	done

	if [[ $has_peer -eq 0 ]]; then
		if (( COMP_CWORD % 2 != 0 )); then
			[[ $has_listen_port -eq 1 ]] || words+=( listen-port )
			[[ $has_extra_ports -eq 1 ]] || words+=( extra-ports )
			[[ $has_fwmark -eq 1 ]] || words+=( fwmark )
			[[ $has_bbr -eq 1 ]] || words+=( bbr )
			[[ $has_fec -eq 1 ]] || words+=( fec )
			[[ $has_private_key -eq 1 ]] || words+=( private-key )
			words+=( peer )
			COMPREPLY+=( $(compgen -W "${words[*]}" -- "${COMP_WORDS[COMP_CWORD]}") )
		elif [[ ${COMP_WORDS[COMP_CWORD-1]} == *-key ]]; then
			compopt -o filenames
			local files
			mapfile -t files < <(compgen -f -- "${COMP_WORDS[COMP_CWORD]}")
			COMPREPLY+=( "${files[@]}" )
		fi
		return
	fi

	if [[ ${COMP_WORDS[COMP_CWORD-1]} == peer ]]; then
		COMPREPLY+=( $(compgen -W "$(uwg show "${COMP_WORDS[2]}" peers 2>/dev/null)" -- "${COMP_WORDS[COMP_CWORD]}") )
		return
	fi

	local has_remove=0 has_endpoint=0 has_keepalive=0 has_allowed_ips=0 has_preshared_key=0 j
	for ((i=has_peer;i<COMP_CWORD;i++)); do
		j=$i
		if [[ ${COMP_WORDS[i]} == peer ]]; then
			has_remove=0
			has_endpoint=0
			has_keepalive=0
			has_allowed_ips=0
			has_preshared_key=0
			((i++))
			continue
		fi
		case "${COMP_WORDS[i]}" in
			remove) has_remove=1 ;;
			endpoint) has_endpoint=1; ((i++)) ;;
			persistent-keepalive) has_keepalive=1; ((i++)) ;;
			allowed-ips) has_allowed_ips=1; ((i++)) ;;
			preshared-key) has_preshared_key=1; ((i++)) ;;
		esac
	done

	((COMP_CWORD == j)) || return

	if [[ $has_remove -ne 1 ]]; then
		[[ $has_preshared_key -eq 1 ]] || words+=( preshared-key )
		[[ $has_endpoint -eq 1 ]] || words+=( endpoint )
		[[ $has_allowed_ips -eq 1 ]] || words+=( allowed-ips )
		[[ $has_keepalive -eq 1 ]] || words+=( persistent-keepalive )
		words+=( remove )
	fi
	words+=( peer )
	COMPREPLY+=( $(compgen -W "${words[*]}" -- "${COMP_WORDS[COMP_CWORD]}") )
}

complete -o nosort -F _uwg_completion uwg
