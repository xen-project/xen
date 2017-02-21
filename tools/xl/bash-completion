# Copy this file to /etc/bash_completion.d/xl.sh

_xl()
{
	local IFS=$'\n,'

	local cur opts xl
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	xl=xl

	if [[ $COMP_CWORD == 1 ]] ; then
		opts=`${xl} help 2>/dev/null | sed '1,4d' | awk '/^ [^ ]/ {print $1}' | sed 's/$/ ,/g'` && COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
		return 0
	fi

	return 0
}

complete -F _xl -o nospace -o default xl
