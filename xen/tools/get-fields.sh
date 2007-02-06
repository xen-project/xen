#!/bin/bash
test -n "$1" -a -n "$2" -a -n "$3"
set -ef

SED=sed
[ -x /usr/xpg4/bin/sed ] && SED=/usr/xpg4/bin/sed

get_fields() {
	local level=1 aggr=0 name= fields=
	for token in $2
	do
		case "$token" in
		struct|union)
			test $level != 1 || aggr=1 fields= name=
			;;
		"{")
			level=$(expr $level + 1)
			;;
		"}")
			level=$(expr $level - 1)
			if [ $level = 1 -a $name = $1 ]
			then
				echo "$fields }"
				return 0
			fi
			;;
		[[:alpha:]_]*)
			test $aggr = 0 -o -n "$name" || name="$token"
			;;
		esac
		test $aggr = 0 || fields="$fields $token"
	done
}

build_enums() {
	local level=1 kind= fields= members= named= id= token
	for token in $2
	do
		case "$token" in
		struct|union)
			test $level != 2 || fields=" "
			kind="$token;$kind"
			;;
		"{")
			level=$(expr $level + 1)
			;;
		"}")
			level=$(expr $level - 1)
			if [ $level = 1 ]
			then
				if [ "${kind%%;*}" = union ]
				then
					echo
					echo "enum XLAT_$1 {"
					for m in $members
					do
						echo "    XLAT_${1}_$m,"
					done
					echo "};"
				fi
				return 0
			elif [ $level = 2 ]
			then
				named='?'
			fi
			;;
		[[:alpha:]]*)
			id=$token
			if [ -n "$named" -a -n "${kind#*;}" ]
			then
				build_enums ${1}_$token "$fields"
				named='!'
			fi
			;;
		",")
			test $level != 2 || members="$members $id"
			;;
		";")
			test $level != 2 || members="$members $id"
			test -z "$named" || kind=${kind#*;}
			named=
			;;
		esac
		test -z "$fields" || fields="$fields $token"
	done
}

handle_field() {
	if [ -z "$5" ]
	then
		echo " \\"
		if [ -z "$4" ]
		then
			echo -n "$1(_d_)->$3 = (_s_)->$3;"
		else
			echo -n "$1XLAT_${2}_HNDL_$(echo $3 | $SED 's,\.,_,g')(_d_, _s_);"
		fi
	elif [ -z "$(echo "$5" | $SED 's,[^{}],,g')" ]
	then
		local tag=$(echo "$5" | python -c '
import re,sys
for line in sys.stdin.readlines():
    print re.subn(r"\s*(struct|union)\s+(compat_)?(\w+)\s.*", r"\3", line)[0].rstrip()
')
		echo " \\"
		echo -n "${1}XLAT_$tag(&(_d_)->$3, &(_s_)->$3);"
	else
		local level=1 kind= fields= id= array= arrlvl=1 array_type= type= token
		for token in $5
		do
			case "$token" in
			struct|union)
				test $level != 2 || fields=" "
				if [ $level = 1 ]
				then
					kind=$token
					if [ $kind = union ]
					then
						echo " \\"
						echo -n "${1}switch ($(echo $3 | $SED 's,\.,_,g')) {"
					fi
				fi
				;;
			"{")
				level=$(expr $level + 1) id=
				;;
			"}")
				level=$(expr $level - 1) id=
				if [ $level = 1 -a $kind = union ]
				then
					echo " \\"
					echo -n "$1}"
				fi
				;;
			"[")
				if [ $level != 2 -o $arrlvl != 1 ]
				then
					:
				elif [ -z "$array" ]
				then
					array=" "
				else
					array="$array;"
				fi
				arrlvl=$(expr $arrlvl + 1)
				;;
			"]")
				arrlvl=$(expr $arrlvl - 1)
				;;
			COMPAT_HANDLE\(*\))
				if [ $level = 2 -a -z "$id" ]
				then
					type=${token#COMPAT_HANDLE?}
					type=${type%?}
					type=${type#compat_}
				fi
				;;
			compat_domain_handle_t)
				if [ $level = 2 -a -z "$id" ]
				then
					array_type=$token
				fi
				;;
			[[:alpha:]]*)
				id=$token
				;;
			[\,\;])
				if [ $level = 2 -a -n "$(echo $id | $SED 's,^_pad[[:digit:]]*,,')" ]
				then
					if [ $kind = union ]
					then
						echo " \\"
						echo -n "${1}case XLAT_${2}_$(echo $3.$id | $SED 's,\.,_,g'):"
						handle_field "$1    " $2 $3.$id "$type" "$fields"
					elif [ -z "$array" -a -z "$array_type" ]
					then
						handle_field "$1" $2 $3.$id "$type" "$fields"
					elif [ -z "$array" ]
					then
						copy_array "    " $3.$id
					else
						handle_array "$1" $2 $3.$id "${array#*;}" "$type" "$fields"
					fi
					test "$token" != ";" || fields= id= type=
					array=
					if [ $kind = union ]
					then
						echo " \\"
						echo -n "$1    break;"
					fi
				fi
				;;
			*)
				if [ -n "$array" ]
				then
					array="$array $token"
				fi
				;;
			esac
			test -z "$fields" || fields="$fields $token"
		done
	fi
}

copy_array() {
	echo " \\"
	echo "${1}if ((_d_)->$2 != (_s_)->$2) \\"
	echo -n "$1    memcpy((_d_)->$2, (_s_)->$2, sizeof((_d_)->$2));"
}

handle_array() {
	local i="i$(echo $4 | $SED 's,[^;], ,g' | wc -w | $SED 's,[[:space:]]*,,g')"
	echo " \\"
	echo "$1{ \\"
	echo "$1    unsigned int $i; \\"
	echo -n "$1    for ($i = 0; $i < "${4%%;*}"; ++$i) {"
	if [ "$4" = "${4#*;}" ]
	then
		handle_field "$1        " $2 $3[$i] "$5" "$6"
	else
		handle_array "$1        " $2 $3[$i] "${4#*;}" "$5" "$6"
	fi
	echo " \\"
	echo "$1    } \\"
	echo -n "$1}"
}

build_body() {
	echo
	echo -n "#define XLAT_$1(_d_, _s_) do {"
	local level=1 fields= id= array= arrlvl=1 array_type= type= token
	for token in $2
	do
		case "$token" in
		struct|union)
			test $level != 2 || fields=" "
			;;
		"{")
			level=$(expr $level + 1) id=
			;;
		"}")
			level=$(expr $level - 1) id=
			;;
		"[")
			if [ $level != 2 -o $arrlvl != 1 ]
			then
				:
			elif [ -z "$array" ]
			then
				array=" "
			else
				array="$array;"
			fi
			arrlvl=$(expr $arrlvl + 1)
			;;
		"]")
			arrlvl=$(expr $arrlvl - 1)
			;;
		COMPAT_HANDLE\(*\))
			if [ $level = 2 -a -z "$id" ]
			then
				type=${token#COMPAT_HANDLE?}
				type=${type%?}
				type=${type#compat_}
			fi
			;;
		compat_domain_handle_t)
			if [ $level = 2 -a -z "$id" ]
			then
				array_type=$token
			fi
			;;
		[[:alpha:]_]*)
			if [ -n "$array" ]
			then
				array="$array $token"
			else
				id=$token
			fi
			;;
		[\,\;])
			if [ $level = 2 -a -n "$(echo $id | $SED 's,^_pad[[:digit:]]*,,')" ]
			then
				if [ -z "$array" -a -z "$array_type" ]
				then
					handle_field "    " $1 $id "$type" "$fields"
				elif [ -z "$array" ]
				then
					copy_array "    " $id
				else
					handle_array "    " $1 $id "${array#*;}" "$type" "$fields"
				fi
				test "$token" != ";" || fields= id= type=
				array=
			fi
			;;
		*)
			if [ -n "$array" ]
			then
				array="$array $token"
			fi
			;;
		esac
		test -z "$fields" || fields="$fields $token"
	done
	echo " \\"
	echo "} while (0)"
	echo ""
}

check_field() {
	if [ -z "$(echo "$4" | $SED 's,[^{}],,g')" ]
	then
		echo "; \\"
		local n=$(echo $3 | $SED 's,[^.], ,g' | wc -w | $SED 's,[[:space:]]*,,g')
		if [ -n "$4" ]
		then
			for n in $4
			do
				case $n in
				struct|union)
					;;
				[[:alpha:]_]*)
					echo -n "    CHECK_$n"
					break
					;;
				*)
					echo "Malformed compound declaration: '$n'" >&2
					exit 1
					;;
				esac
			done
		elif [ $n = 0 ]
		then
			echo -n "    CHECK_FIELD_($1, $2, $3)"
		else
			echo -n "    CHECK_SUBFIELD_${n}_($1, $2, $(echo $3 | $SED 's!\.!, !g'))"
		fi
	else
		local level=1 fields= id= token
		for token in $4
		do
			case "$token" in
			struct|union)
				test $level != 2 || fields=" "
				;;
			"{")
				level=$(expr $level + 1) id=
				;;
			"}")
				level=$(expr $level - 1) id=
				;;
			[[:alpha:]]*)
				id=$token
				;;
			[\,\;])
				if [ $level = 2 -a -n "$(echo $id | $SED 's,^_pad[[:digit:]]*,,')" ]
				then
					check_field $1 $2 $3.$id "$fields"
					test "$token" != ";" || fields= id=
				fi
				;;
			esac
			test -z "$fields" || fields="$fields $token"
		done
	fi
}

build_check() {
	echo
	echo "#define CHECK_$1 \\"
	local level=1 fields= kind= id= arrlvl=1 token
	for token in $2
	do
		case "$token" in
		struct|union)
			if [ $level = 1 ]
			then
				kind=$token
				echo -n "    CHECK_SIZE_($kind, $1)"
			elif [ $level = 2 ]
			then
				fields=" "
			fi
			;;
		"{")
			level=$(expr $level + 1) id=
			;;
		"}")
			level=$(expr $level - 1) id=
			;;
		"[")
			arrlvl=$(expr $arrlvl + 1)
			;;
		"]")
			arrlvl=$(expr $arrlvl - 1)
			;;
		[[:alpha:]_]*)
			test $level != 2 -o $arrlvl != 1 || id=$token
			;;
		[\,\;])
			if [ $level = 2 -a -n "$(echo $id | $SED 's,^_pad[[:digit:]]*,,')" ]
			then
				check_field $kind $1 $id "$fields"
				test "$token" != ";" || fields= id=
			fi
			;;
		esac
		test -z "$fields" || fields="$fields $token"
	done
	echo ""
}

fields="$(get_fields $(echo $2 | $SED 's,^compat_xen,compat_,') "$($SED -e 's,^[[:space:]]#.*,,' -e 's!\([]\[,;:{}]\)! \1 !g' $3)")"
if [ -z "$fields" ]
then
	echo "Fields of '$2' not found in '$3'" >&2
	exit 1
fi
name=${2#compat_}
name=${name#xen}
case "$1" in
"!")
	build_enums $name "$fields"
	build_body $name "$fields"
	;;
"?")
	build_check $name "$fields"
	;;
*)
	echo "Invalid translation indicator: '$1'" >&2
	exit 1
	;;
esac
