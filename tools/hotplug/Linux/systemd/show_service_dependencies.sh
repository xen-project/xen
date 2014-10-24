#!/bin/bash
# dot(1) from graphviz, display(1) from ImageMagick
# Usage: bash $0 tools/hotplug/Linux/systemd/*.in
(
echo " digraph systemd {"
for file in "$@"
do
	if test -f "$file"
	then
		unit=${file##*/}
		unit=${unit%.in}
		requires="`grep ^Requires= $file | cut -f 2- -d =`"
		before="`grep ^Before= $file | cut -f 2- -d =`"
		after="`grep ^After= $file | cut -f 2- -d =`"
		echo "\"$unit\" [fillcolor=lightgray color=black fontcolor=black style=filled];"
		for i in $requires
		do
			echo "\"$i\" -> \"$unit\" [color=red];"
		done
		for i in $after
		do
			echo "\"$i\" -> \"$unit\" [color=blue];"
		done
		for i in $before
		do
			echo "\"$unit\" -> \"$i\" [color=green];"
		done
	fi
done
echo "}"
) | dot -Tpng | display -
