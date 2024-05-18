#!/bin/bash
if [ $# -ne 2 ]; then
    echo "Eroare argument."
    exit 1
fi

PIPE_FD=$2

if [ ! -f "$1" ]; then
    echo "Fisierul $1 nu exista. (script)"
    exit 1
fi
#ii dau fisierului permisiunea de citire
chmod u+r "$1"
#count pentru linii,cuvinte si caractere
line=$(wc -l < "$1")
cuv=$(wc -w < "$1")
carac=$(wc -c < "$1")
#task-ul 5
if [ "$line" -lt 3 ] && [ "$cuv" -gt 1000 ] && [ "$carac" -gt 2000 ]; then

    #initial variabila este pe safe, adica pe 9, daca gasesc ceva in neregula o mut pe periculos, adica pe 6
    periculos=9
    cuvintePericuloase=("corrupted" "dangerous" "risk" "attack" "malware" "malicious")
    for cuvantPericulos in "${cuvintePericuloase[@]}"; do
	grep -q "$cuvantPericulos" "$1"
	if [ $? -eq 0 ]; then
	    periculos=6
	    break
	fi
    done

    #non-ASCII
    grep -q -P "[^\x00-\x7F]" "$1"
    if [ $? -eq 0 ]; then
	periculos=6
    fi

    chmod 000 "$1"
    
    if [ $periculos -eq 9 ]; then
	echo "SAFE" >&${PIPE_FD}
	exit 9
    else
	echo "$1" >&${PIPE_FD}
	exit 6
    fi
    
else #task-ul 4

    periculos=9
    #Caut cuvintele periculoase
    cuvintePericuloase=("corrupted" "dangerous" "risk" "attack" "malware" "malicious")
    for cuvantPericulos in "${cuvintePericuloase[@]}"; do
	grep -q "$cuvantPericulos" "$1"
	if [ $? -eq 0 ]; then
	    periculos=6 #e periculos
	    break
	fi
    done
    
    #fac aceiasi pasi ca sus
    grep -q -P "[^\x00-\x7F]" "$1"
    if [ $? -eq 0 ]; then
	periculos=6
    fi


    chmod 000 "$1"

    if [ $periculos -eq 9 ]; then
        echo "SAFE" >&${PIPE_FD}
        exit 9
    else
        echo "$1" >&${PIPE_FD}
        exit 6
    fi
    
fi

#la sfarsit ma asigur ca fisierul are toate permisiunile lipsa, exact ca la inceput
chmod 000 "$1"
exit 0
