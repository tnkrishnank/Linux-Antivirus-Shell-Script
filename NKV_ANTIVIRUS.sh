#! /usr/bin/bash

echo "WELCOME TO NKV ANTIVIRUS"
echo "------------------------"

DOWNLAOD_LINK_MD5='https://drive.google.com/uc?export=download&id=1yD9ZYFsUiM9Pa-6m7BPJQ34aahoFtck3'
DOWNLAOD_LINK_SHA1='https://drive.google.com/uc?export=download&id=11jHxEq-cf80pwGkB3DKi1LPBC-fIPxSy'
DOWNLAOD_LINK_SHA256='https://drive.google.com/uc?export=download&id=1sQa4RWplEi1StJKoi7vGCR3soVLP0Ns2'

function selectPath() {
        local RECURSE=$(pwd)
        read -ep "ENTER DIRECTORY OR FILE PATH TO SCAN : "  RECURSE
        if [[ -d $RECURSE ]]
        then
                cd "$RECURSE"
        else
                echo $RECURSE
                exit
        fi
        local RECURSE=$(pwd)
        cd - > /dev/null 2>&1
        echo $RECURSE
        exit
}

function update() {
        echo "UPDATING ANTIVIRUS ..."
        wget --no-check-certificate $DOWNLAOD_LINK_MD5 -O MD5.txt 2>/tmp/NKV_UPDATE
        wget --no-check-certificate $DOWNLAOD_LINK_SHA1 -O SHA1.json 2>/tmp/NKV_UPDATE
        wget --no-check-certificate $DOWNLAOD_LINK_SHA256 -O SHA256.txt 2>/tmp/NKV_UPDATE
        COUNT=`cat /tmp/NKV_UPDATE | grep -c 'wget: unable to resolve host address'`
        echo""
        if [[ $COUNT -eq 0 ]]
        then
                echo "ANTIVIRUS UPDATED SUCCESSFULLY ..."
        else
                echo "CHECK YOUR NETWORK AND TRY AGAIN !"
        fi
}

function removeWhitelist() {
        j=0
        while read n ; do
                n=`echo $n | cut -d ' ' -f 1`
                WHITELIST_PATHS[$j]=${n}
                j=$(( $j + 1 ))
                echo $j `find / -xdev -inum $n 2>/dev/null`
        done < 'WHITELIST.NKV'
        echo ""
        read -p "ENTER THE FILES YOU NEED TO REMOVE FROM WHITELIST : " FROM_WHITELIST
        IFS=$' '
        for i in "${FROM_WHITELIST}"
        do
                x=/${WHITELIST_PATHS[$(( $i - 1 ))]}/d
                sed -i $x WHITELIST.NKV
        done
        echo ""
        echo "DONE !"
}

function advancedScan() {
        F_PATH=$( selectPath )
        if [[ -f $F_PATH ]]
        then
                MD5=$(md5sum "$F_PATH" | cut -d ' ' -f 1)
                echo ""
                REPORT=`curl --request GET --url https://www.virustotal.com/api/v3/files/${MD5} --header 'x-apikey: 18681ea45c9e7a64732ba92c6ded1d17608386770a0c78437f6d0b2b0ee39fc0'`
                CODE=$(echo $REPORT | grep -o '"malicious": [0-9]*, "undetected"' | cut -d ' ' -f 2 | cut -d ',' -f 1)

                echo ""
                if [[ $CODE -eq 0 ]]
                then
                        echo "NO VIRUS DETECTED !"
                else
                        MALICIOUS_C=`echo $REPORT | grep -o '"malicious": [0-9]*, "undetected"' | cut -d ' ' -f 2 | cut -d ',' -f 1`
                        UNDETECTED_C=`echo $REPORT | grep -o '"malicious": [0-9]*, "undetected": [0-9]*' | cut -d ' ' -f 4`
                        echo "VIRUS DETECTED !"
                        echo ""
                        echo "REPORT SUMMARY FROM COMMERCIAL ANTIVIRUS SOFTWARES"
                        echo "MALICIOUS  : $MALICIOUS_C"
                        echo "UNDETECTED : $UNDETECTED_C"
                        echo ""
                        echo "NEED DETAILED REPORT"
                        echo "1. YES"
                        echo "2. NO"
                        echo ""
                        read -p "ENTER YOUR CHOICE : " CHOICE
                        echo ""
                        if [[ $CHOICE -eq 1 ]]
                        then
                                echo "$REPORT"
                        fi
                fi
        else
                echo "SELECT A FILE !"
        fi
}

function whitelist() {
        j=1
        for i in "${INFECTED_PATHS[@]}"
        do
                echo $j $i
                j=$(( $j + 1 ))
        done
        echo ""
        read -p "ENTER THE FILES YOU NEED TO WHITELIST : " TO_WHITELIST
        j=1
        for i in "${INFECTED_PATHS[@]}"
        do
                x="\\b$j\\b"
                COUNT=`echo $TO_WHITELIST | grep -c $x`
                if [[ COUNT -eq 0 ]]
                then
                        mv $i "$i.virus"
                else
                        if [[ ! -e "WHITELIST.NKV" ]]
                        then
                                touch WHITELIST.NKV
                        fi
                        SHA1=$(sha1sum "$i" | cut -d ' ' -f 1)
                        INODE=$(ls -i "$i" | cut -d ' ' -f 1)
                        echo $INODE $SHA1 >> WHITELIST.NKV
                fi
                j=$(( $j + 1 ))
        done
        echo ""
        echo "DONE !"
}

function scan() {
        C_MD5=`cat MD5.txt | grep -c $1`
        C_SHA1=`cat SHA1.json | grep -c $2`
        C_SHA256=`cat SHA256.txt | grep -c $3`

        if [[ C_MD5 -gt 0 ]] || [[ C_SHA1 -gt 0 ]] || [[ C_SHA256 -gt 0 ]]
        then
                echo "VIRUS DETECTED ! $4"
                INFECTED_PATHS[$l]=${4}
                l=$(( $l + 1 ))
        fi
}

function findHash() {
        l=0
        IFS=$'\n'
        DIR_PATH=" "
        for CURRENT_PATH in $(ls -R $RECURSE) ; do
        if [[ $CURRENT_PATH =~ (:$) ]]
        then
                DIR_PATH=`echo $CURRENT_PATH | cut -d ':' -f 1`
        else
                if [[ $DIR_PATH != " " ]]
                then
                        FILE_PATH="${DIR_PATH}/${CURRENT_PATH}"
                else
                        FILE_PATH=$CURRENT_PATH
                fi

                if [[ ! -d $FILE_PATH ]] && [[ ${FILE_PATH: -6} != ".virus" ]]
                then
                        MD5=$(md5sum "$FILE_PATH" | cut -d ' ' -f 1)
                        SHA1=$(sha1sum "$FILE_PATH" | cut -d ' ' -f 1)
                        SHA256=$(sha256sum "$FILE_PATH" | cut -d ' ' -f 1)

                        CC=`cat WHITELIST.NKV | grep -c $SHA1`
                        if [[ $CC -eq 0 ]]
                        then
                                scan $MD5 $SHA1 $SHA256 $FILE_PATH
                        fi
                fi
        fi
        done
        if [[ ${#INFECTED_PATHS[@]} -ne 0 ]]
        then
                echo ""
                echo "SCAN COMPLETED SUCCESSFULLY !"
                echo ""
                echo "WHITELIST FILES"
                echo "1. YES"
                echo "2. NO"
                echo ""
                read -p "ENTER YOUR CHOICE : " CHOICE
                echo ""
                if [[ $CHOICE -eq 1 ]]
                then
                        whitelist
                else
                        for i in "${INFECTED_PATHS[@]}"
		        do
                	        mv $i "$i.virus"
	        	done
                fi
        else
                echo "SCAN COMPLETED SUCCESSFULLY !"
                echo ""
                echo  "NO INFECTED FILES FOUND !"
        fi
}

while :
do
        RECURSE=""
        INFECTED_PATHS=()
        WHITELIST_PATHS=()
        if [[ $# -eq 0 ]]
        then
                echo ""
                echo "1. LOCAL FULL SCAN"
                echo "2. LOCAL CUSTOM SCAN"
                echo "3. VIRUSTOTAL ADVANCED SCAN"
                echo "4. REMOVE WHITELISTED FILE"
                echo "5. UPDATE ANTIVIRUS"
                echo "0. EXIT"
                echo ""
                read -p "ENTER YOUR CHOICE : " CHOICE
                echo ""
                if [[ $CHOICE -eq 1 ]]
                then
                        RECURSE="/home/${USER}"
                        findHash
                elif [[ $CHOICE -eq 2 ]]
                then
                        RECURSE=$( selectPath )
                        echo ""
                        findHash
                elif [[ $CHOICE -eq 3 ]]
                then
                        advancedScan
                elif [[ $CHOICE -eq 4 ]]
                then
                        removeWhitelist
                elif [[ $CHOICE -eq 5 ]]
                then
                        update
                elif [[ $CHOICE -eq 0 ]]
                then
                        exit
                else
                        echo "INVALID CHOICE !"
                fi
        fi
done