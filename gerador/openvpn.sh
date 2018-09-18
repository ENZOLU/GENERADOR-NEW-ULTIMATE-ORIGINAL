#!/bin/bash
SCPfrm="/etc/ger-frm" && [[ ! -d ${SCPfrm} ]] && exit
SCPinst="/etc/ger-inst" && [[ ! -d ${SCPinst} ]] && exit

mportas () {
unset portas
portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" |grep -v "COMMAND" | grep "LISTEN")
while read port; do
var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
[[ "$(echo -e $portas|grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
done <<< "$portas_var"
i=1
echo -e "$portas"
}
meu_ip () {
if [[ -e /etc/MEUIPADM ]]; then
echo "$(cat /etc/MEUIPADM)"
else
MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
[[ "$MEU_IP" != "$MEU_IP2" ]] && echo "$MEU_IP2" || echo "$MEU_IP"
echo "$MEU_IP2" > /etc/MEUIPADM
fi
}
IP="$(meu_ip)"

fun_openvpn () {
# OpenVPN instalador para Debian, Ubuntu e CentOS

# Esse script irá trabalhar no Debian, Ubuntu, CentOS e provavelmente outros distros # das mesmas famílias, embora nenhum suporte é oferecido para eles.
# mas irá funcionar se você simplesmente deseja configurar uma VPN no 
# seu Debian/Ubuntu/CentOS. Ele foi projetado para ser tão
# discreto e universal quanto possível.

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 2
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "TUN is not available"
	exit 3
fi

if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit 4
fi
if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu or CentOS system"
	exit 5
fi

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (lowendspirit.com)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -4qO- "http://whatismyip.akamai.com/")
fi

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	    opnp=$(cat /etc/openvpn/server.conf |grep "port" |awk {'print $2'})
	    if grep "duplicate-cn" /etc/openvpn/server.conf > /dev/null; then
	    	mult=$(echo -e "\033[1;32mAtivado")
	    else
	    	mult=$(echo -e "\033[1;31mDesativado")
	    fi
		echo -e "$barra"
		echo -e "${cor[5]} MENU OpenVPN - Porta: $opnp"
		echo -e "$barra"
		echo "O que você deseja fazer?"
		echo -e "${cor[2]} [1] • ${cor[3]}Editar cliente"
		echo -e "${cor[2]} [2] • ${cor[3]}Remover um usuário"
		echo -e "${cor[2]} [3] • ${cor[3]}Remover OpenVPN"
		echo -e "${cor[2]} [4] • ${cor[3]}Multi-Login $mult"
		echo -e "${cor[2]} [0] • ${cor[3]}Voltar"
		read -p "Selecione a opção [1-4]: " option
		case $option in
			1) 
			nano /etc/openvpn/client-common.txt
			sleep 1
			return 0
			;;
			2)
			# This option could be documented a bit better and maybe even be simplimplified
			# ...but what can I say, I want some sleep too
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "Você não tem usuarios existentes!"
				exit 6
			fi
			echo -e "$barra"
			echo "Selecione um usuario para remover"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Selecione um usuario [1]: " CLIENTNUMBER
			else
				read -p "Selecione um usuario [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke $CLIENT
			./easyrsa gen-crl
			rm -rf pki/reqs/$CLIENT.req
			rm -rf pki/private/$CLIENT.key
			rm -rf pki/issued/$CLIENT.crt
			rm -rf /etc/openvpn/crl.pem
			cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
			# CRL is read with each client connection, when OpenVPN is dropped to nobody
			chown nobody:$GROUPNAME /etc/openvpn/crl.pem
			echo -e "$barra"
			echo "Usuario removido"
			sleep 1
			return 0
			;;
			3) 
			echo -e "$barra"
			echo -ne "${cor[5]}Deseja remover OpenVPN? [s/n]: ${cor[0]}"; read REMOVE
			if [[ "$REMOVE" = 's' ]]; then
				rmv_open () {
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 11)
				if pgrep firewalld; then
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
				fi
				if iptables -L -n | grep -qE 'REJECT|DROP|ACCEPT'; then
					iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
					iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
					iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
					sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
				fi
				iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
				sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
							semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
						fi
					fi
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn openvpn-blacklist
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
			    }
			    echo -e "${cor[2]}Removendo o OpenVPN!${cor[0]}"
			    fun_bar 'rmv_open'
				echo -e "$barra"
				echo -e "${cor[2]}OpenVPN removido!${cor[0]}"
			else
				echo -e "$barra"
				echo "Remoção abordada!"
			fi
			sleep 2
			return 0
			;;
			4)
            if grep "duplicate-cn" /etc/openvpn/server.conf > /dev/null; then
            	clear
            	fun_multon () {
            	sed -i '/duplicate-cn/d' /etc/openvpn/server.conf
            	sleep 1.5s
            	service openvpn restart > /dev/null
            	sleep 2
                }
                fun_spinmult () {
                	helice () {
                		fun_multon > /dev/null 2>&1 & 
                		tput civis
                		while [ -d /proc/$! ]
                		do
                			for i in / - \\ \|
                			do
                				sleep .1
                				echo -ne "\e[1D$i"
                			done
                		done
                		tput cnorm
                	}
                	echo ""
                	echo -ne "${cor[3]} Bloqueando Multi-Login${cor[2]}.${cor[4]}.${cor[5]}. ${cor[0]}"
                	helice
                	echo -e "\e[1DOk"
                }
                fun_spinmult
            	sleep 2
                return 0
            else
            	clear
            	fun_multoff () {
            	grep -v "^duplicate-cn" /etc/openvpn/server.conf > /tmp/tmpass && mv /tmp/tmpass /etc/openvpn/server.conf
            	echo "duplicate-cn" >> /etc/openvpn/server.conf
            	sleep 1.5s
            	service openvpn restart > /dev/null
            	sleep 2
                }
                fun_spinmult2 () {
                	helice () {
                		fun_multoff > /dev/null 2>&1 & 
                		tput civis
                		while [ -d /proc/$! ]
                		do
                			for i in / - \\ \|
                			do
                				sleep .1
                				echo -ne "\e[1D$i"
                			done
                		done
                		tput cnorm
                	}
                	echo ""
                	echo -ne "${cor[3]} Permitindo Multi-Login${cor[2]}.${cor[4]}.${cor[5]}. ${cor[0]}"
                	helice
                	echo -e "\e[1DOk"
                }
                fun_spinmult2
            	sleep 2
            fi
	    return 0
            ;;
			0) 
			menu;;
		esac
	done
else
    echo -e "$barra"
	echo -e "${cor[2]} Bem vindo ao instalador OpenVPN"
    echo -e "$barra"
	# OpenVPN instalador e criação do primeiro usuario
	echo -e "${cor[5]} Responda as perguntas para iniciar a instalação"
	echo -e "${cor[5]} Primeiro precisaremos do ip de sua maquina,este ip está correto ?${cor[3]}"
	read -p "IP address: " -e -i $IP IP
    echo -e "$barra"
	echo -e "${cor[5]} Qual protocolo você deseja para as conexões OPENVPN ?"
	echo -e "${cor[2]} [1] • ${cor[3]}UDP"
	echo -e "${cor[2]} [2] • ${cor[3]}TCP (Recomendado)${cor[3]}"
	read -p "Protocol [1-2]: " -e -i 2 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
    echo -e "$barra"
	echo -e "${cor[5]} Qual porta você deseja usar ?${cor[3]}"
	read -p "Port: " -e -i 1194 PORT
    echo -e "$barra"
	echo -e "${cor[5]} Qual DNS você deseja usar ?"
	echo -e "${cor[2]} [1] • ${cor[3]}Sistema(Não Recomendado)"
	echo -e "${cor[2]} [2] • ${cor[3]}Google (Recomendo)"
	echo -e "${cor[2]} [3] • ${cor[3]}OpenDNS"
	echo -e "${cor[2]} [4] • ${cor[3]}NTT"
	echo -e "${cor[2]} [5] • ${cor[3]}Hurricane Electric"
	echo -e "${cor[2]} [6] • ${cor[3]}Verisign"
	echo -e "${cor[2]} [7] • ${cor[3]}Cloudflare (Recomendado como opção 2)${cor[3]}"
	read -p "DNS [1-7]: " -e -i 2 DNS
    echo -e "$barra"
	if [[ "$OS" = 'debian' ]]; then
		echo -e "${cor[2]}ATUALIZANDO O SISTEMA"
		fun_attos () {
		apt-get update
		apt-get upgrade
	    }
	    fun_bar 'fun_attos'
		echo -e "${cor[2]}INSTALANDO DEPENDENCIAS"
		fun_instdep () {
		apt-get install openvpn iptables openssl ca-certificates -y
		apt-get install zip -y
	    }
		fun_bar 'fun_instdep'
	else
		# Else, the distro is CentOS
		fun_bar 'yum install epel-release'
		fun_bar 'yum install openvpn iptables openssl wget ca-certificates'
	fi
	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# Adquirindo easy-rsa
	fun_dep () {
	wget -O ~/EasyRSA-3.0.1.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/3.0.1/EasyRSA-3.0.1.tgz"
	tar xzf ~/EasyRSA-3.0.1.tgz -C ~/
	mv ~/EasyRSA-3.0.1/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.1/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.1.tgz
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full OPENVPN nopass
	./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# Generando key for tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key
	# Generando server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1) 
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2) 
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		4) 
		echo 'push "dhcp-option DNS 129.250.35.250"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 129.250.35.251"' >> /etc/openvpn/server.conf
		;;
		5) 
		echo 'push "dhcp-option DNS 74.82.42.42"' >> /etc/openvpn/server.conf
		;;
		6) 
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server.conf
		;;
		7)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
	esac
	echo "keepalive 10 20
float
cipher AES-128-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem
client-to-client
client-cert-not-required
username-as-common-name
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login" >> /etc/openvpn/server.conf
	# Enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Needed to use rc.local with some systemd distros
	if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
		echo '#!/bin/sh -e
exit 0' > $RCLOCAL
	fi
	chmod +x $RCLOCAL
	# Set NAT for the VPN subnet
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
	sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
	if pgrep firewalld; then
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol. Using both permanent and not permanent
		# rules to avoid a firewalld reload.
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
	fi
	if iptables -L -n | grep -qE 'REJECT|DROP'; then
		# If iptables has at least one REJECT rule, we asume this is needed.
		# Not the best approach but I can't think of other and this shouldn't
		# cause problems.
		iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
          iptables -F
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
	fi
	# If SELinux is enabled and a custom port or TCP was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
				# semanage isn't available in CentOS 6 by default
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
			fi
		fi
	fi
	}
	echo -e "${cor[2]} INSTALANDO O OPENVPN  ${cor[5]}(PODE DEMORAR!)"
	fun_bar 'fun_dep'
	# And finally, restart OpenVPN
	fun_ropen () {
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	}
	echo -e "${cor[2]} REINICIANDO O OPENVPN"
	fun_bar 'fun_ropen'
	# Try to detect a NATed connection and ask about it to potential LowEndSpirit users
	EXTERNALIP=$(wget -4qO- "http://whatismyip.akamai.com/")
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo -e "$barra"
		echo -e "${cor[2]} Parece que seu Servidor está atrás de um NAT"
		echo -e "${cor[5]} Por favor, informe o seu ip externo"
		echo -e "${cor[5]} Caso não seja prossiga com Enter"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# client-common.txt is created so we have a template to add further users later
	echo "# OVPN_ACCESS_SERVER_PROFILE=OpenVPN
client
dev tun
proto $PROTOCOL
remote / $PORT
http-proxy-option CUSTOM-HEADER Host portalrecarga.vivo.com.br/recarga
http-proxy $IP 80
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-128-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
auth-user-pass
verb 3
float" > /etc/openvpn/client-common.txt
	# Generates the custom client.ovpn
	newclient "OPENVPN"
    echo -e "$barra"
	echo -e "${cor[2]} Concluido!"
	echo -e "${cor[5]} Seu arquivo está disponivel em" ~/"OPENVPN.ovpn"
    echo -e "$barra"
fi
return 0
}
fun_openvpn
