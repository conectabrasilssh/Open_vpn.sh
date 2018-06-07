openvpn-install.sh

#! / bin / bash
#
# https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2013 Nyr. Lançado sob a licença MIT.


# Detectar usuários Debian que executam o script com "sh" em vez de bash
se readlink / proc / $$ / exe | grep -q " traço " ;  então
	echo  " Este script precisa ser executado com bash, não sh "
	Saída
fi

if [[ " $ EUID "  -ne 0]] ;  então
	echo  " Desculpe, você precisa rodar isso como root "
	Saída
fi

se [[ !  -e / dev / net / tun]] ;  então
	echo  " O dispositivo TUN não está disponível
Você precisa ativar o TUN antes de executar este script "
	Saída
fi

if [[ -e / etc / debian_version]] ;  então
	OS = debian
	GROUPNAME = nogroup
	RCLOCAL = ' /etc/rc.local '
elif [[ -e / etc / centos-release ||  -e / etc / redhat-release]] ;  então
	OS = centos
	GROUPNAME = nobody
	RCLOCAL = ' /etc/rc.d/rc.local '
outro
	echo  " Parece que você não está executando este instalador no Debian, Ubuntu ou CentOS "
	Saída
fi

newclient () {
	# Gera o cliente custom.ovpn
	cp /etc/openvpn/client-common.txt ~ / $ 1 .ovpn
	echo  " <ca> "  >>  ~ / $ 1 .ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >>  ~ / $ 1 .ovpn
	echo  " </ ca> "  >>  ~ / $ 1 .ovpn
	echo  " <cert> "  >>  ~ / $ 1 .ovpn
	gato / etc / openvpn / easy-rsa / pki / emitido / $ 1 .crt >>  ~ / $ 1 .ovpn
	echo  " </ cert> "  >>  ~ / $ 1 .ovpn
	echo  " <key> "  >>  ~ / $ 1 .ovpn
	gato / etc / openvpn / easy-rsa / pki / privado / $ 1 .key >>  ~ / $ 1 .ovpn
	echo  " </ key> "  >>  ~ / $ 1 .ovpn
	echo  " <tls-auth> "  >>  ~ / $ 1 .ovpn
	cat /etc/openvpn/ta.key >>  ~ / $ 1 .ovpn
	echo  " </ tls-auth> "  >>  ~ / $ 1 .ovpn
}

if [[ -e /etc/openvpn/server.conf]] ;  então
	enquanto  :
	Faz
	Claro
		echo  " Parece que o OpenVPN já está instalado. "
		eco
		echo  " O que você quer fazer? "
		echo  "    1) Adicionar um novo usuário "
		echo  "    2) Revogar um usuário existente "
		echo  "    3) Remover o OpenVPN "
		echo  "    4) Sair "
		read -p " Selecione uma opção [1-4]: " opção
		caso  $ option  em
			1) 
			eco
			echo  " Diga-me um nome para o certificado do cliente. "
			echo  " Por favor, use apenas uma palavra, sem caracteres especiais. "
			leia -p " Nome do cliente: " -e CLIENTE
			cd / etc / openvpn / easy-rsa /
			./easyrsa build-client-full $ CLIENTE nopass
			# Gera o cliente custom.ovpn
			newclient " $ CLIENT "
			eco
			echo  " Cliente $ CLIENT adicionado, configuração disponível em: "  ~ / " $ CLIENT .ovpn "
			Saída
			;;
			2)
			# Esta opção pode ser documentada um pouco melhor e talvez até simplificada
			# ... mas o que posso dizer, também quero dormir um pouco
			NUMBEROFCLIENTS = $ ( tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c " ^ V " )
			if [[ " $ NUMBEROFCLIENTS "  =  ' 0 ' ]] ;  então
				eco
				echo  " Você não tem clientes existentes! "
				Saída
			fi
			eco
			echo  " Selecione o certificado de cliente existente que você deseja revogar: "
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep " ^ V "  | corte -d ' = ' -f 2 | nl -s ' ) '
			if [[ " $ NUMBEROFCLIENTS "  =  ' 1 ' ]] ;  então
				read -p " Selecione um cliente [1]: " CLIENTNUMBER
			outro
				read -p " Selecione um cliente [1- $ NUMBEROFCLIENTS ]: " CLIENTNUMBER
			fi
			CLIENT = $ ( tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep " ^ V "  | cut -d ' = ' -f 2 | sed -n " $ CLIENTNUMBER " p )
			eco
			read -p " Você realmente deseja revogar o acesso para o cliente $ CLIENT ? [y / N]: " -e REVOKE
			if [[ "$REVOKE" = 'y' || "$REVOKE" = 'Y' ]]; then
				cd /etc/openvpn/easy-rsa/
				./easyrsa --batch revoke $CLIENT
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f pki/reqs/$CLIENT.req
				rm -f pki/private/$CLIENT.key
				rm -f pki/issued/$CLIENT.crt
				rm -f /etc/openvpn/crl.pem
				cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:$GROUPNAME /etc/openvpn/crl.pem
				echo
				echo "Certificate for client $CLIENT revoked!"
			else
				echo
				echo "Certificate revocation for client $CLIENT aborted!"
			fi
			exit
			;;
			3) 
			echo
			read -p "Do you really want to remove OpenVPN? [y/N]: " -e REMOVE
			if [[ "$REMOVE" = 'y' || "$REMOVE" = 'Y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
				else
					IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
					if iptables -L -n | grep -qE '^ACCEPT'; then
						iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					fi
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "Removal aborted!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo 'Welcome to this OpenVPN "road warrior" installer!'
	echo
	# OpenVPN setup and first user creation
	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo
	echo "First, provide the IPv4 address of the network interface you want OpenVPN"
	echo "listening to."
	# Autodetect IP address and pre-fill for the user
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -p "IP address: " -e -i $IP IP
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		read -p "Public IP address / hostname: " -e PUBLICIP
	fi
	echo
	echo "Which protocol do you want for OpenVPN connections?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo
	echo "What port do you want OpenVPN listening to?"
	read -p "Port: " -e -i 1194 PORT
	echo
	echo "Which DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) Verisign"
	read -p "DNS [1-5]: " -e -i 1 DNS
	echo
	echo "Finally, tell me your name for the client certificate."
	echo "Please, use one word only, no special characters."
	read -p "Client name: " -e -i client CLIENT
	echo
	echo "Okay, that was all I needed. We are ready to set up your OpenVPN server now."
	read -n1 -r -p "Press any key to continue..."
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl ca-certificates -y
	fi
	# Get easy-rsa
	EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz'
	wget -O ~/easyrsa.tgz "$EASYRSAURL" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
	tar xzf ~/easyrsa.tgz -C ~/
	mv ~/EasyRSA-3.0.4/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -f ~/easyrsa.tgz
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# Generate key for tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key
	# Generate server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	# DNS
	caso  $ DNS  em
		1)
		# Localize o resolv.conf apropriado
		# Necessário para sistemas executando o systemd-resolved
		if grep -q " 127.0.0.53 "  " /etc/resolv.conf " ;  então
			RESOLVCONF = ' /run/systemd/resolve/resolv.conf '
		outro
			RESOLVCONF = ' /etc/resolv.conf '
		fi
		# Obtenha os resolvedores do resolv.conf e use-os para o OpenVPN
		grep -v ' # '  $ RESOLVCONF  | grep ' nameserver '  | grep -E -o ' [0-9] {1,3} \. [0-9] {1,3} \. [0-9] {1,3} \. [0-9] {1, 3} '  |  enquanto  lê a linha ;  Faz
			echo  " push \" dhcp-option DNS $ line \ " "  >> /etc/openvpn/server.conf
		feito
		;;
		2)
		echo  ' push "dhcp-option DNS 1.1.1.1" '  >> /etc/openvpn/server.conf
		echo  ' push "dhcp-option DNS 1.0.0.1" '  >> /etc/openvpn/server.conf
		;;
		3)
		echo  ' push "dhcp-option DNS 8.8.8.8" '  >> /etc/openvpn/server.conf
		echo  ' push "dhcp-option DNS 8.8.4.4" '  >> /etc/openvpn/server.conf
		;;
		4)
		echo  ' push "dhcp-opção DNS 208.67.222.222" '  >> /etc/openvpn/server.conf
		echo  ' push "dhcp-opção DNS 208.67.220.220" '  >> /etc/openvpn/server.conf
		;;
		5)
		echo  ' push' dhcp-option DNS 64.6.64.6 " '  >> /etc/openvpn/server.conf
		echo  ' push' dhcp-option DNS 64.6.65.6 " '  >> /etc/openvpn/server.conf
		;;
	esac
	echo  " keepalive 10 120
cifra AES-256-CBC
comp-lzo
usuário ninguém
grupo $ GROUPNAME
persistência-chave
persist-tun
status openvpn-status.log
verbo 3
crl-verify crl.pem "  >> /etc/openvpn/server.conf
	# Ativar net.ipv4.ip_forward para o sistema
	sed -i ' /\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1 ' /etc/sysctl.conf
	se  ! grep -q " \ <net.ipv4.ip_forward \> " /etc/sysctl.conf ;  então
		echo  ' net.ipv4.ip_forward = 1 '  >> /etc/sysctl.conf
	fi
	# Evite uma reinicialização desnecessária
	echo 1 > / proc / sys / net / ipv4 / ip_forward
	if pgrep firewalld ;  então
		# Usando regras permanentes e não permanentes para evitar um firewalld
		# recarregar.
		# Nós não usamos --add-service = openvpn porque isso só funcionaria com
		# a porta e o protocolo padrão.
		firewall-cmd --zone = public --add-port = $ PORT / $ PROTOCOL
		firewall-cmd --zone = confiável --add-source = 10.8.0.0 / 24
		firewall-cmd --permanent --zone = public --add-port = $ PORT / $ PROTOCOLO
		firewall-cmd --permanent --zone = trusted --add-source = 10.8.0.0 / 24
		# Definir NAT para a sub-rede da VPN
		firewall-cmd --direcionar --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT - para $ IP
		firewall-cmd --permanente --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT - para $ IP
	outro
		# Necessário para usar rc.local com algumas distribuições systemd
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		# Set NAT for the VPN subnet
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# If iptables has at least one REJECT rule, we asume this is needed.
			# Not the best approach but I can't think of other and this shouldn't
			# cause problems.
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
		# Instalar semanage se ainda não estiver presente
		se  !  perenização de hash 2> / dev / null ;  então
			yum instala o policycoreutils-python -y
		fi
		porta semanage -a -t openvpn_port_t -p $ PROTOCOL  $ PORT
	fi
	# E finalmente, reinicie o OpenVPN
	if [[ " $ OS "  =  ' debian ' ]] ;  então
		# Little hack para verificar se há systemd
		if pgrep systemd-journal ;  então
			systemctl reiniciar openvpn@server.service
		outro
			/etc/init.d/openvpn restart
		fi
	outro
		if pgrep systemd-journal ;  então
			systemctl reiniciar openvpn@server.service
			systemctl habilitar openvpn@server.service
		outro
			serviço de reinicialização openvpn
			chkconfig openvpn on
		fi
	fi
	# Se o servidor estiver atrás de um NAT, use o endereço IP correto
	if [[ " $ PUBLICIP "  ! =  " " ]] ;  então
		IP = $ PUBLICIP
	fi
	# client-common.txt é criado, por isso temos um modelo para adicionar outros usuários mais tarde
	echo  " cliente
dev tun
proto $ PROTOCOL
sndbuf 0
rcvbuf 0
remoto $ IP  $ PORT
resolv-retry infinite
nobind
persistência-chave
persist-tun
servidor remote-cert-tls
auth SHA512
cifra AES-256-CBC
comp-lzo
setenv opt block-outside-dns
direção da tecla 1
verbo 3 "  > /etc/openvpn/client-common.txt
	# Gera o cliente custom.ovpn
	newclient " $ CLIENT "
	eco
	echo  " Concluído! "
	eco
	echo  " Sua configuração do cliente está disponível em: "  ~ / " $ CLIENT .ovpn "
	echo  " Se você quiser adicionar mais clientes, basta executar este script novamente! "
fi
