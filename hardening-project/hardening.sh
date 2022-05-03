#!/bin/bash
##############################################################################
# v0.1                                                                       #
# ============================================                               #
#                                                                            #
# Copyright (c) 2022 by Bruno Rodrigues - brunofranrodrigues@gmail.com       #
# Last Updated 24/04/2022                                                    #
#                                                                            #
# This program is free software. You can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation; either version 2 of the License.             #
##############################################################################

# ---------------------------------------
# Environment variables
# ---------------------------------------

i="";
Erro="Sistema nao homologado"
OSVERSION=""
MN="-n"
MC="-e"
CHOWN=`which chown`
CAT=`which cat`
CHMOD=`which chmod`
USERMOD=`which usermod`
AWK=`which awk`
ECHO=`which echo`
FIND=`which find`
GREP=`which grep`
CUT=`which cut`
TOUCH=`which touch`
SED=`which sed`
TAIL=`which tail`
HEAD=`which head`
APTGET=`which apt-get`
YUM=`which yum`
RPM=`which rpm`
DPKG=`which dpkg`
NOLOGIN=`which nologin`
MOUNT=`which mount`
UMOUNT=`which umount`
NETREPORT=`which netreport`
AT=`which at`
CHAGE=`which chage`
CHFN=`which chfn`
CHSH=`which chsh`
GPASSWD=`which gpasswd`
LOCATE=`which locate`
NEWGRP=`which newgrp`
SSHAGENT=`which ssh-agent`
WALL=`which wall`
WRITE=`which write`
UMASKBIN=`which umask`
opc=0
opc2=0

# ---------------------------------------
# Colors
# ---------------------------------------
BLACK="\033[030m"
RED="\033[031m"
GREEN="\033[032m"
YELLOW="\033[033m"
BLUE="\033[034m"
MAGENTA="\033[035m"
CYAN="\033[036m"
WHITE="\033[037m"
UNCOLOR="\033[0m"

export PATH="${PATH:+$PATH:}/sbin:/usr/sbin:/bin:/usr/bin"



while	[ "$opc" -lt 1 -o $opc -gt 2 ]
do
	clear
	echo -e "
	+---------------------------------------------------+
	|						    |
	|                  Hardening script		    |
	|						    |
	+---------------------------------------------------+
		OPCAO	ACAO		
		-----	----
		  1	Aplicar hardening
                  2     Sair
		Entre com a opcao desejada: \c"
	read opc
done
if [ $opc -eq 2 ]
then
   exit
fi

chk_rootuser() {
if [[ $UID -ne 0 ]]; then
     ${ECHO} "$0 must be run as root"
     exit 1
fi
}

check_release(){
OSTYPE=('CentOS' 'Debian' 'Ubuntu' 'Oracle')

for OSTYPE in $($CAT /etc/*-release | $GREP ^NAME | $CUT -d '"' -f 2 | $AWK '{print $1}')
do

if [[ "$OSTYPE" == "CentOS" ]]; then
        i=1
        OSVERSION=`$CAT /etc/*-release | $HEAD -1`
        ${ECHO} ${OSVERSION}
elif [[ "$OSTYPE" == "Debian" ]]; then
        i=2
        OSVERSION=`$CAT /etc/*-release | $HEAD -1 | $AWK -F'=' {' print $2 '}`
        ${ECHO} ${OSVERSION}
elif [[ "$OSTYPE" == "Ubuntu" ]]; then
        i=3
        OSVERSION=`$CAT /etc/*-release | $HEAD -4 | $TAIL -1 | $AWK -F'=' {' print $2 '}`
        ${ECHO} ${OSVERSION}
elif [[ "$OSTYPE" == "Oracle" ]]; then
        i=4
        OSVERSION=`$CAT /etc/*-release | $HEAD -1`
        ${ECHO} ${OSVERSION}
else	
		${ECHO} ${Erro}
fi

done

}

banner() {
clear
${ECHO} ""
${ECHO} "----------------------------------------------"
${ECHO} "Aplicacao de Hardening Linux"
${ECHO} "Sistema Operacional Homologado:"
${ECHO} "Centos 7, Centos 8 Stream, Oracle Linux 8, Ubuntu 20.04, Debian 11"
if [[ $i == 1 ]] || [[ $i == 2 ]] || [[ $i == 3 ]] || [[ $i == 4 ]];
then
${ECHO} "----------------------------------------------"
else 
${ECHO} -e ${Erro}
fi
${ECHO} "----------------------------------------------"
${ECHO} ""
${ECHO} ${MC} "${RED}[Host Configuration]${INCOLOR}"

GETIP=$(ip a | grep "inet" | $GREP -v 127.0.0.1 | $TAIL -2 | $HEAD -1 | $AWK -F' ' {' print $2 '})
cmd=$(for i in ${GETIP}; do ${ECHO} ${MN} "${i} ";done)
${ECHO} ${MC} "${YELLOW}OS Version:${UNCOLOR} $OSVERSION"
${ECHO} ${MC} "${YELLOW}Hostname:${UNCOLOR} `hostname`"
${ECHO} ${MC} "${YELLOW}IP(s):${UNCOLOR} ${cmd}"
${ECHO} ""
${ECHO} ""
}

verify_logrotate(){
if [[ $i == 2 ]] || [[ $i == 3 ]];
then
	if ${DPKG} -l | ${GREP} logrotate > /dev/null;
	then
		${ECHO} ${MC} "${GREEN} O pacote logrotate ja esta instalado ${UNCOLOR}"
	else
		${ECHO} ${MC} "${GREEN} O pacote do logrotate sera instalado ${UNCOLOR}"
		${APTGET} install logrotate
	fi 
elif [[ $i == 1 ]] || [[ $i == 4 ]];
then
	if ${RPM} -qa | ${GREP} logrotate > /dev/null;
	then
		${ECHO} ${MC} "${GREEN} O pacote logrotate ja esta instalado ${UNCOLOR}"
	else
		${ECHO} ${MC} "${GREEN} O pacote do logrotate sera instalado ${UNCOLOR}"
		${YUM} install logrotate
	fi
fi
}

change_logrotate() {
${ECHO} ${MC} "${GREEN} Ajustando os parametros do logrotate:  ${UNCOLOR}"
${SED} -i -- 's/create/create 0600 root root/g' /etc/logrotate.conf


${CAT} <<EOF >> /etc/logrotate.conf
/var/log/wtmp {
    monthly
    minsize 1M
    create 0640 root utmp
    rotate 1
}
EOF
}

verify_rsyslog(){
if [[ $i == 2 ]] || [[ $i == 3 ]];
then
	if ${DPKG} -l | ${GREP} rsyslog > /dev/null;
	then
		${ECHO} ${MC} "${GREEN} O pacote rsyslog ja esta instalado ${UNCOLOR}"
	else
		${ECHO} ${MC} "${GREEN} O pacote do rsyslog sera instalado ${UNCOLOR}"
		${APTGET} install rsyslog
	fi 
elif [[ $i == 1 ]] || [[ $i == 4 ]];
then
	if ${RPM} -qa | ${GREP} rsyslog > /dev/null;
	then
		${ECHO} ${MC} "${GREEN} O pacote rsyslog ja esta instalado ${UNCOLOR}"
	else
		${ECHO} ${MC} "${GREEN} O pacote do rsyslog sera instalado ${UNCOLOR}"
		${YUM} install rsyslog
	fi
fi
}

pam_security() {
${ECHO} ${MC} "${GREEN} Ajuste das permissoes do PAM ${UNCOLOR}"
if [[ $i == 2 ]] || [[ $i == 3 ]]
then
  ${ECHO} "password    requisite     pam_cracklib.so try_first_pass retry=3 type=difok=3 minlen=8 dcredit=1 lcredit=1 ucredit=1 ocredit=1" >> /etc/pam.d/common-password
  ${ECHO} "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=4" >> /etc/pam.d/common-password
  ${ECHO} "auth         required        pam_wheel.so wheel" >> /etc/pam.d/su
elif [[ $i == 1 ]] || [[ $i == 4 ]]
then
  ${ECHO} "password    requisite     pam_cracklib.so try_first_pass retry=3 type=difok=3 minlen=8 dcredit=1 lcredit=1 ucredit=1 ocredit=1" >> /etc/pam.d/system-auth
  ${ECHO} "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=4" >> /etc/pam.d/system-auth
  ${ECHO} "auth         required        pam_wheel.so wheel" >> /etc/pam.d/su
fi
}

systemlogs_perm() {
${ECHO} ${MC} "${GREEN} Ajuste das permissoes de logs ${UNCOLOR}"
${FIND} /var/log/ -type f -exec $CHMOD 600 {} \;

${CHMOD} +t /var/tmp
${CHMOD} +t /tmp

${ECHO} ${MC} "${GREEN} Ajuste das permissoes do arquivo wtmp ${UNCOLOR}"
if ls /var/log/ | $GREP wtmp > /dev/null
then 
	${ECHO} ${MC} "${GREEN} O arquivo wtmp ja existe ${UNCOLOR}"
	${CHMOD} 640 /var/log/wtmp
else
	${TOUCH} /var/log/wtmp
	${CHMOD} 640 /var/log/wtmp
fi
}

home_perm() {
${ECHO} ${MC} "${GREEN} Ajuste das permissoes do home ${UNCOLOR}"
${FIND} /home/ -type d -exec ${CHMOD} 700 {} \;

${CHMOD} 755 /home
}

change_remoteroot(){
${ECHO} ${MC} "${GREEN} Validando o arquivo securetty ${UNCOLOR}"
if ls /etc/ | ${GREP} securetty > /dev/null
then
	${ECHO} ${MC} "${GREEN} O arquivo securetty ja existe ${UNCOLOR}"
else
	${TOUCH} /etc/securetty
	${CHMOD} 640 /etc/securetty
	${CAT} <<EOF > /etc/securetty
console
tty1
tty2
tty3
tty4
tty5
tty6
tty7
tty8
EOF
fi
}

ch_crond() {
${ECHO} ${MC} "${GREEN} Validando o arquivo cron.allow ${UNCOLOR}"
if ls /etc/ | ${GREP} cron.allow  > /dev/null
then
	${ECHO} ${MC} "${GREEN} O arquivo cron.allow ja existe ${UNCOLOR}"
	${ECHO} "root" >> cron.allow
else
	${TOUCH} /etc/cron.allow
	${CHMOD} 600 /etc/cron.allow
	${CAT} <<EOF > /etc/cron.allow
root
EOF
fi

${ECHO} ${MC} "${GREEN} Validando o arquivo cron.deny ${UNCOLOR}"
if ls /etc/ | ${GREP} cron.deny  > /dev/null
then
	${ECHO} ${MC} "${GREEN} O arquivo cron.deny ja existe ${UNCOLOR}"
	${CAT} <<EOF > /etc/cron.deny
bin
daemon
adm
lp
mail
uucp
operator
games
gopher
ftp
nobody
dbus
vcsa
nscd
rpc
abrt
saslauth
postfix
qpidd
haldaemon
ntp
arpwatch
sshd
nslcd
tcpdump
EOF
else
	${TOUCH} /etc/cron.deny
	${CHMOD} 600 /etc/cron.deny
	${CAT} <<EOF > /etc/cron.deny
bin
daemon
adm
lp
mail
uucp
operator
games
gopher
ftp
nobody
dbus
vcsa
nscd
rpc
abrt
saslauth
postfix
qpidd
haldaemon
ntp
arpwatch
sshd
nslcd
tcpdump
EOF
fi
}

add_group_wheel() {
${ECHO} ${MC} "${GREEN} Validando o grupo wheel ${UNCOLOR}"
if ${CAT} /etc/group | ${GREP} wheel > /dev/null
then
	${ECHO} ${MC} "${GREEN} O grupo wheel ja existe ${UNCOLOR}"
	${USERMOD} -a -G wheel root
else
	groupadd wheel
	${ECHO} ${MC} "${GREEN} O grupo wheel foi criado ${UNCOLOR}"
	${USERMOD} -a -G wheel root
fi
}

change_banner() {
${ECHO} ${MC} "${GREEN} Validando /etc/motd ${UNCOLOR}"
if ls /etc | ${GREP} motd > /dev/null
then 
	${ECHO} ${MC} "${GREEN} O arquivo /etc/motd ja existe ${UNCOLOR}"
	${CAT} <<EOF > /etc/motd
--------------------------------------------------------------------------------
                        ATENCAO: Aviso Importante
E proibido o acesso nao autorizado. Esse e um recurso de acesso restrito
devidamente controlado, monitorado e de responsabilidade do Universo Online S/A.
Se voce nao possui autorizacao para acessar este recurso, desconecte
imediatamente ou podera sofrer sancoes legais e/ou acao disciplinar.
Em caso de problemas envie email para l-monitor-sec@uolinc.com
--------------------------------------------------------------------------------
EOF
else
	${TOUCH} /etc/motd
	${CHMOD} 640 /etc/motd
	${CAT} <<EOF > /etc/motd
--------------------------------------------------------------------------------
                        ATENCAO: Aviso Importante
E proibido o acesso nao autorizado. Esse e um recurso de acesso restrito
devidamente controlado, monitorado e de responsabilidade do Universo Online S/A.
Se voce nao possui autorizacao para acessar este recurso, desconecte
imediatamente ou podera sofrer sancoes legais e/ou acao disciplinar.
Em caso de problemas envie email para l-monitor-sec@uolinc.com
--------------------------------------------------------------------------------
EOF
fi

${ECHO} ${MC} "${GREEN} Validando /etc/issue.net ${UNCOLOR}"
if ls /etc | ${GREP} issue.net > /dev/null
then 
	${ECHO} ${MC} "${GREEN} O arquivo issue.net ja existe ${UNCOLOR}"
	${CAT} <<EOF > /etc/issue.net
--------------------------------------------------------------------------------
                        ATENCAO: Aviso Importante
E proibido o acesso nao autorizado. Esse e um recurso de acesso restrito
devidamente controlado, monitorado e de responsabilidade do Universo Online S/A.
Se voce nao possui autorizacao para acessar este recurso, desconecte
imediatamente ou podera sofrer sancoes legais e/ou acao disciplinar.
Em caso de problemas envie email para l-monitor-sec@uolinc.com
--------------------------------------------------------------------------------
EOF
else
	${TOUCH} /etc/issue.net
	${CHMOD} 640 /etc/issue.net
	${CAT} <<EOF > /etc/issue.net
--------------------------------------------------------------------------------
                        ATENCAO: Aviso Importante
E proibido o acesso nao autorizado. Esse e um recurso de acesso restrito
devidamente controlado, monitorado e de responsabilidade do Universo Online S/A.
Se voce nao possui autorizacao para acessar este recurso, desconecte
imediatamente ou podera sofrer sancoes legais e/ou acao disciplinar.
Em caso de problemas envie email para l-monitor-sec@uolinc.com
--------------------------------------------------------------------------------
EOF
fi
}

change_login_defs() {
UMASK=`${CAT} /etc/login.defs | ${GREP} UMASK | ${TAIL} -1 | ${AWK} '{ print $2 }'`
if [ $UMASK -eq 077 ]; then
	${ECHO} ${MC} "${GREEN} O valor do umask ja esta alterado ${UNCOLOR}"
else
	${ECHO} ${MC} "${GREEN} Alterando o valor do umask para o recomendado ${UNCOLOR}"
    ${ECHO} "$(${SED} 's/022/077/' /etc/login.defs)" > /etc/login.defs
    ${UMASKBIN} '077'
	if [[ $i == 2 ]] || [[ $i == 3 ]]
	then
		${ECHO} ${MC} "${GREEN} O valor do umask ja alterado ${UNCOLOR}"
	elif [[ $i == 1 ]] || [[ $i == 4 ]]
	then
		${ECHO} "$(${SED} 's/umask 022/umask 077/' /etc/bashrc)" > /etc/bashrc
	fi
fi

${ECHO} ${MC} "${GREEN} Ajustando os parametros de senhas: ${UNCOLOR}"
${SED} -i -- 's/PASS_MIN_LEN/#PASS_MIN_LEN/g' /etc/login.defs
${SED} -i -- 's/PASS_MAX_DAYS/#PASS_MAX_DAYS/g' /etc/login.defs
${SED} -i -- 's/PASS_MIN_DAYS/#PASS_MIN_DAYS/g' /etc/login.defs
${SED} -i -- 's/PASS_WARN_AGE/#PASS_WARN_AGE/g' /etc/login.defs

${ECHO} "PASS_MIN_LEN 8" >> /etc/login.defs
${ECHO} "PASS_MAX_DAYS 90" >> /etc/login.defs
${ECHO} "PASS_MIN_DAYS 3" >> /etc/login.defs
${ECHO} "PASS_WARN_AGE 7" >> /etc/login.defs
}

change_tmout() {
${ECHO} "readonly TMOUT=7200" >> /etc/profile
${ECHO} "export TMOUT" >> /etc/profile
}

disabled_unservices() {
# Desativando servicos desnecessarios
${ECHO} "${GREEN} Checking (Desativando servicos desnecessarios) ${UNCOLOR}"
if [[ $i == 2 ]] || [[ $i == 3 ]];
then
	for i in $ALLOWSVS; do
		service=`systemctl list-unit-files --type=service | grep "enabled" | grep $i | awk '{ print $1 }'`
		cmd=$(systemctl disable $service)
		[ $? = 0 ] && ${ECHO} ${MC} " - [services] ${service} ${RED}[FAIL]${UNCOLOR} - disable it!" || ${ECHO} ${MC} " - [services] ${service} ${GREEN}[OK]${UNCOLOR}"| COUNTER=$(($COUNTER+1))
	done
else
	CentOS_Version=`cat /etc/*-release | head -1 | grep "^CentOS" | awk '{ print $4 }'`;
	if [[ "$CentOS_Version" == "7.9.2009" ]]; then
        for i in $ALLOWSVS; do
			servicename=`chkconfig --list | grep ':on' | grep $i | awk '{ print $1 }'`;
			service $servicename stop
			cmd=$(chkconfig $servicename off)
			[ $? = 0 ] && ${ECHO} ${MC} " - [services] ${service} ${RED}[FAIL]${UNCOLOR} - disable it!" || ${ECHO} ${MC} " - [services] ${service} ${GREEN}[OK]${UNCOLOR}"| COUNTER=$(($COUNTER+1))
		done
	else 
		for i in $ALLOWSVS; do
			service=`systemctl list-unit-files --type=service | grep "enabled" | grep $i | awk '{ print $1 }'`
			cmd=$(systemctl disable $service)
			[ $? = 0 ] && ${ECHO} ${MC} " - [services] ${service} ${RED}[FAIL]${UNCOLOR} - disable it!" || ${ECHO} ${MC} " - [services] ${service} ${GREEN}[OK]${UNCOLOR}"| COUNTER=$(($COUNTER+1))
		done
	fi
fi
}

remove_nologin() {
${ECHO} ${MC} "${GREEN} Removendo permissao de login ${UNCOLOR}"
if ${CAT} /etc/passwd | ${GREP} "^bin" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario bin perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} bin
else
	${ECHO} ${MC} "${RED} Usuario bin nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^daemon" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario daemon perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} daemon
else
	${ECHO} ${MC} "${RED} Usuario daemon nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^adm" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario adm perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} adm
else
	${ECHO} ${MC} "${RED} Usuario adm nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^lp" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario lp perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} lp
else
	${ECHO} ${MC} "${RED} Usuario lp nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^sync" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario sync perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} sync
else
	${ECHO} ${MC} "${RED} Usuario sync nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^shutdown" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario shutdown perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} shutdown
else
	${ECHO} ${MC} "${RED} Usuario shutdown nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^halt" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario halt perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} halt
else
	${ECHO} ${MC} "${RED} Usuario halt nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^mail" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario mail perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} mail
else
	${ECHO} ${MC} "${RED} Usuario mail nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^uucp" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario uucp perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} uucp
else
	${ECHO} ${MC} "${RED} Usuario uucp nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^operator" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario operator perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} operator
else
	${ECHO} ${MC} "${RED} Usuario operator nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^games" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario games perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} games
else
	${ECHO} ${MC} "${RED} Usuario games nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^gopher" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario gopher perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} gopher
else
	${ECHO} ${MC} "${RED} Usuario gopher nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^ftp" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario ftp perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} ftp
else
	${ECHO} ${MC} "${RED} Usuario ftp nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^nobody" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario nobody perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} nobody
else
	${ECHO} ${MC} "${RED} Usuario nobody nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^vcsa" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario vcsa perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} vcsa
else
	${ECHO} ${MC} "${RED} Usuario vcsa nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^saslauth" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario saslauth perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} saslauth
else
	${ECHO} ${MC} "${RED} Usuario saslauth nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^postfix" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario postfix perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} postfix
else
	${ECHO} ${MC} "${RED} Usuario postfix nao existe ${UNCOLOR}"
fi

if ${CAT} /etc/passwd | ${GREP} "^sshd" > /dev/null
then
	${ECHO} ${MC} "${GREEN} Usuario sshd perdera a opcao de login ${UNCOLOR}"
	${USERMOD} '--shell' ${NOLOGIN} sshd
else
	${ECHO} ${MC} "${RED} Usuario sshd nao existe ${UNCOLOR}"
fi
}

change_perm_passwd() {
${ECHO} ${MC} "${GREEN} Ajustando permissoes de arquivos de senhas ${UNCOLOR}"
${CHOWN} root:root /etc/passwd
${CHOWN} root:root /etc/shadow
${CHOWN} root:root /etc/group
${CHOWN} root:root /etc/gshadow
${CHMOD} 644 /etc/passwd
${CHMOD} 644 /etc/group
${CHMOD} 000 /etc/shadow
${CHMOD} 000 /etc/gshadow
${CHMOD} 600 /etc/logrotate.conf
}

change_perm_crontab() {
${ECHO} ${MC} "${GREEN} Ajustando permissoes do crontab e cron ${UNCOLOR}"
${CHOWN} root:root /etc/crontab
${CHMOD} 600 /etc/crontab

${CHOWN} -R root:root /etc/cron.hourly
${CHOWN} -R root:root /etc/cron.daily
${CHOWN} -R root:root /etc/cron.weekly
${CHOWN} -R root:root /etc/cron.monthly
${CHOWN} -R root:root /etc/cron.d
${CHMOD} -R go-rwx /etc/cron.hourly
${CHMOD} -R go-rwx /etc/cron.daily
${CHMOD} -R go-rwx /etc/cron.weekly
${CHMOD} -R go-rwx /etc/cron.monthly
${CHMOD} -R go-rwx /etc/cron.d
}

chnage_suids()  {
${ECHO} ${MC} "${GREEN} Ajustando SUID dos binarios ${UNCOLOR}"
if which mount > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do mount ${UNCOLOR}"
	${CHMOD} 'u-s' ${MOUNT}
	${CHMOD} '755' ${MOUNT}
else
	${ECHO} ${MC} "${RED} O binario mount nao existe ${UNCOLOR}"
fi

if which umount > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do umount ${UNCOLOR}"
	${CHMOD} 'u-s' ${UMOUNT}
	${CHMOD} '755' ${UMOUNT}
	
else
	${ECHO} ${MC} "${RED} O binario umount nao existe ${UNCOLOR}"
fi

if which netreport > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do netreport ${UNCOLOR}"
	${CHMOD} 'u-s' ${NETREPORT}
	${CHMOD} '755' ${NETREPORT}
	
else
	${ECHO} ${MC} "${RED} O binario netreport nao existe ${UNCOLOR}"
fi

if which at > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do at ${UNCOLOR}"
	${CHMOD} 'u-s' ${AT}
	${CHMOD} '755' ${AT}
	
else
	${ECHO} ${MC} "${RED} O binario at nao existe ${UNCOLOR}"
fi

if which chage > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do chage ${UNCOLOR}"
	${CHMOD} 'u-s' ${CHAGE}
	${CHMOD} '755' ${CHAGE}
	
else
	${ECHO} ${MC} "${RED} O binario chage nao existe ${UNCOLOR}"
fi

if which chfn > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do chfn ${UNCOLOR}"
	${CHMOD} 'u-s' ${CHFN}
	${CHMOD} '755' ${CHFN}
	
else
	${ECHO} ${MC} "${RED} O binario chfn nao existe ${UNCOLOR}"
fi

if which chsh > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do chfn ${UNCOLOR}"
	${CHMOD} 'u-s' ${CHSH}
	${CHMOD} '755' ${CHSH}
	
else
	${ECHO} ${MC} "${RED} O binario chfn nao existe ${UNCOLOR}"
fi

if which gpasswd > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do gpasswd ${UNCOLOR}"
	${CHMOD} 'u-s' ${GPASSWD}
	${CHMOD} '755' ${GPASSWD}
	
else
	${ECHO} ${MC} "${RED} O binario gpasswd nao existe ${UNCOLOR}"
fi

if which locate > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do locate ${UNCOLOR}"
	${CHMOD} 'u-s' ${LOCATE}
	${CHMOD} '755' ${LOCATE}
	
else
	${ECHO} ${MC} "${RED} O binario locate nao existe ${UNCOLOR}"
fi

if which newgrp > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do newgrp ${UNCOLOR}"
	${CHMOD} 'u-s' ${NEWGRP}
	${CHMOD} '755' ${NEWGRP}
	
else
	${ECHO} ${MC} "${RED} O binario newgrp nao existe ${UNCOLOR}"
fi

if which ssh-agent > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do ssh-agent ${UNCOLOR}"
	${CHMOD} 'u-s' ${SSHAGENT}
	${CHMOD} '755' ${SSHAGENT}
	
else
	${ECHO} ${MC} "${RED} O binario ssh-agent nao existe ${UNCOLOR}"
fi

if which wall > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do wall ${UNCOLOR}"
	${CHMOD} 'u-s' ${WALL}
	${CHMOD} '755' ${WALL}
	
else
	${ECHO} ${MC} "${RED} O binario wall nao existe ${UNCOLOR}"
fi

if which write > /dev/null;
then
	${ECHO} ${MC} "${GREEN} Verificando o caminho do binario do wall ${UNCOLOR}"
	${CHMOD} 'u-s' ${WRITE}
	${CHMOD} '755' ${WRITE}
	
else
	${ECHO} ${MC} "${RED} O binario wall nao existe ${UNCOLOR}"
fi
}

ssh_security() {
${ECHO} ${MC} "${GREEN} Ajustando os parametros do SSHD: ${UNCOLOR}"
${SED} -i -- 's/Protocol/#Protocol/g' /etc/ssh/sshd_config
${SED} -i -- 's/UsePrivilegeSeparation/#UsePrivilegeSeparation/g' /etc/ssh/sshd_config
${SED} -i -- 's/RSAAuthentication/#RSAAuthentication/g' /etc/ssh/sshd_config
${SED} -i -- 's/RhostsRSAAuthentication/#RhostsRSAAuthentication/g' /etc/ssh/sshd_config
${SED} -i -- 's/GSSAPIAuthentication/#GSSAPIAuthentication/g' /etc/ssh/sshd_config
${SED} -i -- 's/PermitEmptyPasswords/#PermitEmptyPasswords/g' /etc/ssh/sshd_config
${SED} -i -- 's/PermitRootLogin/#PermitRootLogin/g' /etc/ssh/sshd_config
${SED} -i -- 's/IgnoreRhosts/#IgnoreRhosts/g' /etc/ssh/sshd_config
${SED} -i -- 's/LoginGraceTime/#LoginGraceTime/g' /etc/ssh/sshd_config
${SED} -i -- 's/MaxAuthTries/#MaxAuthTries/g' /etc/ssh/sshd_config
${SED} -i -- 's/StrictModes/#StrictModes/g' /etc/ssh/sshd_config
${SED} -i -- 's/SyslogFacility/#SyslogFacility/g' /etc/ssh/sshd_config
${SED} -i -- 's/AllowTcpForwarding/#AllowTcpForwarding/g' /etc/ssh/sshd_config
${SED} -i -- 's/X11Forwarding/#X11Forwarding/g' /etc/ssh/sshd_config
${SED} -i -- 's/TCPKeepAlive/#TCPKeepAlive/g' /etc/ssh/sshd_config
${SED} -i -- 's/LoginGraceTime/#LoginGraceTime/g' /etc/ssh/sshd_config
${SED} -i -- 's/U$SEDNS/#U$SEDNS/g' /etc/ssh/sshd_config
${SED} -i -- 's/GSSAPIAuthenti$CATion/#GSSAPIAuthenti$CATion/g' /etc/ssh/sshd_config
${SED} -i -- 's/KerberosAuthenti$CATion/#KerberosAuthenti$CATion/g' /etc/ssh/sshd_config
${SED} -i -- 's/PubkeyAuthenti$CATion/#PubkeyAuthenti$CATion/g' /etc/ssh/sshd_config
${SED} -i -- 's/PasswordAuthenti$CATion/#PasswordAuthenti$CATion/g' /etc/ssh/sshd_config
${SED} -i -- 's/ChallengeResponseAuthenti$CATion/#ChallengeResponseAuthenti$CATion/g' /etc/ssh/sshd_config
${SED} -i -- 's/MaxStartups/#MaxStartups/g' /etc/ssh/sshd_config

${ECHO} "Protocol 2" >> /etc/ssh/sshd_config
${ECHO} "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
${ECHO} "PermitRootLogin no" >> /etc/ssh/sshd_config
${ECHO} "IgnoreRhosts yes" >> /etc/ssh/sshd_config
${ECHO} "LoginGraceTime 45" >> /etc/ssh/sshd_config
${ECHO} "MaxAuthTries 3" >> /etc/ssh/sshd_config
${ECHO} "StrictModes yes" >> /etc/ssh/sshd_config
${ECHO} "AllowTcpForwarding no" >> /etc/ssh/sshd_config
${ECHO} "SyslogFacility AUTHPRIV" >> /etc/ssh/sshd_config
${ECHO} "X11Forwarding no" >> /etc/ssh/sshd_config
${ECHO} "TCPKeepAlive yes" >> /etc/ssh/sshd_config
${ECHO} "LoginGraceTime 30" >> /etc/ssh/sshd_config
${ECHO} "UseDNS no" >> /etc/ssh/sshd_config
${ECHO} "GSSAPIAuthenti$CATion no" >> /etc/ssh/sshd_config
${ECHO} "KerberosAuthenti$CATion no" >> /etc/ssh/sshd_config
${ECHO} "PubkeyAuthenti$CATion no" >> /etc/ssh/sshd_config
${ECHO} "PasswordAuthenti$CATion yes" >> /etc/ssh/sshd_config
${ECHO} "ChallengeResponseAuthenti$CATion no" >> /etc/ssh/sshd_config
${ECHO} "UsePrivilegeSeparation yes" >> /etc/ssh/sshd_config
${ECHO} "RSAAuthentication no" >> /etc/ssh/sshd_config
${ECHO} "RhostsRSAAuthentication no" >> /etc/ssh/sshd_config
${ECHO} "GSSAPIAuthentication no" >> /etc/ssh/sshd_config
${ECHO} "MaxStartups 3:50:6" >> /etc/ssh/sshd_config
}

change_syslogsrv() {
# Defina um syslog server
${ECHO} ${MC} "${GREEN} Aplicando (Defina um syslog server) ${UNCOLOR}"
${ECHO} "*.* @10.154.4.103:514" >> /etc/rsyslog.conf
}


kernel_security() {
${ECHO} ${MC} "${GREEN} Validando o arquivo sysctl.conf ${UNCOLOR}"
if ls /etc/ | ${GREP} sysctl.conf  > /dev/null
then
		${ECHO} ${MC} "${GREEN} O arquivo sysctl.conf ja existe ${UNCOLOR}"
        ${CAT} <<EOF > /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_$ECHO_ignore_broadcasts=1
EOF
else
        ${TOUCH} /etc/sysctl.conf
        ${CHMOD} 600 /etc/sysctl.conf
        ${CAT} <<EOF > /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_$ECHO_ignore_broadcasts=1
EOF
fi
}

disable_coredump() {
${ECHO} ${MC} "${GREEN} Desabilitando core dump: ${UNCOLOR}"
${ECHO} "* hard core 0" >> /etc/security/limits.conf
${ECHO} "fs.suid_dumpable = 0" >> /etc/sysctl.conf
}

chk_rootuser
check_release
banner
verify_logrotate
change_logrotate
verify_rsyslog
pam_security
change_remoteroot
systemlogs_perm
home_perm
ch_crond
add_group_wheel
change_banner
change_login_defs
change_tmout
disabled_unservices
remove_nologin
change_perm_passwd
change_perm_crontab
chnage_suids
ssh_security
change_syslogsrv
kernel_security
disable_coredump
