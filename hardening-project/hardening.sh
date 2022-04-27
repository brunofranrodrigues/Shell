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
opc=0

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
     $ECHO "$0 must be run as root"
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
        $ECHO $OSVERSION
elif [[ "$OSTYPE" == "Debian" ]]; then
        i=2
        OSVERSION=`$CAT /etc/*-release | $HEAD -1 | $AWK -F'=' {' print $2 '}`
        $ECHO $OSVERSION
elif [[ "$OSTYPE" == "Ubuntu" ]]; then
        i=3
        OSVERSION=`$CAT /etc/*-release | $HEAD -4 | $TAIL -1 | $AWK -F'=' {' print $2 '}`
        $ECHO $OSVERSION
elif [[ "$OSTYPE" == "Oracle" ]]; then
        i=4
        OSVERSION=`$CAT /etc/*-release | $HEAD -1`
        $ECHO $OSVERSION
else	
		$ECHO $Erro
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
${ECHO} -e $Erro
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
	if $DPKG -l | $GREP logrotate > /dev/null;
	then
		${ECHO} "O pacote logrotate ja esta instalado"
	else
		${ECHO} "O pacote do logrotate sera instalado"
		$APTGET install logrotate
	fi 
elif [[ $i == 1 ]] || [[ $i == 4 ]];
then
	if $RPM -qa | $GREP logrotate > /dev/null;
	then
		${ECHO} "O pacote logrotate ja esta instalado"
	else
		${ECHO} "O pacote do logrotate sera instalado"
		$YUM install logrotate
	fi
fi
}

verify_rsyslog(){
if [[ $i == 2 ]] || [[ $i == 3 ]];
then
	if $DPKG -l | $GREP rsyslog > /dev/null;
	then
		${ECHO} "O pacote rsyslog ja esta instalado"
	else
		${ECHO} "O pacote do rsyslog sera instalado"
		$APTGET install rsyslog
	fi 
elif [[ $i == 1 ]] || [[ $i == 4 ]];
then
	if $RPM -qa | $GREP rsyslog > /dev/null;
	then
		${ECHO} "O pacote rsyslog ja esta instalado"
	else
		${ECHO} "O pacote do rsyslog sera instalado"
		$YUM install rsyslog
	fi
fi
}

pam_security() {
if [[ $i == 2 ]] || [[ $i == 3 ]]
then
  $ECHO "password    requisite     pam_cracklib.so try_first_pass retry=3 type=difok=3 minlen=8 dcredit=1 lcredit=1 ucredit=1 ocredit=1" >> /etc/pam.d/common-password
  $ECHO "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=4" >> /etc/pam.d/common-password
  $ECHO "auth         required        pam_wheel.so wheel" >> /etc/pam.d/su
elif [[ $i == 1 ]] || [[ $i == 4 ]]
then
  $ECHO "password    requisite     pam_cracklib.so try_first_pass retry=3 type=difok=3 minlen=8 dcredit=1 lcredit=1 ucredit=1 ocredit=1" >> /etc/pam.d/system-auth
  $ECHO "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=4" >> /etc/pam.d/system-auth
  $ECHO "auth         required        pam_wheel.so wheel" >> /etc/pam.d/su
fi
}

systemlogs_perm() {
$ECHO "Ajuste das permissoes de logs"
$FIND /var/log/ -type f -exec $CHMOD 600 {} \;

$CHMOD +t /var/tmp
$CHMOD +t /tmp

$ECHO "Ajuste das permissoes do arquivo wtmp"
if ls /var/log/ | $GREP wtmp > /dev/null
then 
	$ECHO "o arquivo wtmp ja existe"
	$CHMOD 640 /var/log/wtmp
else
	$TOUCH /var/log/wtmp
	$CHMOD 640 /var/log/wtmp
fi
}

home_perm() {
$ECHO "Ajuste das permissoes do home"
$FIND /home/ -type d -exec $CHMOD 700 {} \;

$CHMOD 755 /home
}

change_remoteroot(){
$ECHO "Validando o arquivo securetty"
if ls /etc/ | $GREP securetty > /dev/null
then
	$ECHO "O arquivo securetty ja existe"
else
	$TOUCH /etc/securetty
	$CHMOD 640 /etc/securetty
	$CAT <<EOF > /etc/securetty
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
$ECHO "Validando o arquivo cron.allow"
if ls /etc/ | $GREP cron.allow  > /dev/null
then
	$ECHO "O arquivo cron.allow ja existe"
	$ECHO "root" >> cron.allow
else
	$TOUCH /etc/cron.allow
	$CHMOD 600 /etc/cron.allow
	$CAT <<EOF > /etc/cron.allow
root
EOF
fi

$ECHO "Validando o arquivo cron.deny"
if ls /etc/ | $GREP cron.deny  > /dev/null
then
	$ECHO "O arquivo cron.deny ja existe"
	$CAT <<EOF > /etc/cron.deny
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
	$TOUCH /etc/cron.deny
	$CHMOD 600 /etc/cron.deny
	$CAT <<EOF > /etc/cron.deny
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
$ECHO "Validando o grupo wheel"
if $CAT /etc/group | $GREP wheel > /dev/null
then
	$ECHO "O grupo wheel ja existe"
	$USERMOD -a -G wheel root
else
	groupadd wheel
	$ECHO "grupo wheel criado"
	$USERMOD -a -G wheel root
fi
}

change_banner() {
$ECHO "Validando /etc/motd"
if ls /etc | $GREP motd > /dev/null
then 
	$ECHO "O arquivo motd ja existe"
	$CAT <<EOF > /etc/motd
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
	$TOUCH /etc/motd
	$CHMOD 640 /etc/motd
	$CAT <<EOF > /etc/motd
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

$ECHO "Validando /etc/issue.net"
if ls /etc | $GREP issue.net > /dev/null
then 
	$ECHO "o arquivo motd ja existe"
	$CAT <<EOF > /etc/issue.net
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
	$TOUCH /etc/issue.net
	$CHMOD 640 /etc/issue.net
	$CAT <<EOF > /etc/issue.net
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
UMASK=`$CAT /etc/login.defs | $GREP UMASK | $TAIL -1 | $AWK '{ print $2 }'`
if [ $UMASK -eq 077 ]; then
        $ECHO "O valor do umask ja esta alterado"
else
        $ECHO "Alterando o valor do umask para o recomendado"
        $ECHO "$($SED 's/022/077/' /etc/login.defs)" > /etc/login.defs
        umask 077
fi

$ECHO "Ajustando a validacao de senhas:"
$SED -i -- 's/PASS_MIN_LEN/#PASS_MIN_LEN/g' /etc/login.defs
$SED -i -- 's/PASS_MAX_DAYS/#PASS_MAX_DAYS/g' /etc/login.defs
$SED -i -- 's/PASS_MIN_DAYS/#PASS_MIN_DAYS/g' /etc/login.defs
$SED -i -- 's/PASS_WARN_AGE/#PASS_WARN_AGE/g' /etc/login.defs

$ECHO "PASS_MIN_LEN 8" >> /etc/login.defs
$ECHO "PASS_MAX_DAYS 90" >> /etc/login.defs
$ECHO "PASS_MIN_DAYS 3" >> /etc/login.defs
$ECHO "PASS_WARN_AGE 7" >> /etc/login.defs
}

change_tmout() {
$ECHO "readonly TMOUT=7200" >> /etc/profile
$ECHO "export TMOUT" >> /etc/profile
}

remove_nologin() {
$ECHO "Removendo permissao de login"
$USERMOD --shell $NOLOGIN bin
$USERMOD --shell $NOLOGIN daemon
$USERMOD --shell $NOLOGIN adm
$USERMOD --shell $NOLOGIN lp
$USERMOD --shell $NOLOGIN sync
$USERMOD --shell $NOLOGIN shutdown
$USERMOD --shell $NOLOGIN halt
$USERMOD --shell $NOLOGIN mail
$USERMOD --shell $NOLOGIN uucp
$USERMOD --shell $NOLOGIN operator
$USERMOD --shell $NOLOGIN games
$USERMOD --shell $NOLOGIN gopher
$USERMOD --shell $NOLOGIN ftp
$USERMOD --shell $NOLOGIN nobody
$USERMOD --shell $NOLOGIN vcsa
$USERMOD --shell $NOLOGIN saslauth
$USERMOD --shell $NOLOGIN postfix
$USERMOD --shell $NOLOGIN sshd
}

change_perm_passwd() {
$ECHO "Ajustando permissoes de arquivos de senhas"
$CHOWN root:root /etc/passwd
$CHOWN root:root /etc/shadow
$CHOWN root:root /etc/group
$CHOWN root:root /etc/gshadow
$CHMOD 644 /etc/passwd
$CHMOD 644 /etc/group
$CHMOD 000 /etc/shadow
$CHMOD 000 /etc/gshadow
$CHMOD 600 /etc/logrotate.conf
}

change_perm_crontab() {
$ECHO "Ajustando permissoes do crontab e cron"
$CHOWN root:root /etc/crontab
$CHMOD 600 /etc/crontab

$CHOWN -R root:root /etc/cron.hourly
$CHOWN -R root:root /etc/cron.daily
$CHOWN -R root:root /etc/cron.weekly
$CHOWN -R root:root /etc/cron.monthly
$CHOWN -R root:root /etc/cron.d
$CHMOD -R go-rwx /etc/cron.hourly
$CHMOD -R go-rwx /etc/cron.daily
$CHMOD -R go-rwx /etc/cron.weekly
$CHMOD -R go-rwx /etc/cron.monthly
$CHMOD -R go-rwx /etc/cron.d
}

chnage_suids()  {
$ECHO "Ajustando SUID dos binarios"
$CHMOD "u-s" $MOUNT
$CHMOD "u-s" $UMOUNT
$CHMOD "u-s" $NETREPORT
$CHMOD "u-s" $AT
$CHMOD "u-s" $CHAGE
$CHMOD "u-s" $CHFN
$CHMOD "u-s" $CHSH
$CHMOD "u-s" $GPASSWD
$CHMOD "u-s" $LOCATE
$CHMOD "u-s" $NEWGRP
$CHMOD "u-s" $SSHAGENT
$CHMOD "u-s" $WALL
$CHMOD "u-s" $WRITE
$CHMOD "755" $MOUNT
$CHMOD "755" $UMOUNT
$CHMOD "755" $NETREPORT
$CHMOD "755" $AT
$CHMOD "755" $CHAGE
$CHMOD "755" $CHFN
$CHMOD "755" $CHSH
$CHMOD "755" $GPASSWD
$CHMOD "755" $LOCATE
$CHMOD "755" $NEWGRP
$CHMOD "755" $SSHAGENT
$CHMOD "755" $WALL
$CHMOD "755" $WRITE
}

ssh_security() {
$ECHO "Ajustando os parametros do SSHD:"
$SED -i -- 's/Protocol/#Protocol/g' /etc/ssh/sshd_config
$SED -i -- 's/UsePrivilegeSeparation/#UsePrivilegeSeparation/g' /etc/ssh/sshd_config
$SED -i -- 's/RSAAuthentication/#RSAAuthentication/g' /etc/ssh/sshd_config
$SED -i -- 's/RhostsRSAAuthentication/#RhostsRSAAuthentication/g' /etc/ssh/sshd_config
$SED -i -- 's/GSSAPIAuthentication/#GSSAPIAuthentication/g' /etc/ssh/sshd_config
$SED -i -- 's/PermitEmptyPasswords/#PermitEmptyPasswords/g' /etc/ssh/sshd_config
$SED -i -- 's/PermitRootLogin/#PermitRootLogin/g' /etc/ssh/sshd_config
$SED -i -- 's/IgnoreRhosts/#IgnoreRhosts/g' /etc/ssh/sshd_config
$SED -i -- 's/LoginGraceTime/#LoginGraceTime/g' /etc/ssh/sshd_config
$SED -i -- 's/MaxAuthTries/#MaxAuthTries/g' /etc/ssh/sshd_config
$SED -i -- 's/StrictModes/#StrictModes/g' /etc/ssh/sshd_config
$SED -i -- 's/SyslogFacility/#SyslogFacility/g' /etc/ssh/sshd_config
$SED -i -- 's/AllowTcpForwarding/#AllowTcpForwarding/g' /etc/ssh/sshd_config
$SED -i -- 's/X11Forwarding/#X11Forwarding/g' /etc/ssh/sshd_config
$SED -i -- 's/TCPKeepAlive/#TCPKeepAlive/g' /etc/ssh/sshd_config
$SED -i -- 's/LoginGraceTime/#LoginGraceTime/g' /etc/ssh/sshd_config
$SED -i -- 's/U$SEDNS/#U$SEDNS/g' /etc/ssh/sshd_config
$SED -i -- 's/GSSAPIAuthenti$CATion/#GSSAPIAuthenti$CATion/g' /etc/ssh/sshd_config
$SED -i -- 's/KerberosAuthenti$CATion/#KerberosAuthenti$CATion/g' /etc/ssh/sshd_config
$SED -i -- 's/PubkeyAuthenti$CATion/#PubkeyAuthenti$CATion/g' /etc/ssh/sshd_config
$SED -i -- 's/PasswordAuthenti$CATion/#PasswordAuthenti$CATion/g' /etc/ssh/sshd_config
$SED -i -- 's/ChallengeResponseAuthenti$CATion/#ChallengeResponseAuthenti$CATion/g' /etc/ssh/sshd_config
$SED -i -- 's/MaxStartups/#MaxStartups/g' /etc/ssh/sshd_config

$ECHO "Protocol 2" >> /etc/ssh/sshd_config
$ECHO "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
$ECHO "PermitRootLogin no" >> /etc/ssh/sshd_config
$ECHO "IgnoreRhosts yes" >> /etc/ssh/sshd_config
$ECHO "LoginGraceTime 45" >> /etc/ssh/sshd_config
$ECHO "MaxAuthTries 3" >> /etc/ssh/sshd_config
$ECHO "StrictModes yes" >> /etc/ssh/sshd_config
$ECHO "AllowTcpForwarding no" >> /etc/ssh/sshd_config
$ECHO "SyslogFacility AUTHPRIV" >> /etc/ssh/sshd_config
$ECHO "X11Forwarding no" >> /etc/ssh/sshd_config
$ECHO "TCPKeepAlive yes" >> /etc/ssh/sshd_config
$ECHO "LoginGraceTime 30" >> /etc/ssh/sshd_config
$ECHO "UseDNS no" >> /etc/ssh/sshd_config
$ECHO "GSSAPIAuthenti$CATion no" >> /etc/ssh/sshd_config
$ECHO "KerberosAuthenti$CATion no" >> /etc/ssh/sshd_config
$ECHO "PubkeyAuthenti$CATion no" >> /etc/ssh/sshd_config
$ECHO "PasswordAuthenti$CATion yes" >> /etc/ssh/sshd_config
$ECHO "ChallengeResponseAuthenti$CATion no" >> /etc/ssh/sshd_config
$ECHO "UsePrivilegeSeparation yes" >> /etc/ssh/sshd_config
$ECHO "RSAAuthentication no" >> /etc/ssh/sshd_config
$ECHO "RhostsRSAAuthentication no" >> /etc/ssh/sshd_config
$ECHO "GSSAPIAuthentication no" >> /etc/ssh/sshd_config
$ECHO "MaxStartups 3:50:6" >> /etc/ssh/sshd_config
}

kernel_security() {
$ECHO "Validando o arquivo sysctl.conf"
if ls /etc/ | $GREP sysctl.conf  > /dev/null
then
        $ECHO "o arquivo sysctl.conf ja existe"
        $CAT <<EOF > /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_$ECHO_ignore_broadcasts=1
EOF
else
        $TOUCH /etc/sysctl.conf
        $CHMOD 600 /etc/sysctl.conf
        $CAT <<EOF > /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_$ECHO_ignore_broadcasts=1
EOF
fi
}

disable_coredump() {
$ECHO "Desabilitando core dump:"
$ECHO "* hard core 0" >> /etc/security/limits.conf
$ECHO "fs.suid_dumpable = 0" >> /etc/security/limits.conf
}

chk_rootuser
check_release
banner
verify_logrotate
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
remove_nologin
change_perm_passwd
change_perm_crontab
chnage_suids
ssh_security
kernel_security
disable_coredump
