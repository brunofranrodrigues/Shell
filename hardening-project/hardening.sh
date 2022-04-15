#!/bin/bash

# ---------------------------------------
# Environment variables
# ---------------------------------------
OS=$OSVERSION
MN="-n"
MC="-e"
COUNTER=0
LANG=C
export LANG
MAINHOST=`uname ${MN}`
PWD_DIR=`pwd`
confirm=$1
CHATTR=`which chattr`
CHOWN=`which chown`
CHMOD=`which chmod`
USERMOD=`which usermod`
AWK=`which awk`
ECHO=`which echo`
GREP=`which grep`
EGREP=`which egrep`
HEAD=`which head`
TR=`which tr`
TAIL=`which tail`
GETFACL=`which getfacl`
LSATTR=`which lsattr`
PATH=$PATH:/sbin:/bin
export PATH

# ---------------------------------------
# LVS settings
# ---------------------------------------
HOMEDIR="/home"
PASS_MIN_LEN="8"    # Tamanho minimo de senha
PASS_MAX_DAYS="90"  # Tempo maximo para forcar troca de senha
PASS_MIN_DAYS="1"   # Tempo minimo para troca de senha
PASS_WARN_AGE="89"  # Tempo para emitir o aviso para troca de senha
DIFOK="3"           # Quantidade minima de caracteres diferentes em relacao a ultima senha
DCREDIT="1"         # Quantos digitos devem conter na senha
LCREDIT="1"         # Quantas letras minusculas devem conter na senha
UCREDIT="1"         # Quantas letras maiusculas devem conter na senha
OCREDIT="1"         # Quantos caracteres especiais devem conter na senha
REMEMBER="4"        # Historico de senhas que nao podem ser utilizadas
TMOUT="7200"    # Defina o tempo de timeout das sessoes idle no servidor (em segundos) / 86400 = 1 dia
ALLOWCRON="root"    # Usuarios permitidos para utilizarem o crontab
SYSLOGSRV="10.154.4.103" # Servidor syslog
SYSLOGFILE="/etc/rsyslog.conf"         # Arquivo principal do syslog
HA_PROFILE="cliente"     # (uoldiveo/cliente) Defina o profile do script, 'uoldiveo' para servidores internos e 'cliente' para servidores de clientes
GRUBCONF="/etc/grub.conf" # Path para o arquivo de configuracao do GRUB

# ---------------------------------------
# SSH settings
# ---------------------------------------

ALLOW_EMPTY_PASS="no"          # Permitir senhas em branco (yes/no)
ALLOW_ROOT_LOGIN="no"          # Permitir login remoto com root (yes/no/without-password)
IGNORE_RHOSTS="yes"            # Ignorar configuracoes de rhosts (inseguro)
ALLOW_RHOSTS="no"              # Permitir acesso via rhosts (yes/no)
ALLOW_RHOSTS_RSA="no"          # Permitir acesso via rhosts com RSA (yes/no)
MAX_AUTH_TRIES="3"             # Limite de tentativas de login sem sucesso (0 - desabilitado ou >= 1)
ALLOW_TCP_FORWARD="no"         # Permitir Tcp Forwarding (Tunneling)
ALLOW_X11_FORWARD="no"         # Permitir X11 Forwarding (exportar remotar aplicacacoes graficas)
ALLOW_KEEPALIVE="yes"          # Permitir uso de keepalive para manter sessoes abertas
GRACE_TIME="30"                # Tempo durante o login para inserir as credenciais
USE_DNS="no"                   # Usar resolucao DNS para conexoes (yes/no)
GSSAPI_AUTH="no"               # Permitir autenticacao GSSAPI? (yes/no)
KERBEROS_AUTH="no"             # Permitir autenticacao Kerberos? (yes/no)
PUBKEY_AUTH="no"               # Permitir autenticacao via Pubkey? (yes/no)
RSA_AUTH="no"                  # Permitir autenticacao via RSA ? (yes/no)
CHALLENGE_PAM="no"             # Utilizar challenge-response passwords do PAM? (yes/no)
SERVERKEY_BITS="2048"          # Bits nas chaves geradas pelo SSH Server

# ---------------------------------------
# Servicos NAO permitidos
# ---------------------------------------
ALLOWSVS="abrt-ccpp
abrt-oops
abrtd
acpid
anacron
apmd
atd
avahi-daemon
bluetooth
cups
dkms_autoinstaller
firstboot
gpm
hidd
hplip
isdn
kdump
kudzu
messagebus
microcode_ctl
netconsole
prelink
postfix
psacct
pcscd
qpidd
rdisc
readahead_early
readahead_later
rpcbind
rpcgssd
rpcidmapd
saslauthd
smart"

# ---------------------------------------
# SUIDs *NAO* permitidos
# ---------------------------------------
DENYSIDS="/bin/mount
/bin/umount
/sbin/netreport
/usr/bin/at
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/locate
/usr/bin/newgrp
/usr/bin/ssh-agent
/usr/bin/wall
/usr/bin/write
/usr/libexec/openssh/ssh-keysign
/usr/libexec/utempter/utempter
/usr/sbin/sendmail.postfix
/usr/sbin/usernetctl"

# ---------------------------------------
# Usuarios padroes do sistema
# ---------------------------------------
SYSTEMUSERS="bin
daemon
adm
lp
sync
shutdown
halt
mail
uucp
operator
games
gopher
ftp
nobody
vcsa
saslauth
postfix
sshd" 

# ---------------------------------------
# Filesystem must disable
# ---------------------------------------
FS_DISABLED="cramfs
freevxfs
jffs2
hfs
hfsplus
squashfs
udf"

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

banner() {

if cat /etc/*release | grep ^NAME | grep CentOS; then
	OSVERSION=`cat /etc/*release | head -1`
elif cat /etc/*release | grep ^NAME | grep Red; then
	OSVERSION=`cat /etc/*release | head -1`
elif cat /etc/*release | grep ^NAME | grep Fedora; then
	OSVERSION=`cat /etc/*release | head -1`
elif cat /etc/*release | grep ^NAME | grep Ubuntu; then
	OSVERSION=`cat /etc/*release | head -4 | tail -1 | awk -F'=' {' print $2 '}`
elif cat /etc/*release | grep ^NAME | grep Debian ; then
	OSVERSION=`cat /etc/*release | head -1 | awk -F'=' {' print $2 '}`
elif cat /etc/*release | grep ^NAME | grep Oracle ; then
	OSVERSION=`cat /etc/*release | head -1`
else
    echo "OS NOT DETECTED, couldn't verify package"
fi
clear
${ECHO} ""
${ECHO} "----------------------------------------------"
${ECHO} "LVS - Linux Validate Script - Client Version"
${ECHO} "----------------------------------------------"
${ECHO} ""
${ECHO} ${MC} "${RED}[Host Configuration]${INCOLOR}"

GETIP=$(ip a | grep "inet" | grep -v 127.0.0.1 | tail -2 | head -1 | awk -F' ' {' print $2 '})
cmd=$(for i in ${GETIP}; do ${ECHO} ${MN} "${i} ";done)
${ECHO} ${MC} "${YELLOW}OS Version:${UNCOLOR} $OSVERSION"
${ECHO} ${MC} "${YELLOW}Hostname:${UNCOLOR} `hostname`"
${ECHO} ${MC} "${YELLOW}IP(s):${UNCOLOR} ${cmd}"
${ECHO} ""
${ECHO} ""
}

# ---------------------------------------
# Init
# ---------------------------------------
banner
