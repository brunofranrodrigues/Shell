#!/bin/bash
#
# $Linux: LVS.sh,v criação 1.0 2013/02/14 12:27 fmotta Exp $
# $Linux: LVS.sh,v revisão 1.1 2022/04/28 08:19 brfrodrigues Exp $
#
# Author: Felippe de Meirelles Motta (fmotta at uoldiveo dot com)
#
# Ensuring that all items were applied by linux team
#
# ChangeLog:
# 1.0 - LVS (Linux Security Checklist Script) Released
# 1.1 - Disable prelink service on Linux and some bug fixes
#
# TODO:
# Debian Support

# ---------------------------------------
# Environment variables
# ---------------------------------------
Erro="Sistema nao homologado"
OSVERSION=""
OS=""
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
CUT=`which cut`
CAT=`which cat`
AWK=`which awk`
ECHO=`which echo`
GREP=`which grep`
EGREP=`which egrep`
HEAD=`which head`
TR=`which tr`
TAIL=`which tail`
GETFACL=`which getfacl`
LSATTR=`which lsattr`
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

PATH=$PATH:/sbin:/bin
export PATH="${PATH:+$PATH:}/sbin:/usr/sbin:/bin:/usr/bin"


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
DENYSIDS="$MOUNT
$UMOUNT
$NETREPORT
$AT
$CHAGE
$CHFN
$CHSH
$GPASSWD
$LOCATE
$NEWGRP
$SSHAGENT
$WALL
$WRITE"

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

# ---------------------------------------
# Functions
# ---------------------------------------

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
${ECHO} "" 
${ECHO} "----------------------------------------------"
${ECHO} "LVS - Linux Validate Script - Client Version"
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

chk_bootloader() {
# TESTADO
# Incluir senha no Boot Loader
${ECHO} ${MN} "Checking (Incluir senha no Boot Loader): "
cmd=$(${GREP} -e "^password --md5 " ${GRUBCONF})
[ $? = 0 ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_remoteroot() {
# TESTADO
# Remover login remoto como super-usuario
${ECHO} ${MN} "Checking (Remover login remoto como super-usuario) "
cmd=$(${GREP} -e "^vc" -e "^console" /etc/securetty)
[ $? = 0 ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_systemlogs_perm() {
# TESTADO
# Restringindo acesso de visualizacao por outros nos logs do sistema
${ECHO} "Checking (Restringindo acesso de visualizacao por outros nos logs do sistema): "
if [ -f /var/log/bash.log ] && [ $(stat -c '%a' /var/log/bash.log) -eq 600 ]; then
        ${ECHO} ${MC} " - /var/log/bash.log ${GREEN}[OK]${UNCOLOR}"
else
     if [ -f /var/log/bash.log ]; then
        ${ECHO} ${MC} " - /var/log/bash.log ${RED}[FAIL]${UNCOLOR}"
          COUNTER=$(($COUNTER+1))
     else
          ${ECHO} ${MC} " - /var/log/bash.log ${GREEN}[OK]${UNCOLOR}"
     fi
fi
if [ -f /var/log/messages ] && [ $(stat -c '%a' /var/log/messages) -eq 600 ]; then
        ${ECHO} ${MC} " - /var/log/messages ${GREEN}[OK]${UNCOLOR}"
else
     if [ -f /var/log/messages ]; then
        ${ECHO} ${MC} " - /var/log/messages ${RED}[FAIL]${UNCOLOR}"
          COUNTER=$(($COUNTER+1))
     else
          ${ECHO} ${MC} " - /var/log/messages ${GREEN}[OK]${UNCOLOR}"
     fi
fi
if [ -f /var/log/syslog ] && [ $(stat -c '%a' /var/log/syslog) -eq 600 ]; then
        ${ECHO} ${MC} " - /var/log/syslog ${GREEN}[OK]${UNCOLOR}"
else
     if [ -f /var/log/syslog ]; then
        ${ECHO} ${MC} " - /var/log/syslog ${RED}[FAIL]${UNCOLOR}"
          COUNTER=$(($COUNTER+1))
     else
          ${ECHO} ${MC} " - /var/log/syslog ${GREEN}[OK]${UNCOLOR}"
     fi
fi
if [ -f /var/log/secure ] && [ $(stat -c '%a' /var/log/secure) -eq 600 ]; then
        ${ECHO} ${MC} " - /var/log/secure ${GREEN}[OK]${UNCOLOR}"
else
     if [ -f /var/log/secure ]; then
        ${ECHO} ${MC} " - /var/log/secure ${RED}[FAIL]${UNCOLOR}"
          COUNTER=$(($COUNTER+1))
     else
          ${ECHO} ${MC} " - /var/log/secure ${GREEN}[OK]${UNCOLOR}"
     fi
fi
if [ -f /var/log/dmesg ] && [ $(stat -c '%a' /var/log/dmesg) -eq 600 ]; then
        ${ECHO} ${MC} " - /var/log/dmesg ${GREEN}[OK]${UNCOLOR}"
else
     if [ -f /var/log/dmesg ]; then
        ${ECHO} ${MC} " - /var/log/dmesg ${RED}[FAIL]${UNCOLOR}"
          COUNTER=$(($COUNTER+1))
     else
          ${ECHO} ${MC} " - /var/log/dmesg ${GREEN}[OK]${UNCOLOR}"
     fi
fi
if [ -f /var/log/cron ] && [ $(stat -c '%a' /var/log/cron) -eq 600 ]; then
        ${ECHO} ${MC} " - /var/log/cron ${GREEN}[OK]${UNCOLOR}"
else
     if [ -f /var/log/cron ]; then
        ${ECHO} ${MC} " - /var/log/cron ${RED}[FAIL]${UNCOLOR}"
          COUNTER=$(($COUNTER+1))
     else
          ${ECHO} ${MC} " - /var/log/cron ${GREEN}[OK]${UNCOLOR}"
     fi
fi
if [ -f /var/log/audit/audit.log ] && [ $(stat -c '%a' /var/log/audit/audit.log) -eq 600 ]; then
        ${ECHO} ${MC} " - /var/log/audit/audit.log ${GREEN}[OK]${UNCOLOR}"
else
     if [ -f /var/log/audit/audit.log ]; then
        ${ECHO} ${MC} " - /var/log/audit/audit.log ${RED}[FAIL]${UNCOLOR}"
          COUNTER=$(($COUNTER+1))
     else
          ${ECHO} ${MC} " - /var/log/audit/audit.log ${GREEN}[OK]${UNCOLOR}"
     fi
fi
if [ -f /var/log/wtmp ] && [ $(stat -c '%a' /var/log/wtmp) -eq 640 ]; then
        ${ECHO} ${MC} " - /var/log/wtmp ${GREEN}[OK]${UNCOLOR}"
else
     if [ -f /var/log/wtmp ]; then
        ${ECHO} ${MC} " - /var/log/wtmp ${RED}[FAIL]${UNCOLOR}"
          COUNTER=$(($COUNTER+1))
     else
          ${ECHO} ${MC} " - /var/log/wtmp ${GREEN}[OK]${UNCOLOR}"
     fi
fi
if [ -f /var/log/btmp ] && [ $(stat -c '%a' /var/log/btmp) -eq 600 ]; then
        ${ECHO} ${MC} " - /var/log/btmp ${GREEN}[OK]${UNCOLOR}"
else
     if [ -f /var/log/btmp ]; then
        ${ECHO} ${MC} " - /var/log/btmp ${RED}[FAIL]${UNCOLOR}"
          COUNTER=$(($COUNTER+1))
     else
          ${ECHO} ${MC} " - /var/log/btmp ${GREEN}[OK]${UNCOLOR}"
     fi
fi

}

chk_logrotate() {
# TESTADO
# Configurar logrotate para criar arquivos de auditagem por permissao restritiva
${ECHO} "Checking (Configurar logrotate para criar arquivos de auditagem por permissao restritiva) "
cmd=$(${GREP} -e "^create 0600" /etc/logrotate.conf)
[ $? = 0 ] && ${ECHO} ${MC} " - [logrotate.conf] create 0600 entry ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [logrotate.conf] create 0600 entry ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${GREP} -m 1 utmp /etc/logrotate.conf | ${GREP} "create 0640")
[ $? = 0 ] && ${ECHO} ${MC} " - [logrotate.conf] utmp permission ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [logrotate.conf] utmp permission ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}


chk_umask() {
# TESTADO
# Definir umask padrao restritivo
${ECHO} ${MN} "Checking (Definir umask padrao restritivo)  "
cmd=$(${GREP} -e "umask 077" /etc/bashrc)
[ $? = 0 ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_authpasswd() {
# TESTADO
## Politica de Senhas
# Configurar numero minimo de caracteres em senha
# Configurar tempo maximo que a senha pode ser utilizada
# Configurar tempo minimo entre mudanca de senhas
# Configurar tempo de alerta para o usuario que esta proximo da expiracao de senha
# Habilitar verificacao da trivialidade da senha
# Definir tamanho de historico de senhas
${ECHO} "Checking (Politica de Senhas): "
if [[ $i == 2 ]] || [[ $i == 3 ]]
then
    cmd=$(${EGREP} "PASS_MIN_LEN.*${PASS_MIN_LEN}" /etc/login.defs)
	[ $? = 0 ] && ${ECHO} ${MC} " - [login.defs] PASS_MIN_LEN ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [login.defs] PASS_MIN_LEN ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	#cmd=$(${EGREP} "PASS_MIN_DAYS.*${PASS_MIN_DAYS}" /etc/login.defs)
	#[ $? = 0 ] && ${ECHO} ${MC} " - [login.defs] PASS_MIN_DAYS ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [login.defs] PASS_MIN_DAYS ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "difok=${DIFOK}" /etc/pam.d/common-password)
	[ $? = 0 ] && ${ECHO} ${MC} " - [common-password] difok ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [common-password] difok ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "minlen=${PASS_MIN_LEN}" /etc/pam.d/common-password)
	[ $? = 0 ] && ${ECHO} ${MC} " - [common-password] minlen ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [common-password] minlen ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "dcredit=${DCREDIT}" /etc/pam.d/common-password)
	[ $? = 0 ] && ${ECHO} ${MC} " - [common-password] dcredit ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [common-password] dcredit ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "lcredit=${LCREDIT}" /etc/pam.d/common-password)
	[ $? = 0 ] && ${ECHO} ${MC} " - [common-password] lcredit ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [common-password] lcredit ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "ucredit=${UCREDIT}" /etc/pam.d/common-password)
	[ $? = 0 ] && ${ECHO} ${MC} " - [common-password] ucredit ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [common-password] ucredit ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "ocredit=${OCREDIT}" /etc/pam.d/common-password)
	[ $? = 0 ] && ${ECHO} ${MC} " - [common-password] ocredit ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [common-password] ocredit ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "remember=${REMEMBER}" /etc/pam.d/common-password)
	[ $? = 0 ] && ${ECHO} ${MC} " - [common-password] remember ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [common-password] remember ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
elif [[ $i == 1 ]] || [[ $i == 4 ]]
then
	cmd=$(${EGREP} "PASS_MIN_LEN.*${PASS_MIN_LEN}" /etc/login.defs)
	[ $? = 0 ] && ${ECHO} ${MC} " - [login.defs] PASS_MIN_LEN ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [login.defs] PASS_MIN_LEN ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	#cmd=$(${EGREP} "PASS_MIN_DAYS.*${PASS_MIN_DAYS}" /etc/login.defs)
	#[ $? = 0 ] && ${ECHO} ${MC} " - [login.defs] PASS_MIN_DAYS ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [login.defs] PASS_MIN_DAYS ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "difok=${DIFOK}" /etc/pam.d/system-auth)
	[ $? = 0 ] && ${ECHO} ${MC} " - [system-auth] difok ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [system-auth] difok ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "minlen=${PASS_MIN_LEN}" /etc/pam.d/system-auth)
	[ $? = 0 ] && ${ECHO} ${MC} " - [system-auth] minlen ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [system-auth] minlen ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "dcredit=${DCREDIT}" /etc/pam.d/system-auth)
	[ $? = 0 ] && ${ECHO} ${MC} " - [system-auth] dcredit ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [system-auth] dcredit ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "lcredit=${LCREDIT}" /etc/pam.d/system-auth)
	[ $? = 0 ] && ${ECHO} ${MC} " - [system-auth] lcredit ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [system-auth] lcredit ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "ucredit=${UCREDIT}" /etc/pam.d/system-auth)
	[ $? = 0 ] && ${ECHO} ${MC} " - [system-auth] ucredit ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [system-auth] ucredit ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "ocredit=${OCREDIT}" /etc/pam.d/system-auth)
	[ $? = 0 ] && ${ECHO} ${MC} " - [system-auth] ocredit ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [system-auth] ocredit ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
	cmd=$(${EGREP} "remember=${REMEMBER}" /etc/pam.d/system-auth)
	[ $? = 0 ] && ${ECHO} ${MC} " - [system-auth] remember ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [system-auth] remember ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
fi
}

chk_crontab() {
# Restringir o uso do crontab
${ECHO} "Checking (Restringir o uso do crontab) "
[ `stat -c '%a' /etc/crontab` -eq 600 ] && ${ECHO} ${MC} " - /etc/crontab permission ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - /etc/crontab permission ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${GETFACL} -p /etc/crontab | ${GREP} -e "owner: root")
[ $? = 0 ] && ${ECHO} ${MC} " - /etc/crontab owner ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - /etc/crontab owner ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${GREP} root /etc/cron.allow)
[ $? = 0 ] && ${ECHO} ${MC} " - root listed on /etc/cron.allow ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - root listed on /etc/cron.allow ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_timeout() {
# Habilitar timeout para sessoes idle
${ECHO} ${MN} "Checking (Habilitar timeout para sessoes idle)  "
cmd=$(${EGREP} "^export TMOUT" /etc/profile)
[ $? = 0 ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_etcservices() {
# Protegendo o arquivo services no etc
${ECHO} ${MN} "Checking (Protegendo o arquivo services no etc)  "
cmd=$(${LSATTR} /etc/services | grep --color "\-i\-")
[ $? = 0 ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_unservices() {
# Desativando servicos desnecessarios
${ECHO} "Checking (Desativando servicos desnecessarios)  "
for i in $ALLOWSVS; do 
     cmd=$(chkconfig --list| grep ":on" | grep $i)
     [ $? = 0 ] && ${ECHO} ${MC} " - [services] ${i} ${RED}[FAIL]${UNCOLOR} - disable it!" || ${ECHO} ${MC} " - [services] ${i} ${GREEN}[OK]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
done
}

chk_filesystems() {
# Desativando uso de filesystems incomuns
${ECHO} ${MN} "Checking (Desativando uso de filesystems incomuns)  "
[ -e /etc/modprobe.d/secadm.conf ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_passwd() {
## Arquivos de usuario, grupo e senhas
# Protegendo arquivos e diretorios importantes
${ECHO} "Checking (Protegendo arquivos e diretorios importantes)  "
cmd=$(${GETFACL} -p /etc/shadow | ${GREP} -e "owner: root")
[ $? = 0 ] && ${ECHO} ${MC} " - /etc/shadow owner ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - /etc/shadow owner ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${GETFACL} -p /etc/gshadow | ${GREP} -e "owner: root")
[ $? = 0 ] && ${ECHO} ${MC} " - /etc/gshadow owner ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - /etc/gshadow owner ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
[ `stat -c '%a' /etc/shadow` -eq 0 ] && ${ECHO} ${MC} " - /etc/shadow permission ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - /etc/shadow permission ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
[ `stat -c '%a' /etc/gshadow` -eq 0 ] && ${ECHO} ${MC} " - /etc/gshadow permission ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - /etc/gshadow permission ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))

# Bloquear senhas dos usuarios de sistema - BUG
${ECHO} ${MN} "Checking (Bloquear senhas dos usuarios de sistema)  "
cmd=$(${GREP} bash /etc/passwd| ${GREP} -v root | ${GREP} -v "uh-"| ${GREP} -v dcadmin)
[ $? = 0 ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_suids() {
# Remover SUID de arquivos desnecessarios
${ECHO} "Checking (Remover SUID de arquivos desnecessarios)  "
for i in $DENYSIDS; do 
     if [ -f ${i} ]; then
          cmd=$(stat -c '%a' ${i})
          [ ${cmd} -eq 4755 ] && ${ECHO} ${MC} " - ${i} permission ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1)) || ${ECHO} ${MC} " - ${i} permission ${GREEN}[OK]${UNCOLOR}"
     else
          continue
     fi
done
}

chk_su() {
# Limitar uso do comando su
${ECHO} ${MN} "Checking (Limitar uso do comando su)  "
cmd=$(${EGREP} "^auth.*pam_wheel.so.*wheel" /etc/pam.d/su)
[ $? = 0 ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_homeusers() {
# Certifique que diretorios home de usuarios nao sao Group-Writable e World-Readable
${ECHO} "Checking (Certifique que diretorios home de usuarios nao sao Group-Writable e World-Readable)  "
HOMELIST=$(find /home/ -mindepth 1 -maxdepth 1 -type d)
for i in $HOMELIST; do
[ `stat -c '%a' ${i}` -eq 700 ] && ${ECHO} ${MC} " - ${i} permission ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - ${i} permission ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
done
}

chk_netrc() {
# Certifique que usuarios nao tem arquivos .netrc
${ECHO} ${MN} "Checking (Certifique que usuarios nao tem arquivos .netrc)  "
cmd=$(find $HOMEDIR -name ".netrc")
if [ -e $cmd ]; then
     ${ECHO} ""
     for i in $cmd; do
          ${ECHO} ${MC} " - ${i} found ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
     done
else
     ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}"
fi
}

chk_coredumps() {
# Desabilitando core dumps
${ECHO} "Checking (Desabilitando core dumps)  "
cmd=$(${EGREP} "^*.*hard.*core" /etc/security/limits.conf)
[ $? = 0 ] && ${ECHO} ${MC} " - [limits.conf] hard core ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [limits.conf] hard core ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${GREP} "fs.suid_dumpable = 0" /etc/sysctl.conf)
[ $? = 0 ] && ${ECHO} ${MC} " - [sysctl.conf] fs.suid_dumpable ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sysctl.conf] fs.suid_dumpable ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_syslogsrv() {
# Defina um syslog server
${ECHO} ${MN} "Checking (Defina um syslog server)  "
if [ -f ${SYSLOGFILE} ]; then
     cmd=$(${GREP} -e "^*.*" ${SYSLOGFILE} | ${GREP} ":514")
     [ $? = 0 ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
else
     ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"
     ${ECHO} ${MC} "${YELLOW}Syslog configuration file not found, please set SYSLOGFILE setting on LVS Script${UNCOLOR}"; COUNTER=$(($COUNTER+1))
fi
}

chk_syslogd() {
# Restricting access by other users viewer the syslog
${ECHO} "Checking (Restringindo acesso de visualizacao por outros nos logs do sistema)  "
if [ -f ${SYSLOGFILE} ] && [ ${SYSLOGFILE} = "/etc/rsyslog.conf" ]; then
     SYSLOGS=`${GREP} -e '/var/log' ${SYSLOGFILE} | ${GREP} -v "programname"^ | awk -F" " {' print $2 '} | sed 's/^\-//g'`
     for SYSLOG in ${SYSLOGS}; do
          [ `stat -c '%a' ${i}` -eq 600 ] && ${ECHO} ${MC} " - logfile ${i} permission ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - logfile ${i} permission ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
     done
else
     ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
     ${ECHO} ${MC} "${YELLOW}Syslog configuration file not found, please set SYSLOGFILE setting on LVS Script${UNCOLOR}"
fi
}

chk_motd() {
# Tested on CentOS 6.2 x64
# Defina um MOTD para alerta
${ECHO} "Checking (Remover motd/issue padrao)  "

cmd=$(${EGREP} ".*ATENCAO: Aviso Importante" /etc/motd)
[ $? = 0 ] && ${ECHO} ${MC} " - /etc/motd content ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - /etc/motd content ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
#cmd=$(${EGREP} ".*ATENCAO: Aviso Importante" /etc/issue)
#[ $? = 0 ] && ${ECHO} ${MC} " - /etc/issue content ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - /etc/issue content${RED}[FAIL]${UNCOLOR}" ${YELLOW}ignore!${UNCOLOR}; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} ".*ATENCAO: Aviso Importante" /etc/issue.net)
[ $? = 0 ] && ${ECHO} ${MC} " - /etc/issue.net content${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - /etc/issue.net content${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

improve_pass_hash_algorithm() {
${ECHO} ${MN} "Checking (Elevando algoritmo hash de senhas)  "
cmd=$(${EGREP} "PASSWDALGORITHM=sha512" /etc/sysconfig/authconfig)
[ $? = 0 ] && ${ECHO} ${MC} "${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} "${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

ssh_security() {
${ECHO} "Checking (SSH Security Settings)  "
cmd=$(${EGREP} "PermitEmptyPasswords $ALLOW_EMPTY_PASS" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] PermitEmptyPasswords ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] PermitEmptyPasswords ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "PermitRootLogin $ALLOW_ROOT_LOGIN" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] PermitRootLogin ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] PermitRootLogin ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "IgnoreRhosts $IGNORE_RHOSTS" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] IgnoreRhosts ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] IgnoreRhosts ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "RhostsRSAAuthentication $ALLOW_RHOSTS_RSA" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] RhostsRSAAuthentication ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] RhostsRSAAuthentication ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "Protocol 2" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] Protocol ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] Protocol ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "UsePrivilegeSeparation yes" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] UsePrivilegeSeparation ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] UsePrivilegeSeparation ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "StrictModes yes" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] StrictModes ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] StrictModes ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "MaxAuthTries $MAX_AUTH_TRIES" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] MaxAuthTries ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] MaxAuthTries ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "AllowTcpForwarding $ALLOW_TCP_FORWARD" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] AllowTcpForwarding ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] AllowTcpForwarding ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "X11Forwarding $ALLOW_X11_FORWARD" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] X11Forwarding ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] X11Forwarding ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "SyslogFacility AUTHPRIV" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] SyslogFacility ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] SyslogFacility ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "LogLevel INFO" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] LogLevel ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] LogLevel ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "TCPKeepAlive $ALLOW_KEEPALIVE" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] TCPKeepAlive ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] TCPKeepAlive ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "PermitUserEnvironment no" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] PermitUserEnvironment ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] PermitUserEnvironment ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "LoginGraceTime $GRACE_TIME" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] LoginGraceTime ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] LoginGraceTime ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
#cmd=$(${EGREP} "KeyRegenerationInterval 1800" /etc/ssh/sshd_config)
#[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] KeyRegenerationInterval ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] KeyRegenerationInterval ${RED}[FAIL]${UNCOLOR}" ${YELLOW}ignore!${UNCOLOR}; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "UseDNS $USE_DNS" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] UseDNS ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] UseDNS ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
#cmd=$(${EGREP} "ServerKeyBits $SERVERKEY_BITS" /etc/ssh/sshd_config)
#[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] ServerKeyBits ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] ServerKeyBits ${RED}[FAIL]${UNCOLOR}" ${YELLOW}ignore!${UNCOLOR}; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "RSAAuthentication $RSA_AUTH" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] RSAAuthentication ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] RSAAuthentication ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
#cmd=$(${EGREP} "PubkeyAuthentication $PUBKEY_AUTH" /etc/ssh/sshd_config)
#[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] PubkeyAuthentication ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] PubkeyAuthentication ${RED}[FAIL]${UNCOLOR}" ${YELLOW}ignore!${UNCOLOR}; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "ChallengeResponseAuthentication $CHALLENGE_PAM" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] ChallengeResponseAuthentication ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] ChallengeResponseAuthentication ${RED}[FAIL]${UNCOLOR} "; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "KerberosAuthentication $KERBEROS_AUTH" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] KerberosAuthentication ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] KerberosAuthentication ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "GSSAPIAuthentication $GSSAPI_AUTH" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] GSSAPIAuthentication ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] GSSAPIAuthentication ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "PrintLastLog yes" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] PrintLastLog ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] PrintLastLog ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
cmd=$(${EGREP} "UsePAM yes" /etc/ssh/sshd_config)
[ $? = 0 ] && ${ECHO} ${MC} " - [sshd_config] UsePAM ${GREEN}[OK]${UNCOLOR}" || ${ECHO} ${MC} " - [sshd_config] UsePAM ${RED}[FAIL]${UNCOLOR}"; COUNTER=$(($COUNTER+1))
}

chk_final() {
if [ ${COUNTER} -gt 0 ]; then
     ${ECHO} ${MC} ""
     ${ECHO} ${MC} "#################################################"
     ${ECHO} ${MC} "#  Checklist ${RED}[FAIL]${UNCOLOR} ${YELLOW} - ${COUNTER} items are missing${UNCOLOR}     #"
     ${ECHO} ${MC} "#################################################"
     ${ECHO} ${MC} ""
else
     ${ECHO} ${MC} ""
     ${ECHO} ${MC} "#########################################"
     ${ECHO} ${MC} "#  Congratulations! Checklist ${GREEN}[OK]${UNCOLOR}!     #"
     ${ECHO} ${MC} "#########################################"
     ${ECHO} ${MC} ""
fi
}


# ---------------------------------------
# Init
# ---------------------------------------

chk_rootuser
check_release
banner
#chk_bootloader
chk_remoteroot
chk_systemlogs_perm
chk_logrotate
chk_umask
chk_authpasswd
chk_crontab
chk_timeout
#chk_etcservices
chk_unservices
#chk_filesystems
chk_passwd
chk_suids
chk_su
chk_homeusers
chk_netrc
chk_coredumps
chk_syslogsrv
#chk_syslogd
chk_motd
ssh_security
improve_pass_hash_algorithm
chk_final
#rm -f $0
