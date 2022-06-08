#!/bin/bash
##############################################################################
# v0.1                                                                       #
# ============================================                               #
#                                                                            #
# Copyright (c) 2022 by Bruno Rodrigues - brunofranrodrigues@gmail.com       #
# Last Updated 08/06/2022                                                    #
#                                                                            #
# This program is free software. You can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation; either version 2 of the License.             #
##############################################################################

# ---------------------------------------
# Environment variables
# ---------------------------------------


MN="-n"
MC="-e"
CHOWN=`which chown`
CAT=`which cat`
CHMOD=`which chmod`
USERMOD=`which usermod`
USERADD=`which useradd`
GROUPADD=`which groupadd`
SUDO=`which sudo`
AWK=`which awk`
ECHO=`which echo`
FIND=`which find`
GREP=`which grep`
CUT=`which cut`
TOUCH=`which touch`
SED=`which sed`
TAIL=`which tail`
HEAD=`which head`
YUM=`which yum`
SYSTEMCTL=`which systemctl`
WGET=`which wget`
CD=`which cd`
TAR=`which tar`
CP=`which cp`


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

# Acessa o diretorio de instalacao
DIR="/export"

export PATH="${PATH:+$PATH:}/sbin:/usr/sbin:/bin:/usr/bin"

add_group_splunk() {
${ECHO} ${MC} "${GREEN} Validando o grupo splunk ${UNCOLOR}"
if ${CAT} /etc/group | ${GREP} splunk > /dev/null
then
	${ECHO} ${MC} "${GREEN} O grupo splunk ja existe ${UNCOLOR}"
else
	${GROUPADD} splunk
	${ECHO} ${MC} "${GREEN} O grupo splunk foi criado ${UNCOLOR}"
fi
}

add_group_wheel() {
${ECHO} ${MC} "${GREEN} Validando o grupo wheel ${UNCOLOR}"
if ${CAT} /etc/group | ${GREP} wheel > /dev/null
then
	${ECHO} ${MC} "${GREEN} O grupo wheel ja existe ${UNCOLOR}"
	${USERMOD} -a -G wheel splunk
else
	groupadd wheel
	${ECHO} ${MC} "${GREEN} O grupo wheel foi criado ${UNCOLOR}"
	${USERMOD} -a -G wheel splunk
fi
}

if [ -d "$DIR" ]; then
  ${ECHO} ${MC} "${GREEN} Installing Splunk in ${DIR}...${UNCOLOR}"
  # Acessa o diretorio de instalacao /export/splunk
  ${CD} ${DIR}
  ${WGET} -O splunk-8.2.6-a6fe1ee8894b-Linux-x86_64.tgz "https://download.splunk.com/products/splunk/releases/8.2.6/linux/splunk-8.2.6-a6fe1ee8894b-Linux-x86_64.tgz"
  MD5CHECK=`md5sum splunk-8.2.6-a6fe1ee8894b-Linux-x86_64.tgz | awk {'print $1}'`
  if [ "14f8aa5b2a5cd554975cb9410eda0879" = "$MD5CHECK" ]
	then
		${ECHO} ${MC} "${GREEN} MD5 esta correto ${UNCOLOR}"
	else
		${ECHO} ${MC} "${GREEN} Erro: MD5 nao confere ${UNCOLOR}"
		exit 1
  fi
  ${TAR} -xzvf splunk-8.2.6-a6fe1ee8894b-Linux-x86_64.tgz -C ${DIR}
  add_group_splunk
  ${USERADD} -d /export/splunk/ -m -g splunk splunk
  add_group_wheel
  ${CP} /etc/skel/.bash* /export/splunk
  ${CHOWN} -R splunk.splunk /export/splunk/
  ${SUDO} firewall-cmd --zone=public --permanent --add-port=8000/tcp
  ${SUDO} firewall-cmd --zone=public --permanent --add-port=5514/udp
  ${SUDO} firewall-cmd --zone=public --permanent --add-port=9997/tcp
  ${SUDO} firewall-cmd --zone=public --permanent --add-port=8089/tcp
  ${SUDO} firewall-cmd --zone=public --permanent --add-port=8080/tcp
  ${SUDO} firewall-cmd --reload
else
  ${ECHO} ${MC} "${GREEN} Error: ${DIR} not found. Can not continue. ${UNCOLOR}"
  exit 1
fi
