#!/bin/bash
##############################################################################
# v0.1                                                                       #
# ============================================                               #
#                                                                            #
# Copyright (c) 2020 by Bruno Rodrigues - brunofranrodrigues@gmail.com       #
# Last Updated 18/07/2020                                                    #
#                                                                            #
# This program is free software. You can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation; either version 2 of the License.             #
##############################################################################

INPUTVALUE="";
IP="localhost";

df_Info () {
	clear;
	df -h | egrep -v "/dev/shm|/boot" | grep "Filesystem" |awk '{if ($0) print "\t" $0}'
	echo "	======================================================"
	df -h | egrep -v "/dev/shm|/boot|Mounted" | awk '{if ($0) print "\t" $0}'
	echo ""
	}

main_loopy () {

	df_Info;
		echo ""
		echo " Recovery System"
		echo ""
		echo ""
		echo " Escolha as opcoes abaixo:"
		echo ""
		echo -e " Digite \"\\033[31;1m1\\033[0;39m\" para instalar os requisitos do app."
		echo -e " Digite \"\\033[31;1m2\\033[0;39m\" para criar o bucket."
		echo -e " Digite \"\\033[31;1m3\\033[0;39m\" para efetuar o deploy do app."
		echo -e " Digite \"\\033[31;1m4\\033[0;39m\" para recovery completo de modo expresso."
	

		echo ""
		echo -e " Digite \"\\033[31;1m5\\033[0;39m\" Para sair."

		printf "\n (Case Sensitive) \\033[31;1m-->\\033[0;39m ";
		read INPUTVALUE;
	}

	menuloopflag=0;
	while [ $menuloopflag -ne 1 ]; do

		if [ "$INPUTVALUE" = "1" ]; then
        ############################### Reconstrucao do servidor ###############################
		apt-get update

		#Instalação dos pacotes necessario para rodar o  app
		apt install -y python3 python3-pip unzip gunicorn s3fs ruby2.5 ruby2.5-dev

		#Instalação do framework e dos modulos
		sudo pip3 install pipenv
		sudo pip3 install boto3
		sudo pip3 install flask
		sudo pip3 install pytest

		sudo pipenv --python 3 install --system --deploy
		
		gem install travis --no-document
		
		# cria o usuario que tera acesso ao repo e a integracao
		
		if id travis >/dev/null 2>&1; then
			echo "user exists"
			echo 'travis:Vx@A2nSf34' | chpasswd
		else
			echo "user does not exist"
			useradd -m -s /bin/bash travis
			echo 'travis:Vx@A2nSf34' | chpasswd
			echo 'travis  ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers
			mkdir /home/travis/.ssh
			chmod 700 /home/travis/.ssh
			chown travis.travis /home/travis/.ssh
			touch /home/travis/.ssh/authorized_keys
			chmod 600 /home/travis/.ssh/authorized_keys
		fi

		#Ajusta a permissao da pasta /opt
		chown travis:travis -R /opt
		
		############################### Reconstrucao do servidor ###############################
                fi

		if [ "$INPUTVALUE" = "2" ]; then
		############################### BUCKET ###############################
		#Instalação do minio para funcionar como bucket
		wget https://dl.minio.io/server/minio/release/linux-amd64/minio -O /usr/local/bin/minio

        wget https://dl.min.io/client/mc/release/linux-amd64/mc -O /usr/local/bin/mc

        sudo useradd -r minio-user -s /sbin/nologin

        sudo chown minio-user:minio-user /usr/local/bin/minio

        sudo chown minio-user:minio-user /usr/local/bin/mc

        chmod +x /usr/local/bin/minio

        chmod +x /usr/local/bin/mc

        mkdir /mnt/data

		sudo chown minio-user:minio-user /mnt/data

		sudo mkdir /usr/local/share/minio

		sudo chown minio-user:minio-user /usr/local/share/minio

		sudo mkdir /etc/minio

		sudo chown minio-user:minio-user /etc/minio
		
echo "
MINIO_ACCESS_KEY="minio"
MINIO_VOLUMES="/mnt/data"
MINIO_OPTS="-C /etc/minio --address $IP:9000"
MINIO_SECRET_KEY="miniostorage"" > /etc/default/minio

		#Variaveis de ambiente
		MINIO_ACCESS_KEY="minio"
		MINIO_VOLUMES="/mnt/data"
		MINIO_OPTS="-C /etc/minio --address $IP:9000"
		MINIO_SECRET_KEY="miniostorage"
		
		export $MINIO_ACCESS_KEY
		export $MINIO_VOLUMES
		export $MINIO_OPTS
		export $MINIO_SECRET_KEY 

		curl -O https://raw.githubusercontent.com/minio/minio-service/master/linux-systemd/minio.service

		sudo chown minio-user:minio-user minio.service

		sudo mv minio.service /etc/systemd/system

		sudo systemctl daemon-reload

		sudo systemctl enable minio

		sudo systemctl start minio
		
		/usr/local/bin/mc config host add minio http://$IP:9000 minio miniostorage --api S3v4
		
		/usr/local/bin/mc mb minio/teste
		
		/usr/local/bin/mc policy set public minio/teste

		############################### BUCKET ###############################
		
			fi

		if [ "$INPUTVALUE" = "3" ]; then
        ############################### APP ###############################
		#Diretorio onde vai rodar o app
		cd /opt
		
		if [ ! -d "/opt/instruct-selecao-flask" ]; then
			#Clone do github
			git clone https://github.com/brunofranrodrigues/instruct-selecao-flask.git
			chown travis.travis -R /opt/instruct-selecao-flask/

		fi

		cd /opt/instruct-selecao-flask/

                sudo pipenv --python 3 install --system --deploy


		#Variaveis de ambiente
		S3_URL="http://$IP:9000/minio/teste/"
		S3_ACCESS_KEY="minio"
		S3_SECRET_KEY="miniostorage"

		export S3_URL;
		export S3_ACCESS_KEY;
		export S3_SECRET_KEY;

		cd /opt/instruct-selecao-flask
		
		
		SERVICE="gunicorn"
		if pgrep -x "$SERVICE" >/dev/null
		then
			echo "$SERVICE rodando"
			sleep 5;
		else
			echo "$SERVICE parado"
			echo "Iniciando o servico"
			sleep 5;
			gunicorn --bind 0.0.0.0:5000 wsgi:app &
		fi
		
		############################### APP ###############################
                fi
		
		if [ "$INPUTVALUE" = "4" ]; then
        ############################### expresso ###############################
		
		apt-get update

		#Instalação dos pacotes necessario para rodar o  app
		apt install -y python3 python3-pip unzip gunicorn s3fs ruby2.5 ruby2.5-dev
		#Instalação do framework e dos modulos
		sudo pip3 install pipenv
		sudo pip3 install boto3
		sudo pip3 install flask
		sudo pip3 install pytest

		sudo pipenv --python 3 install --system --deploy
		
		gem install travis --no-document
		
		# cria o usuario que tera acesso ao repo e a integracao
		
		if id travis >/dev/null 2>&1; then
			echo "user exists"
			echo 'travis:Vx@A2nSf34' | chpasswd
		else
			echo "user does not exist"
			useradd -m -s /bin/bash travis
			echo 'travis:Vx@A2nSf34' | chpasswd
			echo 'travis  ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers
			mkdir /home/travis/.ssh
			chmod 700 /home/travis/.ssh
			chown travis.travis /home/travis/.ssh
			touch /home/travis/.ssh/authorized_keys
			chmod 600 /home/travis/.ssh/authorized_keys
		fi

		#Ajusta a permissao da pasta /opt
		chown travis.travis -R /opt
		
		#Instalação do minio para funcionar como bucket
		wget https://dl.minio.io/server/minio/release/linux-amd64/minio -O /usr/local/bin/minio

        wget https://dl.min.io/client/mc/release/linux-amd64/mc -O /usr/local/bin/mc

        sudo useradd -r minio-user -s /sbin/nologin

        sudo chown minio-user:minio-user /usr/local/bin/minio

        sudo chown minio-user:minio-user /usr/local/bin/mc

        chmod +x /usr/local/bin/minio

        chmod +x /usr/local/bin/mc

        mkdir /mnt/data

		sudo chown minio-user:minio-user /mnt/data

		sudo mkdir /usr/local/share/minio

		sudo chown minio-user:minio-user /usr/local/share/minio

		sudo mkdir /etc/minio

		sudo chown minio-user:minio-user /etc/minio
		
echo "
MINIO_ACCESS_KEY="minio"
MINIO_VOLUMES="/mnt/data"
MINIO_OPTS="-C /etc/minio --address $IP:9000"
MINIO_SECRET_KEY="miniostorage"" > /etc/default/minio

		#Variaveis de ambiente
		MINIO_ACCESS_KEY="minio"
		MINIO_VOLUMES="/mnt/data"
		MINIO_OPTS="-C /etc/minio --address $IP:9000"
		MINIO_SECRET_KEY="miniostorage"
		
		export $MINIO_ACCESS_KEY
		export $MINIO_VOLUMES
		export $MINIO_OPTS
		export $MINIO_SECRET_KEY 

		curl -O https://raw.githubusercontent.com/minio/minio-service/master/linux-systemd/minio.service

		sudo chown minio-user:minio-user minio.service

		sudo mv minio.service /etc/systemd/system

		sudo systemctl daemon-reload

		sudo systemctl enable minio

		sudo systemctl start minio
		
		/usr/local/bin/mc config host add minio http://$IP:9000 minio miniostorage --api S3v4
		
		/usr/local/bin/mc mb minio/teste
		
		/usr/local/bin/mc policy set public minio/teste
		
		#Diretorio onde vai rodar o app
		cd /opt
		
		if [ ! -d "/opt/instruct-selecao-flask" ]; then
			#Clone do github
			git clone https://github.com/brunofranrodrigues/instruct-selecao-flask.git
			chown travis.travis -R /opt/instruct-selecao-flask/

		fi
		
		cd /opt/instruct-selecao-flask/

		sudo pipenv --python 3 install --system --deploy

		#Variaveis de ambiente
		S3_URL="http://$IP:9000/minio/teste/"
		S3_ACCESS_KEY="minio"
		S3_SECRET_KEY="miniostorage"

		export S3_URL;
		export S3_ACCESS_KEY;
		export S3_SECRET_KEY;

		cd /opt/instruct-selecao-flask
		
		
		SERVICE="gunicorn"
		if pgrep -x "$SERVICE" >/dev/null
		then
			echo "$SERVICE rodando"
			sleep 5;
		else
			echo "$SERVICE parado"
			echo "Iniciando o servico"
			sleep 5;
			gunicorn --bind 0.0.0.0:5000 wsgi:app &

		fi
		
		clear;
		exit 0;
		
		############################### expresso ###############################
				fi
		
		if [ "$INPUTVALUE" = "5" ]; then
			echo "5";
            menuloopflag=1;
			INPUTVALUE="";
            break;
                fi

main_loopy;
done;
exit 0;
