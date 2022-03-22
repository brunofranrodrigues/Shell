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

eval "$(ssh-agent -s)" # Start ssh-agent cache
chmod 600 /home/travis/.travis/travis_rsa # Allow read access to the private key
ssh-add /home/travis/.travis/travis_rsa # Add the private key to SSH

IP="localhost";

pid=`pgrep -x gunicorn | tail -1`
SERVICE="gunicorn";

	if pgrep -x "$SERVICE" >/dev/null
	then
		echo "$SERVICE rodando"
		sudo kill -9 $pid
	    sudo rm -rf /opt/instruct-selecao-flask
		cd /opt
		git clone https://github.com/brunofranrodrigues/instruct-selecao-flask.git
		chown travis.travis -R /opt/instruct-selecao-flask/
		cd /opt/instruct-selecao-flask
		
		#Variaveis de ambiente
		S3_URL="http://$IP:9000/minio/teste/"
		S3_ACCESS_KEY="minio"
		S3_SECRET_KEY="miniostorage"

		export S3_URL;
		export S3_ACCESS_KEY;
		export S3_SECRET_KEY;

		gunicorn --bind 0.0.0.0:5000 wsgi:app &
		sleep 5;
	else
		echo "$SERVICE parado"
		sudo rm -rf /opt/instruct-selecao-flask
        cd /opt
        git clone https://github.com/brunofranrodrigues/instruct-selecao-flask.git
		chown travis.travis -R /opt/instruct-selecao-flask/
		cd /opt/instruct-selecao-flask
		
		#Variaveis de ambiente
        S3_URL="http://$IP:9000/minio/teste/"
        S3_ACCESS_KEY="minio"
        S3_SECRET_KEY="miniostorage"

        export S3_URL;
        export S3_ACCESS_KEY;
        export S3_SECRET_KEY;

		echo "Iniciando o servico"

		gunicorn --bind 0.0.0.0:5000 wsgi:app &
		sleep 5;
	fi
