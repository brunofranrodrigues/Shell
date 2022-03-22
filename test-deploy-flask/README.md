# Início do ambiente de teste
Neste repositório está hospedado todos os arquivos utilizados para simular o ambiente de CI utilizando a plataforma Travis-CI.

## Sobre o processo de desenvolvimento
Os scripts de deploy e de recovery foram montados a partir de exemplos encontrados na documentação do próprio Travis-CI.

A linguagem utilizada foi o shell-script pois possuo mais habilidade/experiência com ela.


Faça o upload dos scripts para o servidor.

### Segurança:
Foi criado um usuario no SO específico para a plataforma Travis-ci.

Segui a referência da documentação.
https://docs.travis-ci.com/user/private-dependencies/

A chave SSH utilizada foi encriptada e adicionada no repositório do github.

**Ps:**
Em ambos os scripts têm uma variável chamada “IP”.
Esta variável deve ser o IP da máquina que ira ser utilizada como teste.
Caso o ambiente esteja hospedado na AWS deixe a variável como localhost.

### Versão do SO
Description:    Ubuntu 18.04.4 LTS.


### Script de recovery do SO
O script foi criado com Shell Script.

Basicamente, funciona via menu ou de forma expressa.

Basta dar permissão de execução
```bash
chmod 755 recovery_system.sh
```

E chamar conforme o exemplo abaixo:
```bash
./recovery_system.sh
```
Se quiser apenas seguir com o recovery escolha a opção número 4.

### Exemplo:
O teste foi feito com o usuário root executando o recovery.

Recovery System

```bash
 Escolha as opcoes abaixo:

 Digite "1" para instalar os requisitos do app.
 Digite "2" para criar o bucket.
 Digite "3" para efetuar o deploy do app.
 Digite "4" para recovery completo de modo expresso.

 Digite "5" Para sair.

 (Case Sensitive) -->
```

### Script de deploy.
Basta dar permissão de execução

```bash
chmod 755 deploy.sh
```

E copiar para um diretório que esteja no path.
```bash
cp deploy.sh /usr/local/bin
```

Ele precisa estar acessível para o usuário travis.
