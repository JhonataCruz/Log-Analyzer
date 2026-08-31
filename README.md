# Log Analyzer

Esse projeto nasceu daquela vontade de parar de ficar olhando log linha por linha e tentar transformar pelo menos uma parte desse trabalho em algo automático.

A ideia é simples: jogar um log do SSH, Apache ou Nginx no programa e receber um resumo dos IPs que parecem estar fazendo coisa errada.

Por enquanto as regras são bem diretas, mas já dão uma boa base para estudar análise de logs, regex e detecção de comportamento suspeito.

## O que ele detecta

### SSH

- várias falhas de login do mesmo IP;
- tentativa de acesso com usuários inválidos;
- quantidade de falhas e logins aceitos por IP.

### Apache / Nginx

- tentativas simples de SQL Injection, como `' OR 1=1`;
- padrões de `UNION SELECT`;
- XSS com `<script>`;
- path traversal com `../`;
- alguns padrões básicos de command injection.

No final ele mostra os alertas e monta um ranking dos IPs que mais apareceram em atividades suspeitas.

## Estrutura

```text
log-analyzer-portfolio/
├── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
├── src/
│   └── log_analyzer.py
├── samples/
│   ├── auth.log
│   └── access.log
├── reports/
└── tests/
    └── test_log_analyzer.py
```

## Rodando

Não tem dependência externa. Python 3.10+ já resolve.

```bash
python3 src/log_analyzer.py samples/auth.log --type ssh
```

Para mudar o limite de alerta:

```bash
python3 src/log_analyzer.py samples/auth.log --type ssh --threshold 3
```

Para testar um log web:

```bash
python3 src/log_analyzer.py samples/access.log --type web
```

Gerando os dois relatórios:

```bash
python3 src/log_analyzer.py samples/access.log --type web \
  --txt reports/relatorio.txt \
  --html reports/relatorio.html
```

Também dá para deixar o programa descobrir o tipo sozinho:

```bash
python3 src/log_analyzer.py samples/access.log --type auto
```

## Usando com logs reais

No Linux, por exemplo:

```bash
sudo python3 src/log_analyzer.py /var/log/auth.log --type ssh
```

Para Apache ou Nginx, passe o arquivo de access log correspondente.

O projeto não altera o log original. Ele só lê o arquivo e gera a análise.

## Testes

```bash
python3 -m unittest discover -s tests -v
```

## Limitações atuais

Isso aqui não pretende substituir ferramentas como Fail2ban, Wazuh ou um SIEM. As regras são intencionalmente simples e podem gerar falso positivo.

A detecção de brute force usa uma janela por quantidade de linhas, não por tempo real. Para um projeto maior, faria sentido trabalhar com timestamps de verdade, adicionar whitelist, score de risco e talvez acompanhar o arquivo em modo `tail -f`.

## Ideias para continuar

- suporte melhor a IPv6 e mais formatos de log;
- exportação JSON;
- dashboard simples;
- score por IP juntando vários tipos de alerta;
- modo de monitoramento contínuo;
- integração com Fail2ban ou alguma API;
- testes com logs maiores e mais variados.

## Licença

MIT. Veja `LICENSE`.
