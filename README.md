# Blind-SQL | Error-Based & Time-Based | PortSwigger Lab's
> ⚠️ For Educational and Ethical Use Only

Ferramenta desenvolvida em Python para identificação e exploração de Blind SQL Injection utilizando técnicas Error-Based e Time-Based.
O objetivo da ferramenta é automatizar testes em alguns laboratórios da PortSwigger, auxiliando estudantes de segurança ofensiva a entender como ataques de Blind SQL Injection funcionam na prática.

| Aviso Importante

Esta ferramenta foi criada exclusivamente para fins educacionais e éticos.
Destinada apenas para uso em ambientes de laboratório, especificamente em alguns labs da PortSwigger Web Security Academy.
Não utilize esta ferramenta em sistemas reais sem autorização explícita.
O uso indevido contra sistemas sem permissão pode ser ilegal.
O autor não se responsabiliza por qualquer uso indevido desta ferramenta.

---

## 🎯 Objetivo

Esta ferramenta foi criada para ajudar no aprendizado de:

- Blind SQL Injection
- Identificação de banco de dados

Técnicas de:

- Error-Based SQL Injection
- Time-Based SQL Injection

Além de demonstrar a automação da extração de dados em ambientes de laboratório.

---

## 🛠️ Tecnologias Utilizadas

Python 3

Bibliotecas:

- requests
- argparse

---

## ⚙️ Funcionamento

A ferramenta executa as seguintes etapas:

### 1️⃣ Identificação da vulnerabilidade

Primeiro é realizado um teste para verificar se o alvo é vulnerável utilizando:

- Error-Based SQL Injection
- Time-Based SQL Injection

### 2️⃣ Identificação do banco de dados

A ferramenta testa payloads específicos para identificar qual banco de dados está sendo utilizado:

- Oracle
- PostgreSQL
- MySQL
- Microsoft SQL Server

### 3️⃣ Extração de dados

Após identificar:

- Tipo de banco de dados
- Tipo de vulnerabilidade

A ferramenta tenta extrair informações da base de dados (senha do administrator) utilizando técnicas de Blind SQL Injection, realizando consultas caractere por caractere.

---

## 📦 Instalação

Clone o repositório:

```bash
git clone https://github.com/acid-toxic/blindsqli-tool
```

Entre no diretório:

```bash
cd blindsqli-tool
```

Instale as dependências:

```bash
pip install requests
```

---

## 🚀 Uso

```bash
python tool.py -u <URL> -c <COOKIE_VULNERAVEL> -s <SESSION_TOKEN>
```

---

## 📌 Parâmetros

| Parâmetro | Descrição |
|-----------|-----------|
| -u | URL do lab |
| -c | Valor do cookie vulnerável |
| -s | Token de sessão (opcional) |

---

## 🧪 Ambientes Compatíveis

Esta ferramenta foi desenvolvida especificamente para alguns laboratórios da PortSwigger Web Security Academy, principalmente aqueles que envolvem:

- Blind SQL Injection via cookies
- Estruturas de banco semelhantes às usadas nos labs
- Cenários de treinamento controlados

Ela não foi projetada para aplicações reais e pode não funcionar fora desses ambientes.

---
