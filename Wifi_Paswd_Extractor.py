import re
import subprocess

print("[+] Wait, Start Capturing Profiles...\n")

show_profiles = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True).stdout.decode()

profile_names = (re.findall("All User Profile     : (.*)\r", show_profiles))

wifi_list = []
try:
    if len(profile_names) != 0:
        for name in profile_names:
            wifi_profiles = {}

            profile_detail = subprocess.run(["netsh", "wlan", "show", "profile", name], capture_output=True).stdout.decode()

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

    print("[+] Found Profiles Successfully\n")

    for num in range(len(wifi_list)):
        print('[+] Wifi Name: "', wifi_list[num]['SSID'], '"')
        print("\tPassword: ", wifi_list[num]['Password'], '\n')
        print('===============================\n')


except :
    print("[-] A profile is corrupted.")
