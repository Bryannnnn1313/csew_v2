import sys
import traceback
import win32com.client
import os
import re
import time
import datetime
from inspect import getfullargspec
from wmi import WMI
from tkinter import messagebox
import balloontip
import admin_test
import db_handler


# Scoring Report creation
def draw_head():
    f = open(scoreIndex, 'w+')
    f.write('<!doctype html><html><head><title>CSEW Score Report</title><meta http-equiv="refresh" content="60"></head><body style="background-color:powderblue;">''\n')
    f.write('<table align="center" cellpadding="10"><tr><td><img src="C:/CyberPatriot/CCC_logo.png"></td><td><div align="center"><H2>Cyberpatriot Scoring Engine:Windows v1.0</H2></div></td><td><img src="C:/CyberPatriot/SoCalCCCC.png"></td></tr></table>If you see this wait a few seconds then refresh<br><H2>Your Score: #TotalScore#/' + str(menuSettings["Tally Points"]) + '</H2><H2>Vulnerabilities: #TotalVuln#/' + str(menuSettings["Tally Vulnerabilities"]) + '</H2><hr>')
    f.close()


def record_hit(name, points, message):
    global total_points, total_vulnerabilities
    write_to_html(('<p style="color:green">' + name + ' (' + str(points) + ' points)</p>'))
    total_points += int(points)
    total_vulnerabilities += 1


def record_miss(name, points):
    if not menuSettings['Silent Mode']:
        write_to_html(('<p style="color:red">MISS ' + name + ' Issue</p>'))


def record_penalty(name, points, message):
    global total_points
    write_to_html(('<p style="color:red">' + name + ' (' + str(points) + ' points)</p>'))
    total_points -= int(points)


def draw_tail():
    write_to_html('<hr><div align="center"><b>Coastline Collage</b><br>Created by Shaun Martin, Anthony Nguyen, and Minh-Khoi Do</br><br>Feedback welcome: <a href="mailto:smartin94@student.cccd.edu?Subject=CSEW Scoring Engine" target="_top">smartin94@student.cccd.edu</a></div>')
    print(str(total_points) + ' / ' + str(menuSettings["Tally Points"]) + '\n' + str(total_vulnerabilities) + ' / ' + str(menuSettings["Tally Vulnerabilities"]))
    replace_section(scoreIndex, '#TotalScore#', str(total_points))
    replace_section(scoreIndex, '#TotalVuln#', str(total_vulnerabilities))
    replace_section(scoreIndex, 'If you see this wait a few seconds then refresh', '')

    path = os.path.join(Desktop, 'ScoreReport.lnk')
    target = scoreIndex
    icon = os.path.join(index, 'scoring_engine_logo_windows_icon_5TN_icon.ico')
    shell = win32com.client.Dispatch("WScript.Shell")
    shortcut = shell.CreateShortCut(path)
    shortcut.Targetpath = target
    shortcut.IconLocation = icon
    shortcut.WindowStyle = 7  # 7 - Minimized, 3 - Maximized, 1 - Normal
    shortcut.save()


# Extra Functions
def check_runas():
    if not admin_test.isUserAdmin():
        messagebox.showerror('Administrator Access Needed', 'Please make sure the scoring engine is running as admin.')
        exit(admin_test.runAsAdmin())


def check_score():
    global total_points, total_vulnerabilities
    menuSettings["Current Vulnerabilities"] = total_vulnerabilities
    if total_points > menuSettings["Current Points"]:
        menuSettings["Current Points"] = total_points
        Settings.update_score(menuSettings)
        w.ShowWindow('Score Update', 'You gained points!!')
    elif total_points < menuSettings["Current Points"]:
        menuSettings["Current Points"] = total_points
        Settings.update_score(menuSettings)
        w.ShowWindow('Score Update', 'You lost points!!')
    if total_points == menuSettings["Tally Points"] and total_vulnerabilities == menuSettings["Tally Vulnerabilities"]:
        w.ShowWindow('Image Completed', 'Congratulations you finished the image.')


def write_to_html(message):
    f = open(scoreIndex, 'a')
    f.write(message)
    f.close()


def replace_section(loc, search, replace):
    lines = []
    with open(loc) as file:
        for line in file:
            line = line.replace(search, replace)
            lines.append(line)
    with open(loc, 'w') as file:
        for line in lines:
            file.write(line)


# Option Check
def forensic_question(vulnerability):
    for idx, vuln in enumerate(vulnerability):
        if vuln != 1:
            f = open(vulnerability[vuln]["Location"], 'r')
            content = f.read().splitlines()
            for c in content:
                if 'ANSWER:' in c:
                    if vulnerability[vuln]["Answers"] in c:
                        record_hit('Forensic question number ' + str(idx) + ' has been answered.', vulnerability[vuln]['Points'], '')
                    else:
                        record_miss('Forensic Question', vulnerability[vuln]['Points'])


def disable_guest(vulnerability):
    guest_name = (re.search(r"(?<=NewGuestName \= \")\w+", policy_settings_content).group(0) if re.search(r"(?<=NewGuestName \= \")\w+", policy_settings_content) else "Guest")
    guest = wmi.Win32_UserAccount(Name=guest_name)[0]
    if guest.Disabled:
        record_hit('The guest account haas been disabled.', vulnerability[1]['Points'], '')
    else:
        record_miss('User Management', vulnerability[1]['Points'])


def disable_admin(vulnerability):
    admin_name = (re.search(r"(?<=NewAdministratorName \= \")\w+", policy_settings_content).group(0) if re.search(r"(?<=NewAdministratorName \= \")\w+", policy_settings_content) else "Administrator")
    admin = wmi.Win32_UserAccount(Name=admin_name)[0]
    if admin.Disabled:
        record_hit('The default administrator account has been disabled.', vulnerability[1]['Points'], '')
    else:
        record_miss('User Management', vulnerability[1]['Points'])


def critical_users(vulnerability):
    users = wmi.Win32_UserAccount()
    user_list = []
    for user in users:
        user_list.append(user.Name)
    for vuln in vulnerability:
        if vuln != 1:
            if vulnerability[1]['User Name'] not in user_list:
                record_penalty(vulnerability[vuln]['User Name'] + ' was removed.', vulnerability[vuln]['Points'], '')


def users_manipulation(vulnerability, name):
    users = wmi.Win32_UserAccount()
    user_list = []
    for user in users:
        user_list.append(user.Name)
    if name == "Add User":
        for vuln in vulnerability:
            if vuln != 1:
                if vulnerability[vuln]['User Name'] in user_list:
                    record_hit(vulnerability[vuln]['User Name'] + ' has been added.', vulnerability[vuln]['Points'], '')
                else:
                    record_miss('User Management', vulnerability[vuln]['Points'])
    if name == "Remove User":
        for vuln in vulnerability:
            if vuln != 1:
                if vulnerability[vuln]['User Name'] not in user_list:
                    record_hit(vulnerability[vuln]['User Name'] + ' has been removed.', vulnerability[vuln]['Points'], '')
                else:
                    record_miss('User Management', vulnerability[vuln]['Points'])


def turn_on_firewall(vulnerability, name):
    file = open('firewall_status.txt')
    content = file.read()
    file.close()
    if name == "Turn On Domain Firewall":
        firewall = re.search(r"Domain Profile Settings: \n-+\n\w+\s+\w+\n\n", content).group(0)
        if re.search("ON", firewall):
            record_hit('Firewall has been turned on.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])
    if name == "Turn On Private Firewall":
        firewall = re.search(r"Private Profile Settings: \n-+\n\w+\s+\w+\n\n", content).group(0)
        if re.search("ON", firewall):
            record_hit('Firewall has been turned on.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])
    if name == "Turn On Public Firewall":
        firewall = re.search(r"Public Profile Settings: \n-+\n\w+\s+\w+\n", content).group(0)
        if re.search("ON", firewall):
            record_hit('Firewall has been turned on.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])


def local_group_policy(vulnerability, name):
    if name == "Minimum Password Age":
        if 30 <= (int(re.search(r"(?<=MinimumPasswordAge \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=MinimumPasswordAge \= )\d+", policy_settings_content) else 0) <= 60:
            record_hit('Minimum password age is set to 30-60.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])
    if name == "Maximum Password Age":
        if 60 <= (int(re.search(r"(?<=MaximumPasswordAge \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=MaximumPasswordAge \= )\d+", policy_settings_content) else 0) <= 90:
            record_hit('Maximum password age is set to 60-90.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])
    if name == "Maximum Login Tries":
        if 5 <= (int(re.search(r"(?<=LockoutBadCount \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=LockoutBadCount \= )\d+", policy_settings_content) else 0) <= 10:
            record_hit('Maximum login tries is set to 5-10.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management1', vulnerability[1]['Points'])
    if name == "Lockout Duration":
        if 30 <= (int(re.search(r"(?<=LockoutDuration \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=LockoutDuration \= )\d+", policy_settings_content) else 0):
            record_hit('Lockout duration set is set to 30.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management2', vulnerability[1]['Points'])
    if name == "Lockout Reset Duration":
        if 30 <= (int(re.search(r"(?<=ResetLockoutCount \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=ResetLockoutCount \= )\d+", policy_settings_content) else 0):
            record_hit('Lockout counter reset is set to 30.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])
    if name == "Minimum Password Length":
        if 10 <= (int(re.search(r"(?<=MinimumPasswordLength \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=MinimumPasswordLength \= )\d+", policy_settings_content) else 0):
            record_hit('Minimum password length is set to 10 or more.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])
    if name == "Password History":
        if 5 <= (int(re.search(r"(?<=PasswordHistorySize \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=PasswordHistorySize \= )\d+", policy_settings_content) else 0):
            record_hit('Password history size is set to 5 or more.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])
    if name == "Password Complexity":
        if (int(re.search(r"(?<=PasswordComplexity \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=PasswordComplexity \= )\d+", policy_settings_content) else 0) == 1:
            record_hit('Password complexity has been enabled.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])
    if name == "Reversible Password Encryption":
        if (int(re.search(r"(?<=ClearTextPassword \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=ClearTextPassword \= )\d+", policy_settings_content) else 1) == 0:
            record_hit('Reversible password encryption has been Disabled.', vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[1]['Points'])
    if name == "Audit Account Login":
        if (int(re.search(r"(?<=AuditAccountLogon \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=AuditAccountLogon \= )\d+", policy_settings_content) else 0) == 3:
            record_hit('Audit Account Login set to Success and Failure.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Audit Account Management":
        if (int(re.search(r"(?<=AuditAccountManage \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=AuditAccountManage \= )\d+", policy_settings_content) else 0) == 3:
            record_hit('Audit Account Manage set to Success and Failure.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Audit Directory Settings Access":
        if (int(re.search(r"(?<=AuditDSAccess \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=AuditDSAccess \= )\d+", policy_settings_content) else 0) == 3:
            record_hit('Audit Directory Service Access set to Success and Failure.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Audit Logon Events":
        if (int(re.search(r"(?<=AuditLogonEvents \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=AuditLogonEvents \= )\d+", policy_settings_content) else 0) == 3:
            record_hit('Audit Logon Events set to Success and Failure.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Audit Object Access":
        if (int(re.search(r"(?<=AuditObjectAccess \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=AuditObjectAccess \= )\d+", policy_settings_content) else 0) == 3:
            record_hit('Audit Object Access set to Success and Failure.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Audit Policy Change":
        if (int(re.search(r"(?<=AuditPolicyChange \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=AuditPolicyChange \= )\d+", policy_settings_content) else 0) == 3:
            record_hit('Audit Policy Change set to Success and Failure.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Audit Privilege Use":
        if (int(re.search(r"(?<=AuditPrivilegeUse \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=AuditPrivilegeUse \= )\d+", policy_settings_content) else 0) == 3:
            record_hit('Audit Privilege Use set to Success and Failure.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Audit Process Tracking":
        if (int(re.search(r"(?<=AuditProcessTracking \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=AuditProcessTracking \= )\d+", policy_settings_content) else 0) == 3:
            record_hit('Audit Process Tracking set to Success and Failure.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Audit System Events":
        if (int(re.search(r"(?<=AuditSystemEvents \= )\d+", policy_settings_content).group(0)) if re.search(r"(?<=AuditSystemEvents \= )\d+", policy_settings_content) else 0) == 3:
            record_hit('Audit System Events set to Success and Failure.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Do Not Require CTRL_ALT_DEL":
        if (int(re.search(r"(?<=MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD\=\d,)\d+", policy_settings_content).group(0)) if re.search(r"(?<=MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD\=\d,)\d+", policy_settings_content) else 1) == 0:
            record_hit('Do not require CTRL + ALT + DEL has been disabled.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])
    if name == "Don't Display Last User":
        if (int(re.search(r"(?<=MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName\=\d,)\d+", policy_settings_content).group(0)) if re.search(r"(?<=MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName\=\d,)\d+", policy_settings_content) else 0) == 1:
            record_hit('Don\'t Display Last User Name has been enabled.',  vulnerability[1]['Points'], '')
        else:
            record_miss('Policy Management',  vulnerability[1]['Points'])


def group_manipulation(vulnerability, name):
    groups = wmi.Win32_GroupUser()
    group_list = {}
    for group in groups:
        try:
            if group.GroupComponent.Name in group_list:
                group_list[group.GroupComponent.Name].append(group.PartComponent.Name)
            else:
                group_list.update({group.GroupComponent.Name: [group.PartComponent.Name]})
        except:
            print(group.GroupComponent.Name, "was not added.")
    if name == "Add Admin":
        for vuln in vulnerability:
            if vuln != 1:
                if vulnerability[vuln]['User Name'] in group_list["Administrators"]:
                    record_hit(vulnerability[vuln]['User Name'] + ' has been promoted to administrator.', vulnerability[vuln]['Points'], '')
                else:
                    record_miss('User Management', vulnerability[vuln]['Points'])
    if name == "Remove Admin":
        for vuln in vulnerability:
            if vuln != 1:
                if vulnerability[vuln]['User Name'] not in group_list["Administrators"]:
                    record_hit(vulnerability[vuln]['User Name'] + ' has been demoted to standard user.', vulnerability[vuln]['Points'], '')
                else:
                    record_miss('User Management', vulnerability[vuln]['Points'])
    if name == "Add User to Group":
        for vuln in vulnerability:
            if vuln != 1:
                if vulnerability[vuln]['User Name'] in group_list[vulnerability[vuln]['Group Name']]:
                    record_hit(vulnerability[vuln]['User Name'] + ' is in the ' + vulnerability[vuln]['Group Name'] + ' group.', vulnerability[vuln]['Points'], '')
                else:
                    record_miss('User Management', vulnerability[vuln]['Points'])
    if name == "Remove User from Group":
        for vuln in vulnerability:
            if vuln != 1:
                if vulnerability[vuln]['User Name'] not in group_list[vulnerability[vuln]['Group Name']]:
                    record_hit(vulnerability[vuln]['User Name'] + ' is no longer in the ' + vulnerability[vuln]['Group Name'] + ' group.', vulnerability[vuln]['Points'], '')
                else:
                    record_miss('User Management', vulnerability[vuln]['Points'])


def user_change_password(vulnerability):
    for vuln in vulnerability:
        file = open('user_' + vulnerability[vuln]['User Name'].lower() + '.txt')
        content = file.read()
        file.close()
        last_changed_list = re.search(r"(?<=Password last set\s{12})\S+", content).group(0).split('/')
        last_changed = ''
        for date in last_changed_list:
            if int(date) < 10:
                temp = '0' + date
            else:
                temp = date
            last_changed = last_changed + temp + '/'
        if datetime.datetime.now().strftime('%m/%d/%Y') == last_changed.rsplit('/', 1)[0]:
            record_hit(vulnerability[vuln]['User Name'] + '\'s password was changed.', vulnerability[vuln]['Points'], '')
        else:
            record_miss('Policy Management', vulnerability[vuln]['Points'])


def check_startup(vulnerability):
    f = open('startup.txt', 'r', encoding='utf-16-le')
    content = f.read().splitlines()
    f.close()
    for vuln in vulnerability:
        if vuln != 1:
            if vulnerability[vuln]['Program Name'] in content:
                record_hit('Program Removed from Startup', vulnerability[vuln]['Points'], '')
            else:
                record_miss('Program Management', vulnerability[vuln]['Points'])


def add_text_to_file(vulnerability):
    for vuln in vulnerability:
        if vuln != 1:
            f = open(vulnerability[vuln]["File Path"], 'r')
            content = f.read()
            f.close()
            if re.search(vulnerability[vuln]["Text to Add"], content):
                record_hit(vulnerability[vuln]["Text to Add"] + ' has been added to ' + vulnerability[vuln]["File Path"], vulnerability[vuln]["Points"], '')
            else:
                record_miss('File Management', vulnerability[vuln]["Points"])


def remove_text_from_file(vulnerability):
    for vuln in vulnerability:
        if vuln != 1:
            f = open(vulnerability[vuln]["File Path"], 'r')
            content = f.read()
            f.close()
            if not re.search(vulnerability[vuln]["Text to Remove"], content):
                record_hit(vulnerability[vuln]["Text to Remove"] + ' has been removed from ' + vulnerability[vuln]["File Path"], vulnerability[vuln]["Points"], '')
            else:
                record_miss('File Management', vulnerability[vuln]["Points"])


def critical_services(vulnerability):
    services = wmi.Win32_SystemServices()
    service_list = {}
    service_status = {}
    for service in services:
        service_list.update({service.PartComponent.DisplayName: service.PartComponent.Name})
        service_status.update({service.PartComponent.Name: {"State": service.PartComponent.State, "Start Mode": service.PartComponent.StartMode}})

    for vuln in vulnerability:
        if vuln != 1:
            name = vulnerability[vuln]['Service Name']
            if name in service_list:
                name = service_list[name]
            if name in service_status:
                service_info = service_status[name]
                if vulnerability[vuln]['Service State'] == service_info["State"] and vulnerability[vuln]['Service Start mode'] == service_info["Start Mode"]:
                    record_penalty(name + ' was changed.', vulnerability[vuln]['Points'], '')


def manage_services(vulnerability):
    services = wmi.Win32_SystemServices()
    service_list = {}
    service_status = {}
    for service in services:
        service_list.update({service.PartComponent.DisplayName: service.PartComponent.Name})
        service_status.update({service.PartComponent.Name: {"State": service.PartComponent.State, "Start Mode": service.PartComponent.StartMode}})

    for vuln in vulnerability:
        if vuln != 1:
            name = vulnerability[vuln]['Service Name']
            if name in service_list:
                name = service_list[name]
            if name in service_status:
                service_info = service_status[name]
                if vulnerability[vuln]['Service State'] == service_info["State"] and vulnerability[vuln]['Service Start mode'] == service_info["Start Mode"]:
                    record_hit(name + ' has been ' + vulnerability[vuln]['Service State'] + ' and set to ' + vulnerability[vuln]['Service Start mode'], vulnerability[vuln]['Points'], '')
                else:
                    record_miss('Program Management', vulnerability[vuln]['Points'])


def critical_programs(vulnerability):
    k = open('programs.txt', 'r', encoding='utf-16-le')
    content = k.read().splitlines()
    k.close()
    for vuln in vulnerability:
        if vuln != 1:
            installed = False
            for c in content:
                if vulnerability[vuln]['Program Name'] in c:
                    installed = True
            if installed:
                record_penalty(vulnerability[vuln]['Program Name'] + ' was uninstalled.', vulnerability[vuln]['Points'], '')


def programs(vulnerability, name):
    k = open('programs.txt', 'r', encoding='utf-16-le')
    content = k.read().splitlines()
    k.close()
    if name == "Good Program":
        for vuln in vulnerability:
            if vuln != 1:
                installed = False
                for c in content:
                    if vulnerability[vuln]["Program Name"] in c:
                        installed = True
                if installed:
                    record_hit(vulnerability[vuln]["Program Name"] + ' is installed', vulnerability[vuln]["Points"], '')
                else:
                    record_miss('Program Management', vulnerability[vuln]["Points"])
    if name == "Bad Program":
        for vuln in vulnerability:
            installed = False
            for c in content:
                if vulnerability[vuln]["Program Name"] in c:
                    installed = True
            if not installed:
                record_hit(vulnerability[vuln]["Program Name"] + ' is uninstalled', vulnerability[vuln]["Points"], '')
            else:
                record_miss('Program Management', vulnerability[vuln]["Points"])


def anti_virus(vulnerability):
    z = open('security.txt', 'r', encoding='utf-16-le')
    content = z.read()
    z.close()
    if 'Real-time Protection Status : Enabled' in content:
        record_hit('Virus & threat protection enabled.', vulnerability[1]['Points'], '')
    else:
        record_miss('Security', vulnerability[1]['Points'])


def bad_file(vulnerability):
    for vuln in vulnerability:
        if vuln != 1:
            if not os.path.exists(vulnerability[vuln]["File Path"]):
                record_hit('The item ' + vulnerability[vuln]["File Path"] + ' has been removed.', vulnerability[vuln]["Points"], '')
            else:
                record_miss('File Management', vulnerability[vuln]["Points"])


def no_scoring_available(name):
    messagebox.showerror(("No scoring for:", name), ("There is no scoring definition for", name, ". Please remove this option if you are the image creator, if you are a competitor ignore this message."))


def load_policy_settings():
    os.system('secedit /export /cfg group-policy.inf')
    policy_settings = open('group-policy.inf', 'r', encoding='utf-16-le')
    content = policy_settings.read()
    policy_settings.close()
    return content


def ps_create():
    vuln_scripts = ["Good Program", "Bad Program", "Anti-Virus", "User Change Password", "Turn On Domain Firewall", "Turn On Private Firewall", "Turn On Public Firewall"]
    vuln_obj = {}
    for vuln in vuln_scripts:
        vuln_obj.update({vuln: Vulnerabilities.get_option_table(vuln, False)})
    m = open('check.ps1', 'w+')

    if vuln_obj["Bad Program"][1]["Enabled"] or vuln_obj["Good Program"][1]["Enabled"]:
        m.write('Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize > programs.txt\n')
    if vuln_obj["Anti-Virus"][1]["Enabled"]:
        m.write('function Get-AntiVirusProduct {\n[CmdletBinding()]\nparam (\n[parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]\n[Alias(\'name\')]\n$computername=$env:computername\n\n)\n\n#$AntivirusProducts = Get-WmiObject -Namespace "root\\SecurityCenter2" -Query $wmiQuery  @psboundparameters # -ErrorVariable myError -ErrorAction \'SilentlyContinue\' # did not work\n$AntiVirusProducts = Get-WmiObject -Namespace "root\\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername\n\n$ret = @()\nforeach($AntiVirusProduct in $AntiVirusProducts){\n#Switch to determine the status of antivirus definitions and real-time protection.\n#The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx\nswitch ($AntiVirusProduct.productState) {\n"262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}\n"262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}\n"266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}\n"266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}\n"393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}\n"393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}\n"393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}\n"397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}\n"397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}\n"397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}\ndefault {$defstatus = "Unknown" ;$rtstatus = "Unknown"}\n}\n\n#Create hash-table for each computer\n$ht = @{}\n$ht.Computername = $computername\n$ht.Name = $AntiVirusProduct.displayName\n$ht.\'Product GUID\' = $AntiVirusProduct.instanceGuid\n$ht.\'Product Executable\' = $AntiVirusProduct.pathToSignedProductExe\n$ht.\'Reporting Exe\' = $AntiVirusProduct.pathToSignedReportingExe\n$ht.\'Definition Status\' = $defstatus\n$ht.\'Real-time Protection Status\' = $rtstatus\n\n#Create a new object for each computer\n$ret += New-Object -TypeName PSObject -Property $ht \n}\nReturn $ret\n} \nGet-AntiVirusProduct > security.txt\n')
    m.close()
    m = open('check.bat', 'w+')
    m.write('echo > trigger.cfg\n')
    if vuln_obj["User Change Password"][1]["Enabled"]:
        for vuln in vuln_obj["User Change Password"]:
            if vuln != 1:
                m.write('net user ' + vuln_obj["User Change Password"][vuln]["User Name"].lower() + ' > user_' + vuln_obj["User Change Password"][vuln]["User Name"].lower() + '.txt\n')
    if vuln_obj["Turn On Domain Firewall"][1]["Enabled"] or vuln_obj["Turn On Private Firewall"][1]["Enabled"] or vuln_obj["Turn On Public Firewall"][1]["Enabled"]:
        m.write('netsh advfirewall show allprofiles state > firewall_status.txt\n')
    if vuln_obj["Bad Program"][1]["Enabled"] or vuln_obj["Good Program"][1]["Enabled"] or vuln_obj["Anti-Virus"][1]["Enabled"]:
        m.write('Powershell.exe -Command "& {Start-Process Powershell.exe -ArgumentList \'-ExecutionPolicy Bypass -File "check.ps1"\' -Verb RunAs -Wait -WindowStyle Hidden}"\n')
    m.write('timeout 30')
    m.close()
    f = open('invisible.vbs', 'w+')
    f.write('CreateObject("Wscript.Shell").Run """" & WScript.Arguments(0) & """", 0, False')
    f.close()
    os.system('wscript.exe "invisible.vbs" "check.bat"')


def account_management(vulnerabilities):
    write_to_html('<H3>USER MANAGEMENT</H3>')
    vulnerability_def = {"Disable Admin": disable_admin, "Disable Guest": disable_guest, "Add Admin": group_manipulation, "Remove Admin": group_manipulation, "Add User to Group": group_manipulation, "Remove User from Group": group_manipulation, "Add User": users_manipulation, "Remove User": users_manipulation, "User Change Password": user_change_password}
    for vuln in vulnerabilities:
        vulnerability = Vulnerabilities.get_option_table(vuln.name, False)
        if "Critical" in vuln.name:
            critical_items.append(vuln)
        elif vulnerability[1]["Enabled"]:
            if len(getfullargspec(vulnerability_def[vuln.name]).args) == 1:
                vulnerability_def[vuln.name](vulnerability if "vulnerability" in getfullargspec(vulnerability_def[vuln.name]).args else vuln.name)
            else:
                vulnerability_def[vuln.name](vulnerability, vuln.name)


def local_policies(vulnerabilities):
    write_to_html('<H3>SECURITY POLICIES</H3>')
    vulnerability_def = {"Turn On Domain Firewall": turn_on_firewall, "Turn On Private Firewall": turn_on_firewall, "Turn On Public Firewall": turn_on_firewall, "Do Not Require CTRL_ALT_DEL": local_group_policy, "Don't Display Last User": local_group_policy, "Minimum Password Age": local_group_policy, "Maximum Password Age": local_group_policy, "Minimum Password Length": local_group_policy, "Maximum Login Tries": local_group_policy, "Lockout Duration": local_group_policy, "Lockout Reset Duration": local_group_policy, "Password History": local_group_policy, "Password Complexity": local_group_policy, "Reversible Password Encryption": local_group_policy, "Audit Account Login": local_group_policy, "Audit Account Management": local_group_policy, "Audit Directory Settings Access": local_group_policy, "Audit Logon Events": local_group_policy, "Audit Object Access": local_group_policy, "Audit Policy Change": local_group_policy, "Audit Privilege Use": local_group_policy, "Audit Process Tracking": local_group_policy, "Audit System Events": local_group_policy}
    for vuln in vulnerabilities:
        vulnerability = Vulnerabilities.get_option_table(vuln.name, False)
        if vulnerability[1]["Enabled"]:
            if len(getfullargspec(vulnerability_def[vuln.name]).args) == 1:
                vulnerability_def[vuln.name](vulnerability if "vulnerability" in getfullargspec(vulnerability_def[vuln.name]).args else vuln.name)
            else:
                vulnerability_def[vuln.name](vulnerability, vuln.name)


def program_management(vulnerabilities):
    write_to_html('<H3>PROGRAMS</H3>')
    vulnerability_def = {"Good Program": programs, "Bad Program": programs, "Update Program": no_scoring_available, "Add Feature": no_scoring_available, "Remove Feature": no_scoring_available, "Services": manage_services}
    for vuln in vulnerabilities:
        vulnerability = Vulnerabilities.get_option_table(vuln.name, False)
        if "Critical" in vuln.name:
            critical_items.append(vuln)
        elif vulnerability[1]["Enabled"]:
            if len(getfullargspec(vulnerability_def[vuln.name]).args) == 1:
                vulnerability_def[vuln.name](vulnerability if "vulnerability" in getfullargspec(vulnerability_def[vuln.name]).args else vuln.name)
            else:
                vulnerability_def[vuln.name](vulnerability, vuln.name)


def file_management(vulnerabilities):
    write_to_html('<H3>FILE MANAGEMENT</H3>')
    vulnerability_def = {"Forensic": forensic_question, "Bad File": bad_file, "Check Hosts": no_scoring_available, "Add Text to File": add_text_to_file, "Remove Text From File": remove_text_from_file, "File Permissions": no_scoring_available}
    for vuln in vulnerabilities:
        vulnerability = Vulnerabilities.get_option_table(vuln.name, False)
        if vulnerability[1]["Enabled"]:
            if len(getfullargspec(vulnerability_def[vuln.name]).args) == 1:
                vulnerability_def[vuln.name](vulnerability if "vulnerability" in getfullargspec(vulnerability_def[vuln.name]).args else vuln.name)
            else:
                vulnerability_def[vuln.name](vulnerability, vuln.name)


def miscellaneous(vulnerabilities):
    write_to_html('<H3>MISCELLANEOUS</H3>')
    vulnerability_def = {"Anti-Virus": anti_virus, "Update Check Period": no_scoring_available, "Update Auto Install": no_scoring_available, "Task Scheduler": no_scoring_available, "Check Startup": no_scoring_available}
    for vuln in vulnerabilities:
        vulnerability = Vulnerabilities.get_option_table(vuln.name, False)
        if vulnerability[1]["Enabled"]:
            if len(getfullargspec(vulnerability_def[vuln.name]).args) == 1:
                vulnerability_def[vuln.name](vulnerability if "vulnerability" in getfullargspec(vulnerability_def[vuln.name]).args else vuln.name)
            else:
                vulnerability_def[vuln.name](vulnerability, vuln.name)


def critical_functions(vulnerabilities):
    write_to_html('<H4>Critical Functions:</H4>')
    vulnerability_def = {"Critical Users": critical_users, "Critical Programs": critical_programs, "Critical Services": critical_services}
    for vuln in vulnerabilities:
        vulnerability = Vulnerabilities.get_option_table(vuln.name, False)
        if vulnerability[1]["Enabled"]:
            vulnerability_def[vuln.name](vulnerability)


wmi = WMI()
try:
    Settings = db_handler.Settings()
    menuSettings = Settings.get_settings(False)
    Categories = db_handler.Categories()
    categories = Categories.get_categories()
    Vulnerabilities = db_handler.OptionTables()
    Vulnerabilities.initialize_option_table()
except:
    f = open('scoring_engine.log', 'w')
    e = traceback.format_exc()
    if "KeyboardInterrupt" in e:
        sys.exit()
    f.write(str(e))
    f.close()
    messagebox.showerror('Crash Report', 'The scoring engine has stopped working, a log has been saved to ' + os.path.abspath('scoring_engine.log'))
    sys.exit()

total_points = 0
total_vulnerabilities = 0
prePoints = 0
category_def = {"Account Management": account_management, "Local Policy": local_policies, "Program Management": program_management, "File Management": file_management, "Miscellaneous": miscellaneous}
Desktop = menuSettings["Desktop"]
index = 'C:/CyberPatriot/'
scoreIndex = index + 'ScoreReport.html'

# --------- Main Loop ---------#
print("Building Balloon")
w = balloontip.WindowsBalloonTip()
print("Running Checks")
check_runas()
while True:
    print("Initializing Variables and Running Scrips(~20 seconds)")
    try:
        if not os.path.exists('trigger.cfg'):
            print("Creating PS")
            ps_create()
        else:
            os.remove('trigger.cfg')
        total_points = 0
        total_vulnerabilities = 0
        critical_items = []
        policy_settings_content = load_policy_settings()
        time.sleep(5)
        print("Building Report Head")
        draw_head()
        for category in categories:
            print("Checking", category.name, "Options")
            category_def[category.name](Vulnerabilities.get_option_template_by_category(category.id))
        print("Checking Critical Functions")
        critical_functions(critical_items)
        print("Checking Score")
        check_score()
        print("Building Report Tail")
        draw_tail()
        print("Finished...Looping in 30 Seconds")
        time.sleep(30)
    except:
        f = open('scoring_engine.log', 'w')
        e = traceback.format_exc()
        if "KeyboardInterrupt" in e:
            sys.exit()
        f.write(str(e))
        f.close()
        messagebox.showerror('Crash Report', 'The scoring engine has stopped working, a log has been saved to ' + os.path.abspath('scoring_engine.log'))
        sys.exit()

# TODO add Functions:
#  updatecheckperiod    ["Miscellaneous"]["Update Check Period"]
#  updateautoinstall    ["Miscellaneous"]["Update Auto Install"]
#  checkhosts           ["File Management"]["Check Hosts"]
#  taskscheduler        ["Miscellaneous"]["Task Scheduler"]
#  checkstartup         ["Miscellaneous"]["Check Startup"]
