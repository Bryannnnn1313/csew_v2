import ctypes, os, sys, subprocess, time
import win32com.client
import fileinput
import balloontip
from io import StringIO
import traceback
import wmi
from winreg import (HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS,
                     OpenKey, EnumValue, QueryValueEx)

##OPTIONVARIABLES##
Desktop = ''
silentMiss = True
FTPServertrue = False
forensicCount = [2]
forensicsAnswer1 = ['w']
checkForensicsQuestion1Value = [10]
forensicsAnswer2 = ['a']
checkForensicsQuestion2Value = [10]
disableAdmin = False
requireCTRL_ALT_DEL = False
XXX = False
checkFirewall = False
XXX = False
XXX = False
minPassAge = False
maxPassAge = False
maxLoginTries = False
checkPassLength = False
checkPassHist = False
checkPassCompx = False
XXX = False
updateAutoInstall = False
goodUser = False
badUser = False
newUser = False
changePassword = False
goodAdmin = False
badAdmin = False
goodGroup = False
badGroup = False
goodProgram = False
badProgram = False
goodService = False
badService = False
badFile = False
antivirus = False
checkHosts = False
checkStartup = False
taskScheduler = False
userInGroup = False
fileContainsText1 = False
fileContainsText2 = False
fileNoLongerContains1 = False
fileNoLongerContains2 = False

# Program Base Variables
posPoints = 0
posVuln = 0
totalPoints = 0
totalVuln = 0
prePoints = 0
index = 'C:/CyberPatriot/'
scoreIndex = index, 'ScoreReport.html'

'''if ctypes.windll.shell32.IsUserAnAdmin() == 0:
    exit()'''

# Scoring Report creation
def drawHead():
    f = open(scoreIndex, 'w+')
    f.write('<!doctype html><html><head><title>CSEL Score Report</title><meta http-equiv="refresh" content="30"></head><body style="background-color:powderblue;">''\n')
    f.write('<table align="center" cellpadding="10"><tr><td><img src="/etc/CYBERPATRIOT_DO_NOT_REMOVE/iguana.png"></td><td><img src="/etc/CYBERPATRIOT_DO_NOT_REMOVE/logo.png"></td><td><div align="center"><H2>Cyberpatriot Scoring Engine:Linux v2.0</H2></div></td><td><img '
            'src="/etc/CYBERPATRIOT_DO_NOT_REMOVE/SoCalCCCC.png"></td><td><img src="/etc/CYBERPATRIOT_DO_NOT_REMOVE/CCC_logo.png"></td></tr></table><br><H2>Your Score: #TotalScore#/#PossiblePoints#</H2><H2>Vulnerabilities: #TotalVuln#/#PossibleVuln#</H2><hr>')
    f.close()

def recordHit(name, points, message):
    global totalPoints
    global totalVuln
    f = open(scoreIndex, 'a')
    f.write('<p style="color:green">', name, '(', points, 'points)</p>')
    f.close()
    totalPoints += points
    totalVuln += 1

def recordMiss(name):
    if not silentMiss:
        f = open(scoreIndex, 'a')
        f.write('<p style="color:red">MISS', name, 'Issue</p>')
        f.close()

def recordPenalty(name, points, message):
    global totalPoints
    f = open(scoreIndex, 'a')
    f.write('<p style="color:red">', name, '(', points, 'points)</p>')
    f.close()
    totalPoints -= points

def replaceSec(filename, text_to_search, replacement_text):
    with fileinput.FileInput(filename, inplace=True, backup='.bak') as file:
        for line in file:
            print(line.replace(text_to_search, replacement_text), end='')

def drawTail():
    f = open(scoreIndex, 'a')
    f.write('<hr><div align="center"><br>Developed by Josh Davis<br><b>Eastern Oklahoma County Technology Center/Coastline Collage</b><br>Feedback welcome: <a href="mailto:jdavis@eoctech.edu?Subject=CSEL" target="_top">jdavis@eoctech.edu</a><br>Modified/Updated by Shaun Martin</br><b>Coastline Collage</b><br>Feedback '
            'welcome: <a href="mailto:smartin94@student.cccd.edu?Subject=CSEL Scoring Engine" target="_top">smartin94@student.cccd.edu</a></div>')
    f.close()

    path = os.path.join(Desktop, 'ScoreReport.html')
    target = scoreIndex
    icon = index, 'scoreIcon.ico'
    shell = win32com.client.Dispatch("WScript.Shell")
    shortcut = shell.CreateShortCut(path)
    shortcut.Targetpath = target
    shortcut.IconLocation = icon
    shortcut.WindowStyle = 7  # 7 - Minimized, 3 - Maximized, 1 - Normal
    shortcut.save()

    replaceSec(index, '#TotalScore#', totalPoints)
    replaceSec(index, '#PossiblePoints#', posPoints)
    replaceSec(index, '#TotalVuln#', totalVuln)
    replaceSec(index, '#PossibleVuln#', posVuln)

# Extra Checks
def scoreCheck():
    global totalPoints
    global prePoints
    if totalPoints > prePoints:
        prePoints = totalPoints
        balloontip.balloon_tip('Score Update', 'You gained points!!')
    if totalPoints < prePoints:
        prePoints = totalPoints
        balloontip.balloon_tip('Score Update', 'You lost points!!')

def runPowershell(fileName):
    f = open('powerRun.bat', 'x')
    f.write('PowerShell.exe -ExecutionPolicy Bypass -Command "& \'.\\' + fileName + '.ps1\'"')
    f.close()
    subprocess.Popen([r'powerRun.bat'])
    time.sleep(1)
    os.remove(fileName + '.ps1')
    os.remove('powerRun.bat')

# Option Check
def forensicQuestion():
    for fq in forensicCount:
        path = Desktop + 'Question' + fq + '.txt'
        name = 'Forensic Question', fq
        f = open(path, 'r')
        content = f.read().splitlines()
        for c in content:
            if 'ANSWER:' in c:
                if forensicAnswer[fq] in c:
                    recordHit(name, forensicValue[fq], '')
                else:
                    recordMiss(name)

def disableGuest():
    f = open('guestCheck.ps1', 'w+')
    f.write('Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=\'$true\'"|Select-Object Name,Disabled|Format-Table -AutoSize > user.txt')
    f.close()
    runPowershell('guestCheck')
    f = open('user.txt', 'r', encoding='utf-16-le')
    content = f.read().splitlines()
    f.close()
    for c in content:
        if 'Guest' in c:
            if ' True' in c:
                recordHit('Disable Guest', disableGuestValue, '')
                os.remove('user.txt')
            else:
                recordMiss('Disable Guest')
                os.remove('user.txt')

def disableAdmin():
    f = open('adminCheck.ps1', 'w+')
    f.write('Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=\'$true\'"|Select-Object Name,Disabled|Format-Table -AutoSize > user.txt')
    f.close()
    runPowershell('adminCheck')
    f = open('user.txt', 'r', encoding='utf-16-le')
    content = f.read().splitlines()
    f.close()
    for c in content:
        if 'Administrator' in c:
            if ' True' in c:
                recordHit('Disable Admin', disableAdminValue, '')
                os.remove('user.txt')
            else:
                recordMiss('Disable Admin')
                os.remove('user.txt')

def checkFirewall():
    f = open('firewall.bat', 'x')
    f.write('@echo off\nnetsh advfirewall show private > status.txt\nnetsh advfirewall show public >> status.txt\necho working')
    f.close()
    subprocess.Popen([r'firewall.bat'])
    time.sleep(1)
    with open('status.txt') as t:
        content = t.read().splitlines()
    t.close()
    statuson = 'true'
    for cont in content:
        if 'OFF' in cont:
            statuson = 'false'
    if statuson == 'true':
        recordHit('checkFirewall', checkFirewallValue, '')
    else:
        recordMiss('checkFirewall')
    os.remove('firewall.bat')
    os.remove('status.txt')

def localGroupPolicy(option):
    os.system('secedit /export /cfg group-policy.txt')
    p = open('group-policy.txt','r', encoding='utf-16-le')
    content = p.read().split('\n')
    p.close()
    if option == 'minPassAge':
        for i in content:
            if 'MinimumPasswordAge' in i:
                if i.endswith('30'):
                    recordHit('Minimum Password Age', option+'value', '')
                else:
                    recordMiss('Password Policy')
    elif option =='maxPassAge':
        for i in content:
            if 'MaximumPasswordAge' in i:
                if i.endswith('60'):
                    recordHit('Maximum Password Age', option+'value', '')
                else:
                    recordMiss('Password Policy')
    elif option =='maxLoginTries':
        for i in content:
            if 'LockoutBadCount' in i:
                if i.endswith('5'):
                    recordHit('Maximum Login Tries', option+'value', '')
                else:
                    recordMiss('Account Policy')
    elif option == 'checkPassLength':
        for i in content:
            if 'MinimumPasswordLength' in i:
                if i.endswith('10'):
                    recordHit('Minimum Password Length', option+'value', '')
                else:
                    recordMiss('Password Policy')
    elif option == 'checkPassHist':
        for i in content:
            if 'PasswordHistorySize' in i:
                if i.endswith('5'):
                    recordHit('Password History Size', option+'value', '')
                else:
                    recordMiss('Password Policy')
    elif option == 'checkPassCompx':
        for i in content:
            if 'PasswordComplexity' in i:
                if i.endswith('1'):
                    recordHit('Password Complexity', option+'value', '')
                else:
                    recordMiss('Password Policy')
    elif option == 'requireCTRL_ALT_DEL':
        for i in content:
            if 'DisableCAD' in i:
                if i.endswith('1'):
                    recordHit('Require CTRL + ALT + DEL', option+'value', '')
                else:
                    recordMiss('Security Policy')
    elif option == 'DontDisplayLastUser':
        for i in content:
            if 'DontDisplayLastUserName' in i:
                if i.endswith('1'):
                    recordHit('Dont Display Last User Name', option+'value', '')
                else:
                    recordMiss('Security Policy')

def checkUser(VariableName):
    f = open('user.bat', 'x')
    f.write('@echo off\nnet users > users.txt')
    f.close()
    subprocess.Popen([r'user.bat'])
    time.sleep(1)
    with open('users.txt') as t:
        content = t.read().splitlines()
    t.close()
    userlist = []
    for c in content:
        for f in VariableName:
            if f in c:
                userlist.append[True]
            else:
                userlist.append[False]
    return userlist
    os.remove('user.bat')
    os.remove('users.txt')

def goodUser():
    userlists = checkUser(goodUserKeywords)
    for idx, item in enumerate(userlists):
        if not userlists[idx]:
            recordPenalty('goodUser', goodUserValue[idx], '')

def badUser():
    userlists = checkUser(badUserKeywords)
    for idx, item in enumerate(userlists):
        if userlists[idx]:
            recordMiss('Remove User')
        else:
            recordHit('Remove User', badUserValue[idx], '')

def newUser():
    userlists = checkUser(newUserKeywords)
    for idx, item in enumerate(userlists):
        if userlists[idx]:
            recordHit('newUser', newUserValue[idx], '')
        else:
            recordMiss('Add User')

def adminCheck(VariableName):
    f = open('admin.bat', 'x')
    f.write('@echo off\nnet localgroup Administrators > admins.txt')
    f.close()
    subprocess.Popen([r'admin.bat'])
    time.sleep(1)
    with open('admins.txt') as t:
        content = t.read().splitlines()
    t.close()
    adminlist = []
    for c in content:
        for f in VariableName:
            if f in c:
                adminlist.append[True]
            else:
                adminlist.append[False]
    return adminlist
    os.remove('admin.bat')
    os.remove('admins.txt')

def goodAdmin():
    adminlists = adminCheck(goodAdminKeywords)
    for idx, item in enumerate(adminlists):
        if not adminlists[idx]:
            recordPenalty('goodAdmin', goodAdminValue[idx], '')

def badAdmin():
    adminlists = adminCheck(badAdminKeywords)
    for idx, item in enumerate(adminlists):
        if adminlists[idx]:
            recordMiss('Remove Admin')
        else:
            recordHit('badAdmin', badAdminValue[idx], '')

def groupCheck(VariableName):
    f = open('group.bat', 'x')
    f.write('@echo off\nnet localgroup > groups.txt')
    f.close()
    subprocess.Popen([r'group.bat'])
    time.sleep(1)
    with open('groups.txt') as t:
        content = t.read().splitlines()
    t.close()
    grouplist = []
    for c in content:
        for f in VariableName:
            if f in c:
                grouplist.append[True]
            else:
                grouplist.append[False]
    return grouplist
    os.remove('group.bat')
    os.remove('groups.txt')

def goodGroup():
    grouplists = groupCheck(goodGroupKeywords)
    for idx, item in enumerate(grouplists):
        if not grouplists[idx]:
            recordPenalty('goodGroup', goodGroupValue[idx], '')

def badGroup():
    grouplists = groupCheck(badGroupKeywords)
    for idx, item in enumerate(grouplists):
        if grouplists[idx]:
            recordMiss('Remove Group')
        else:
            recordHit('badGroup', badGroupValue[idx], '')

def userInGroup():
    for idx, item in enumerate(userInGroupExtraKeywords):
        f = open('UserGroup.bat', 'x')
        f.write('@echo off\nnet localgroup'+ userInGroupExtraKeywords[idx] +' > UserGroups.txt\n')
        f.close()
        subprocess.Popen([r'UserGroup.bat'])
        time.sleep(1)
        with open('UserGroups.txt') as t:
            content = t.read().splitlines()
        t.close()
        for cont in content:
            if userInGroupKeywords[idx] in cont:
                recordHit('userInGroup', userInGroupValue[idx], '')
            else:
                recordMiss('User Not In Group')
        os.remove('UserGroup.bat')
        os.remove('UserGroups.txt')

def checkStartup():
    f = open('checkstartup.ps1', 'w+')
    f.write('Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location | Format-Table -AutoSize > startup.txt')
    f.close()
    runPowershell('checkstartup')
    f = open('startup.txt', 'r', encoding='utf-16-le')
    content = f.read().splitlines()
    f.close()
    for k in checkStartupKeywords:
        if k in content:
            recordHit('Program Removed from Startup', checkStartupValue, '')
        else:
            recordMiss('Startup')

def fileContainsText():
    f = open(fileContainsTextKeywords, 'r')
    content = f.read().splitlines()
    infile = False
    for c in content:
        if fileContainsTextExtraKeywords in c:
            infile = True
    if infile:
        recordHit(fileContainsTextMessage,fileContainsTextValue,'')
    else:
        recordMiss('File Does Not Contains Text')

def checkInstalled():
    softFile = open('softLog.log', 'w')
    errorLog = open('errorLog.log', 'w')
    r = wmi.Registry()
    result, names = r.EnumKey(hDefKey=HKEY_LOCAL_MACHINE, sSubKeyName=r"Software\Microsoft\Windows\CurrentVersion\Uninstall")

    separator = "*" * 80
    keyPath = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"

    for subkey in names:
        try:
            softFile.write(separator + '\n\n')
            path = keyPath + "\\" + subkey
            key = OpenKey(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS)
            try:
                temp = QueryValueEx(key, 'DisplayName')
                display = str(temp[0])
                softFile.write('Display Name: ' + display + '\nRegkey: ' + subkey + '\n')
            except:
                softFile.write('Regkey: ' + subkey + '\n')

        except:
            fp = StringIO.StringIO()
            traceback.print_exc(file=fp)
            errorMessage = fp.getvalue()
            error = 'Error for ' + key + '. Message follows:\n' + errorMessage
            errorLog.write(error)
            errorLog.write("\n\n")

    softFile.close()
    errorLog.close()

def goodPrograms():
    f = open('softFile.log')
    content = f.read().splitlines()
    f.close()
    for i in goodProgramKeywords:
        if i in content:
            recordHit('Program Installed', goodProgramValue, '')
        else:
            recordMiss('Programs')

def badPrograms():
    f = open('softFile.log')
    content = f.read().splitlines()
    f.close()
    for i in badProgramKeywords:
        if i in content:
            recordMiss('Programs')
        else:
            recordHit('Program Uninstalled', badProgramValue, '')

def fileNoLongerContainsText():
    f = open(fileNoLongerContainsTextKeywords, 'r')
    content = f.read().splitlines()
    infile = False;
    for c in content:
        if fileNoLongerContainsTextExtraKeywords in c:
            infile = True
    if not infile:
        recordHit(fileNoLongerContainsTextMessage,fileNoLongerContainsTextValue,'')
    else:
        recordMiss('File Still Contains Text')

def badService():
    m = open('getServices.ps1', 'w+')
    m.write('Get-Service | Select-Object Name,status,startType | Format-Table -AutoSize > services.txt')
    m.close()
    runPowerShell('getServices')
    p = open('services.txt','r', encoding='utf-16-le')
    content = p.read().splitlines()
    p.close()
    for c in content:
        for bs in badServiceKeywords:
            if bs in c:
                if 'Disabled' in c and 'Stopped' in c:
                    recordHit('Disabled Service', badServiceValue, '')
                else:
                    recordmiss('Service')
    if os.path.exists('getServices.ps1'):
        os.remove('getServices.ps1')
    if os.path.exists('services.txt'):
        os.remove('services.txt')
                    
                    
def programs():
    m = open('getPrograms.ps1', 'w+')
    m.write('Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table �AutoSize > programs.txt')
    m.close()
    runPowershell('getPrograms')
    k = open('programs.txt', 'r', encoding='utf-16-le')
    content = k.read().splitlines()
    k.close()
    for gp in goodProgramKeywords:
        installed=False
        for c in content:
            if gp in c:
                installed=True
        if installed:
            recordHit('Good program installed', goodProgramValue, '')
        else:
            recordmiss('Program')
    for bp in badProgramKeywords:
        installed=False
        for c in content:
            if bp in c:
                installed=True
        if not installed:
            recordHit('Bad program uninstalled', badProgramValue, '')
        else:
            recordmiss('Program')
    if os.path.exists('getPrograms.ps1'):
        os.remove('getPrograms.ps1')
    if os.path.exists('programs.txt'):
        os.remove('programs.txt')

def antivirus():
    protections = ['AntispywareEnabled', 'AntivirusEnabled', 'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'IsTamperProtected', 'NISEnabled', 'OnAccessProtectionEnabled', 'RealTimeProtectionEnabled']
    m = open('getSecurity.ps1', 'w+')
    m.write('Get-MpComputerStatus > security.txt')
    m.close()
    runPowershell('getSecurity')
    z = open('security.txt', 'r', encoding='utf-16-le')
    content = z.read().splitlines()
    z.close()
    protected = True
    for c in content:
        for p in protections:
            if (p in c) and ('False' in c):
                protected = False
    if protected:
        recordHit('Virus & threat protection enabled', antivirusValue, '')
    else:
        recordMiss('Virus & threat protection')
    if os.path.exists('getSecurity.ps1'):
        os.remove('getSecurity.ps1')
    if os.path.exists('security.txt'):
        os.remove('security.txt')

def badFile():
    for idx, item in enumerate(badFileKeywords):
        f = open('badfile.bat', 'x')
        f.write('@echo off\nif EXIST \"' + badFileKeywords[idx] + '\" echo y > check.txt\nif NOT EXIST \"' + badFileKeywords[idx] + 'echo n > check.txt')
        f.close()
        subprocess.Popen([r'badfile.bat'])
        time.sleep(1)
        with open('check.txt') as t:
            if 'n' in t.read():
                recordHit('badFile', badFileValue[idx], '')
            else:
                recordMiss('Remove bad file')
        t.close()
        os.remove('badfile.bat')
        os.remove('check.txt')