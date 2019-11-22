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
Desktop = 'C:/Users/CyberPatriot/Desktop/'
silentMiss = True
FTPServertrue = False
forensicQuestion = False
forensicCount = [2]
forensicAnswer = ['w']
forensicValue = [10]
disableGuest = False
disableGuestValue = [9]
disableAdmin = False
disableAdminValue = [4]
requireCTRL_ALT_DEL = True
requireCTRL_ALT_DELValue = [4]
dontDisplayLastUser = True
dontDisplayLastUserValue = [4]
XXX = False
checkFirewall = True
checkFirewallValue = [9]
XXX = False
XXX = False
minPassAge = True
minPassAgeValue = [7]
maxPassAge = True
maxLoginTries = True
checkPassLength = True
checkPassHist = True
checkPassCompx = True
XXX = False
updateAutoInstall = False
goodUser = False
goodUserValue = [8, 8]
goodUserKeywords = ['hi', 'bye']
badUser = False
badUserValue = [8]
badUserKeywords = ['hi']
newUser = False
newUserValue = [9]
newUserKeywords = ['hi']
changePassword = False
goodAdmin = False
goodAdminValue = [8]
goodAdminKeywords = ['hi']
badAdmin = False
badAdminValue = [4]
badAdminKeywords = ['hi']
goodGroup = False
goodGroupValue = [9]
goodGroupKeywords = ['hi']
badGroup = False
badGroupValue = [9]
badGroupKeywords = ['hi']
goodProgram = True
goodProgramValue = [9]
goodProgramKeywords = ['hi']
badProgram = True
badProgramValue = [4]
badProgramKeywords = ['hi']
goodService = False
badService = True
badServiceValue = [9]
badServiceKeywords = ['hi']
badFile = True
badFileValue = [9]
badFileKeywords = ['hi']
antiVirus = True
antiVirusValue = [5]
checkHosts = False
checkStartup = True
checkStartupValue = [8]
checkStartupKeywords = ['hi']
taskScheduler = False
userInGroup = True
userInGroupValue = [4]
userInGroupKeywords = ['hi']
userInGroupExtraKeywords = ['hi']
fileContainsText = True
fileContainsTextValue = [9]
fileContainsTextKeywords = ['hi']
fileContainsTextExtraKeywords = ['hi']
fileContainsTextMessage = ['ag']
fileNoLongerContains = True
fileNoLongerContainsValue = [8]
fileNoLongerContainsKeywords = ['hi']
fileNoLongerContainsExtraKeywords = ['hi']
fileNoLongerContainsMessage = ['erg']

# Program Base Variables
posPoints = 0
posVuln = 0
totalPoints = 0
totalVuln = 0
prePoints = 0
index = 'C:/CyberPatriot/'
scoreIndex = index + 'ScoreReport.html'


# Scoring Report creation
def drawhead():
    f = open(scoreIndex, 'w+')
    f.write('<!doctype html><html><head><title>CSEL Score Report</title><meta http-equiv="refresh" content="30"></head><body style="background-color:powderblue;">''\n')
    f.write('<table align="center" cellpadding="10"><tr><td><img src="/etc/CYBERPATRIOT_DO_NOT_REMOVE/iguana.png"></td><td><img src="/etc/CYBERPATRIOT_DO_NOT_REMOVE/logo.png"></td><td><div align="center"><H2>Cyberpatriot Scoring Engine:Linux v2.0</H2></div></td><td><img '
            'src="/etc/CYBERPATRIOT_DO_NOT_REMOVE/SoCalCCCC.png"></td><td><img src="/etc/CYBERPATRIOT_DO_NOT_REMOVE/CCC_logo.png"></td></tr></table><br><H2>Your Score: #TotalScore#/#PossiblePoints#</H2><H2>Vulnerabilities: #TotalVuln#/#PossibleVuln#</H2><hr>')
    f.close()


def recordhit(name, points, message):
    global totalPoints
    global totalVuln
    writetohtml(('<p style="color:green">' + name + '(' + str(points) + 'points)</p>'))
    totalPoints += points
    totalVuln += 1


def recordmiss(name):
    if not silentMiss:
        writetohtml(('<p style="color:red">MISS' + name + 'Issue</p>'))


def recordpenalty(name, points, message):
    global totalPoints
    writetohtml(('<p style="color:red">' + name + '(' + str(points) + 'points)</p>'))
    totalPoints -= points


def drawtail():
    writetohtml(('<hr><div align="center"><br>Developed by Josh Davis<br><b>Eastern Oklahoma County Technology Center/Coastline Collage</b><br>Feedback welcome: <a href="mailto:jdavis@eoctech.edu?Subject=CSEL" target="_top">jdavis@eoctech.edu</a><br>Modified/Updated by Shaun Martin</br><b>Coastline Collage</b><br>Feedback '
                 'welcome: <a href="mailto:smartin94@student.cccd.edu?Subject=CSEL Scoring Engine" target="_top">smartin94@student.cccd.edu</a></div>'))
    replacements = {'#TotalScore#': totalPoints, '#PossiblePoints#': posPoints, '#TotalVuln#': totalVuln, '#PossibleVuln#': posVuln}
    replacesec(index, replacements)

    path = os.path.join(Desktop, 'ScoreReport.html')
    target = scoreIndex
    icon = index, 'scoreIcon.ico'
    shell = win32com.client.Dispatch("WScript.Shell")
    shortcut = shell.CreateShortCut(path)
    shortcut.Targetpath = target
    shortcut.IconLocation = icon
    shortcut.WindowStyle = 7  # 7 - Minimized, 3 - Maximized, 1 - Normal
    shortcut.save()


# Extra Functions
def checkrunas():
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        exit()


def scorecheck():
    global totalPoints
    global prePoints
    if totalPoints > prePoints:
        prePoints = totalPoints
        balloontip.balloon_tip('Score Update', 'You gained points!!')
    if totalPoints < prePoints:
        prePoints = totalPoints
        balloontip.balloon_tip('Score Update', 'You lost points!!')


def runpowershell(fileName):
    f = open('powerRun.bat', 'x')
    f.write('PowerShell.exe -ExecutionPolicy Bypass -Command "& \'.\\' + fileName + '.ps1\'"')
    f.close()
    subprocess.Popen([r'powerRun.bat'])
    time.sleep(1)
    os.remove(fileName + '.ps1')
    os.remove('powerRun.bat')


def writetohtml(message):
    f = open(scoreIndex, 'a')
    f.write(message)
    f.close()


def replacesec(loc, replaceList):
    lines = []
    with open(loc) as file:
        for line in file:
            for search, replace in replaceList.iteritems():
                line = line.replace(search, replace)
            lines.append(line)
    with open(loc, 'w') as file:
        for line in lines:
            file.write(line)


# Option Check
def forensicquestion():
    for fq in forensicCount:
        path = Desktop + 'Question' + fq + '.txt'
        name = 'Forensic Question', fq
        f = open(path, 'r')
        content = f.read().splitlines()
        for c in content:
            if 'ANSWER:' in c:
                if forensicAnswer[fq] in c:
                    recordhit(name, forensicValue[fq], '')
                else:
                    recordmiss(name)


def disableguest():
    f = open('guestCheck.ps1', 'w+')
    f.write('Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=\'$true\'"|Select-Object Name,Disabled|Format-Table -AutoSize > user.txt')
    f.close()
    runpowershell('guestCheck')
    time.sleep(10)
    f = open('user.txt', 'r', encoding='utf-16-le')
    content = f.read().splitlines()
    f.close()
    for c in content:
        if 'Guest' in c:
            if ' True' in c:
                recordhit('Disable Guest', disableGuestValue, '')
                os.remove('user.txt')
            else:
                recordmiss('Disable Guest')
                os.remove('user.txt')


def disableadmin():
    f = open('adminCheck.ps1', 'w+')
    f.write('Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=\'$true\'"|Select-Object Name,Disabled|Format-Table -AutoSize > user.txt')
    f.close()
    runpowershell('adminCheck')
    f = open('user.txt', 'r', encoding='utf-16-le')
    content = f.read().splitlines()
    f.close()
    for c in content:
        if 'Administrator' in c:
            if ' True' in c:
                recordhit('Disable Admin', disableAdminValue, '')
                os.remove('user.txt')
            else:
                recordmiss('Disable Admin')
                os.remove('user.txt')


def checkfirewall():
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
        recordhit('checkFirewall', checkFirewallValue[0], '')
    else:
        recordmiss('checkFirewall')
    os.remove('firewall.bat')
    os.remove('status.txt')


def localgrouppolicy(option):
    os.system('secedit /export /cfg group-policy.txt')
    p = open('group-policy.txt', 'r', encoding='utf-16-le')
    content = p.read().split('\n')
    p.close()
    if option == 'minPassAge':
        for i in content:
            if 'MinimumPasswordAge' in i:
                if i.endswith('30'):
                    recordhit('Minimum Password Age', option + 'value', '')
                else:
                    recordmiss('Password Policy')
    elif option == 'maxPassAge':
        for i in content:
            if 'MaximumPasswordAge' in i:
                if i.endswith('60'):
                    recordhit('Maximum Password Age', option + 'value', '')
                else:
                    recordmiss('Password Policy')
    elif option == 'maxLoginTries':
        for i in content:
            if 'LockoutBadCount' in i:
                if i.endswith('5'):
                    recordhit('Maximum Login Tries', option + 'value', '')
                else:
                    recordmiss('Account Policy')
    elif option == 'checkPassLength':
        for i in content:
            if 'MinimumPasswordLength' in i:
                if i.endswith('10'):
                    recordhit('Minimum Password Length', option + 'value', '')
                else:
                    recordmiss('Password Policy')
    elif option == 'checkPassHist':
        for i in content:
            if 'PasswordHistorySize' in i:
                if i.endswith('5'):
                    recordhit('Password History Size', option + 'value', '')
                else:
                    recordmiss('Password Policy')
    elif option == 'checkPassCompx':
        for i in content:
            if 'PasswordComplexity' in i:
                if i.endswith('1'):
                    recordhit('Password Complexity', option + 'value', '')
                else:
                    recordmiss('Password Policy')
    elif option == 'requireCTRL_ALT_DEL':
        for i in content:
            if 'DisableCAD' in i:
                if i.endswith('1'):
                    recordhit('Require CTRL + ALT + DEL', option + 'value', '')
                else:
                    recordmiss('Security Policy')
    elif option == 'DontDisplayLastUser':
        for i in content:
            if 'dontDisplayLastUserName' in i:
                if i.endswith('1'):
                    recordhit('Dont Display Last User Name', option + 'value', '')
                else:
                    recordmiss('Security Policy')


def checkuser(VariableName):
    f = open('user.bat', 'x')
    f.write('@echo off\nnet users > users.txt')
    f.close()
    subprocess.Popen([r'user.bat'])
    time.sleep(1)
    with open('users.txt') as t:
        content = t.read().splitlines()
    t.close()
    check = False
    userlist = []
    for f in VariableName:
        for c in content:
            if f in c:
                userlist.append(True)
                check = True
        if not check:
            userlist.append(False)
            check = False
    os.remove('user.bat')
    os.remove('users.txt')
    return userlist


def gooduser():
    userlists = checkuser(goodUserKeywords)
    for idx, item in enumerate(userlists):
        print(idx)
        if not userlists[idx]:
            recordpenalty('Removed User', goodUserValue[idx], '')


def baduser():
    userlists = checkuser(badUserKeywords)
    for idx, item in enumerate(userlists):
        if userlists[idx]:
            recordmiss('Users')
        else:
            recordhit('Remove User', badUserValue[idx], '')


def newuser():
    userlists = checkuser(newUserKeywords)
    for idx, item in enumerate(userlists):
        if userlists[idx]:
            recordhit('Add User', newUserValue[idx], '')
        else:
            recordmiss('Users')


def admincheck(VariableName):
    f = open('admin.bat', 'x')
    f.write('@echo off\nnet localgroup Administrators > admins.txt')
    f.close()
    subprocess.Popen([r'admin.bat'])
    time.sleep(1)
    with open('admins.txt') as t:
        content = t.read().splitlines()
    t.close()
    adminlist = []
    check = False
    for f in VariableName:
        for c in content:
            if f in c:
                userlist.append(True)
                check = True
        if not check:
            userlist.append(False)
            check = False
    os.remove('admin.bat')
    os.remove('admins.txt')
    return adminlist


def goodadmin():
    adminlists = admincheck(goodAdminKeywords)
    for idx, item in enumerate(adminlists):
        if adminlists[idx]:
            recordhit('Add Admin', goodAdminValue[idx], '')
        else:
            recordmiss('Users')


def badadmin():
    adminlists = admincheck(badAdminKeywords)
    for idx, item in enumerate(adminlists):
        if adminlists[idx]:
            recordmiss('Users')
        else:
            recordhit('Remove Admin', badAdminValue[idx], '')


def groupcheck(VariableName):
    f = open('group.bat', 'x')
    f.write('@echo off\nnet localgroup > groups.txt')
    f.close()
    subprocess.Popen([r'group.bat'])
    time.sleep(1)
    with open('groups.txt') as t:
        content = t.read().splitlines()
    t.close()
    grouplist = []
    check = False
    for f in VariableName:
        for c in content:
            if f in c:
                userlist.append(True)
                check = True
        if not check:
            userlist.append(False)
            check = False
    os.remove('group.bat')
    os.remove('groups.txt')
    return grouplist


def goodgroup():
    grouplists = groupcheck(goodGroupKeywords)
    for idx, item in enumerate(grouplists):
        if not grouplists[idx]:
            recordpenalty('goodGroup', goodGroupValue[idx], '')


def badgroup():
    grouplists = groupcheck(badGroupKeywords)
    for idx, item in enumerate(grouplists):
        if grouplists[idx]:
            recordmiss('Remove Group')
        else:
            recordhit('badGroup', badGroupValue[idx], '')


def useringroup():
    for idx, item in enumerate(userInGroupExtraKeywords):
        f = open('UserGroup.bat', 'x')
        f.write('@echo off\nnet localgroup' + userInGroupExtraKeywords[idx] + ' > UserGroups.txt\n')
        f.close()
        subprocess.Popen([r'UserGroup.bat'])
        time.sleep(1)
        with open('UserGroups.txt') as t:
            content = t.read().splitlines()
        t.close()
        for cont in content:
            if userInGroupKeywords[idx] in cont:
                recordhit('userInGroup', userInGroupValue[idx], '')
            else:
                recordmiss('User Not In Group')
        os.remove('UserGroup.bat')
        os.remove('UserGroups.txt')


def checkstartup():
    f = open('checkstartup.ps1', 'w+')
    f.write('Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location | Format-Table -AutoSize > startup.txt')
    f.close()
    runpowershell('checkstartup')
    f = open('startup.txt', 'r', encoding='utf-16-le')
    content = f.read().splitlines()
    f.close()
    for k in checkStartupKeywords:
        if k in content:
            recordhit('Program Removed from Startup', checkStartupValue, '')
        else:
            recordmiss('Startup')


def filecontainstext():
    f = open(fileContainsTextKeywords, 'r')
    content = f.read().splitlines()
    infile = False
    for c in content:
        if fileContainsTextExtraKeywords in c:
            infile = True
    if infile:
        recordhit(fileContainsTextMessage, fileContainsTextValue, '')
    else:
        recordmiss('File Does Not Contains Text')


def filenolongercontains():
    f = open(fileNoLongerContainsKeywords, 'r')
    content = f.read().splitlines()
    infile = False;
    for c in content:
        if fileNoLongerContainsExtraKeywords in c:
            infile = True
    if not infile:
        recordhit(fileNoLongerContainsMessage, fileNoLongerContainsValue, '')
    else:
        recordmiss('File Still Contains Text')


def services():
    m = open('getServices.ps1', 'w+')
    m.write('Get-Service | Select-Object Name,status,startType | Format-Table -AutoSize > services.txt')
    m.close()
    runpowershell('getServices')
    p = open('services.txt', 'r', encoding='utf-16-le')
    content = p.read().splitlines()
    p.close()
    for c in content:
        for bs in badServiceKeywords:
            if bs in c:
                if 'Disabled' in c and 'Stopped' in c:
                    recordhit('Disabled ' + bs, badServiceValue, '')
                else:
                    recordmiss('Service')
        for i in range(len(goodServiceKeywords)):
            if goodServiceKeywords[i] in c:
                if goodServiceExtraKeywords[i] in c and goodServiceMessage[i] in c:
                    recordhit('Configured ' + goodServiceKeywords[i] + " service correctly", goodServiceValue, '')
                else:
                    recordmiss('Service')
    if os.path.exists('getServices.ps1'):
        os.remove('getServices.ps1')
    if os.path.exists('services.txt'):
        os.remove('services.txt')


def programs(option):
    m = open('getPrograms.ps1', 'w+')
    m.write('Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table �AutoSize > programs.txt')
    m.close()
    runpowershell('getPrograms')
    k = open('programs.txt', 'r', encoding='utf-16-le')
    content = k.read().splitlines()
    k.close()
    if option == 'goodProgram':
        for gp in goodProgramKeywords:
            installed = False
            for c in content:
                if gp in c:
                    installed = True
            if installed:
                recordhit('Good program installed', goodProgramValue, '')
            else:
                recordmiss('Program')
    if option == 'badProgram':
        for bp in badProgramKeywords:
            installed = False
            for c in content:
                if bp in c:
                    installed = True
            if not installed:
                recordhit('Bad program uninstalled', badProgramValue, '')
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
    runpowershell('getSecurity')
    z = open('security.txt', 'r', encoding='utf-16-le')
    content = z.read().splitlines()
    z.close()
    protected = True
    for c in content:
        for p in protections:
            if (p in c) and ('False' in c):
                protected = False
    if protected:
        recordhit('Virus & threat protection enabled', antiVirusValue, '')
    else:
        recordmiss('Virus & threat protection')
    if os.path.exists('getSecurity.ps1'):
        os.remove('getSecurity.ps1')
    if os.path.exists('security.txt'):
        os.remove('security.txt')


def badfile():
    for idx, item in enumerate(badFileKeywords):
        f = open('badfile.bat', 'x')
        f.write('@echo off\nif EXIST "' + badFileKeywords[idx] + '" echo y > check.txt\nif NOT EXIST "' + badFileKeywords[idx] + '" echo n > check.txt')
        f.close()
        subprocess.Popen([r'badfile.bat'])
        time.sleep(20)
        with open('check.txt') as t:
            if 'n' in t.read():
                recordhit('badFile', badFileValue[idx], '')
            else:
                recordmiss('Remove bad file')
        t.close()
        os.remove('badfile.bat')
        os.remove('check.txt')


def usermanagement():
    writetohtml(('<H3>USER MANAGEMENT</H3>'))
    if goodUser:
        gooduser()
    if badUser:
        baduser()
    if newUser:
        newuser()
    if changePassword:
        '''changepassword()'''
    if goodAdmin:
        goodadmin()
    if badAdmin:
        badadmin()
    if goodGroup:
        goodgroup()
    if badGroup:
        badgroup()
    if userInGroup:
        useringroup()


def securitypolicies():
    writetohtml(('<H3>SECURITY POLICIES</H3>'))
    if disableGuest:
        disableguest()
    if disableAdmin:
        disableadmin()
    if checkFirewall:
        checkfirewall()
    if minPassAge:
        localgrouppolicy('minPassAge')
    if maxPassAge:
        localgrouppolicy('maxPassAge')
    if maxLoginTries:
        localgrouppolicy('maxLoginTries')
    if checkPassLength:
        localgrouppolicy('checkPassLength')
    if checkPassHist:
        localgrouppolicy('checkPassHist')
    if checkPassCompx:
        localgrouppolicy('checkPassCompx')
    if requireCTRL_ALT_DEL:
        localgrouppolicy('requireCTRL_ALT_DEL')
    if dontDisplayLastUser:
        localgrouppolicy('dontDisplayLastUser')
    if updateAutoInstall:
        '''updateautoinstall()'''


def programmanagement():
    writetohtml(('<H3>PROGRAMS</H3>'))
    if goodProgram:
        programs('goodProgram')
    if badProgram:
        programs('badProgram')
    if goodService:
        '''goodservice()'''
    # if badService:
    # badservice()


def filemanagement():
    writetohtml(('<H3>FILE MANAGEMENT</H3>'))
    if forensicQuestion:
        forensicquestion()
    if badFile:
        badfile()
    if checkHosts:
        '''checkhosts()'''
    if fileContainsText:
        filecontainstext()
    if fileNoLongerContains:
        filenolongercontains()


def miscpoints():
    writetohtml(('<H3>MISCELLANEOUS</H3>'))
    if checkStartup:
        checkstartup()
    if taskScheduler:
        '''taskscheduler()'''
    if antivirus:
        antivirus()


# --------- Main Loop ---------#

checkrunas()
drawhead()
usermanagement()
securitypolicies()
filemanagement()
miscpoints()
scorecheck()
drawtail()
time.sleep(60)

# TODO add Functions:
#  changepassword
#  updateautoinstall
#  goodservice
#  checkhosts
#  taskscheduler
