import subprocess
import win32com.client
import os
import time
import balloontip
import admin_test

##OPTIONVARIABLES##


forensicQuestion = False
forensicCount = [2]
forensicAnswer = ['w']
forensicValue = [10]


# Program Base Variables
posPoints = 0
posVuln = 0
totalPoints = 0
totalVuln = 0
prePoints = 0
Desktop = vulnDict['Desktop']
index = 'C:/CyberPatriot/'
scoreIndex = index + 'ScoreReport.html'


# Scoring Report creation
def drawhead():
    f = open(scoreIndex, 'w+')
    f.write('<!doctype html><html><head><title>CSEL Score Report</title><meta http-equiv="refresh" content="30"></head><body style="background-color:powderblue;">''\n')
    f.write('<table align="center" cellpadding="10"><tr><td><img src="C:/CyberPatriot/iguana.png"></td><td><img src="C:/CyberPatriot/logo.png"></td><td><div align="center"><H2>Cyberpatriot Scoring Engine:Windows v2.0</H2></div></td><td><img ' 
            'src="C:/CyberPatriot/SoCalCCCC.png"></td><td><img src="C:/CyberPatriot/CCC_logo.png"></td></tr></table><br><H2>Your Score: #TotalScore#/#PossiblePoints#</H2><H2>Vulnerabilities: #TotalVuln#/#PossibleVuln#</H2><hr>')
    f.close()


def recordhit(name, points, message):
    global totalPoints, posPoints
    global totalVuln, posVuln
    writetohtml(('<p style="color:green">' + name + '(' + str(points) + 'points)</p>'))
    totalPoints += int(points)
    posPoints += int(points)
    totalVuln += 1
    posVuln += 1


def recordmiss(name, points):
    global posPoints, posVuln
    posPoints += int(points)
    posVuln += 1
    if not vulnDict['silentMiss']['enable']:
        writetohtml(('<p style="color:red">MISS ' + name + 'Issue</p>'))


def recordpenalty(name, points, message):
    global totalPoints
    writetohtml(('<p style="color:red">' + name + '(' + str(points) + 'points)</p>'))
    totalPoints -= int(points)


def drawtail():
    writetohtml(('<hr><div align="center"><br>Developed by Josh Davis<br><b>Eastern Oklahoma County Technology Center/Coastline Collage</b><br>Feedback welcome: <a href="mailto:jdavis@eoctech.edu?Subject=CSEL" target="_top">jdavis@eoctech.edu</a><br>Modified/Updated by Shaun Martin</br><b>Coastline Collage</b><br>Feedback '
                 'welcome: <a href="mailto:smartin94@student.cccd.edu?Subject=CSEL Scoring Engine" target="_top">smartin94@student.cccd.edu</a></div>'))
    print(str(totalPoints) + ' / ' + str(posPoints) + '\n' + str(totalVuln) + ' / ' + str(posVuln))
    replacesec(scoreIndex, '#TotalScore#', str(totalPoints))
    replacesec(scoreIndex, '#PossiblePoints#', str(posPoints))
    replacesec(scoreIndex, '#TotalVuln#', str(totalVuln))
    replacesec(scoreIndex, '#PossibleVuln#', str(posVuln))

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
def checkrunas():
    if not admin_test.isUserAdmin():
        w.ShowWindow('Admin Needed', 'Please make sure the scoring engine is running as admin.')
        exit(admin_test.runAsAdmin())


def scorecheck():
    global totalPoints
    global prePoints
    if totalPoints > prePoints:
        prePoints = totalPoints
        w.ShowWindow('Score Update', 'You gained points!!')
    if totalPoints < prePoints:
        prePoints = totalPoints
        w.ShowWindow('Score Update', 'You lost points!!')


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


def replacesec(loc, search, replace):
    lines = []
    with open(loc) as file:
        for line in file:
            line = line.replace(search, replace)
            lines.append(line)
    with open(loc, 'w') as file:
        for line in lines:
            file.write(line)


# Option Check
def forensicquestion():
    for fq in vulnDict['forensics']['count']:
        path = Desktop + 'Question' + fq + '.txt'
        name = 'Forensic Question', fq
        f = open(path, 'r')
        content = f.read().splitlines()
        for c in content:
            if 'ANSWER:' in c:
                if vulnDict['forensics']['answer'][fq] in c:
                    recordhit(name, vulnDict['forensics']['points'][fq], '')
                else:
                    recordmiss(name, vulnDict['forensics']['points'][fq])


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
                recordhit('Disable Guest', vulnDict['disableGuest']['points'][0], '')
                os.remove('user.txt')
            else:
                recordmiss('Disable Guest', vulnDict['disableGuest']['points'][0])
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
                recordhit('Disable Admin', vulnDict['disableAdmin']['points'][0], '')
                os.remove('user.txt')
            else:
                recordmiss('Disable Admin', vulnDict['disableAdmin']['points'][0])
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
        recordhit('checkFirewall', vulnDict['checkFirewall']['points'][0], '')
    else:
        recordmiss('checkFirewall', vulnDict['checkFirewall']['points'][0])
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
                    recordhit('Minimum Password Age', vulnDict[option]['points'][0], '')
                else:
                    recordmiss('Password Policy', vulnDict[option]['points'][0])
    elif option == 'maxPassAge':
        for i in content:
            if 'MaximumPasswordAge' in i:
                if i.endswith('60'):
                    recordhit('Maximum Password Age', vulnDict[option]['points'][0], '')
                else:
                    recordmiss('Password Policy', vulnDict[option]['points'][0])
    elif option == 'maxLoginTries':
        for i in content:
            if 'LockoutBadCount' in i:
                if i.endswith('5'):
                    recordhit('Maximum Login Tries', vulnDict[option]['points'][0], '')
                else:
                    recordmiss('Account Policy', vulnDict[option]['points'][0])
    elif option == 'checkPassLength':
        for i in content:
            if 'MinimumPasswordLength' in i:
                if i.endswith('10'):
                    recordhit('Minimum Password Length', vulnDict[option]['points'][0], '')
                else:
                    recordmiss('Password Policy', vulnDict[option]['points'][0])
    elif option == 'checkPassHist':
        for i in content:
            if 'PasswordHistorySize' in i:
                if i.endswith('5'):
                    recordhit('Password History Size', vulnDict[option]['points'][0], '')
                else:
                    recordmiss('Password Policy', vulnDict[option]['points'][0])
    elif option == 'checkPassCompx':
        for i in content:
            if 'PasswordComplexity' in i:
                if i.endswith('1'):
                    recordhit('Password Complexity', vulnDict[option]['points'][0], '')
                else:
                    recordmiss('Password Policy', vulnDict[option]['points'][0])
    elif option == 'requireCTRL_ALT_DEL':
        for i in content:
            if 'DisableCAD' in i:
                if i.endswith('1'):
                    recordhit('Require CTRL + ALT + DEL', vulnDict[option]['points'][0], '')
                else:
                    recordmiss('Security Policy', vulnDict[option]['points'][0])
            else:
                recordmiss('Security Policy', vulnDict[option]['points'][0])
    elif option == 'DontDisplayLastUser':
        for i in content:
            if 'dontDisplayLastUserName' in i:
                if i.endswith('1'):
                    recordhit('Dont Display Last User Name', vulnDict[option]['points'][0], '')
                else:
                    recordmiss('Security Policy', vulnDict[option]['points'][0])
    os.remove('group-policy.txt')


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
    userlists = checkuser(vulnDict['goodUser']['keywords'])
    for idx, item in enumerate(userlists):
        if not userlists[idx]:
            recordpenalty('Removed User', vulnDict['goodUser']['points'][idx], '')


def baduser():
    userlists = checkuser(vulnDict['badUser']['keywords'])
    for idx, item in enumerate(userlists):
        if userlists[idx]:
            recordmiss('Users', vulnDict['badUser']['points'][idx])
        else:
            recordhit('Remove User', vulnDict['badUser']['points'][idx], '')


def newuser():
    userlists = checkuser(vulnDict['newUser']['keywords'])
    for idx, item in enumerate(userlists):
        if userlists[idx]:
            recordhit('Add User', vulnDict['newUser']['points'][idx], '')
        else:
            recordmiss('Users', vulnDict['newUser']['points'][idx])


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
                adminlist.append(True)
                check = True
        if not check:
            adminlist.append(False)
            check = False
    os.remove('admin.bat')
    os.remove('admins.txt')
    return adminlist


def goodadmin():
    adminlists = admincheck(vulnDict['goodAdmin']['keywords'])
    for idx, item in enumerate(adminlists):
        if adminlists[idx]:
            recordhit('Add Admin', vulnDict['goodAdmin']['points'][idx], '')
        else:
            recordmiss('Users', vulnDict['goodAdmin']['points'][idx])


def badadmin():
    adminlists = admincheck(vulnDict['badAdmin']['keywords'])
    for idx, item in enumerate(adminlists):
        if adminlists[idx]:
            recordmiss('Users', vulnDict['badAdmin']['points'][idx])
        else:
            recordhit('Removed Admin', vulnDict['badAdmin']['points'][idx], '')


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
                grouplist.append(True)
                check = True
        if not check:
            grouplist.append(False)
            check = False
    os.remove('group.bat')
    os.remove('groups.txt')
    return grouplist


def goodgroup():
    grouplists = groupcheck(vulnDict['goodGroup']['keywords'])
    for idx, item in enumerate(grouplists):
        if grouplists[idx]:
            recordhit('Add Group', vulnDict['goodGroup']['points'][idx], '')
        else:
            recordmiss('Users', vulnDict['goodGroup']['points'][idx])


def badgroup():
    grouplists = groupcheck(vulnDict['badGroup']['keywords'])
    for idx, item in enumerate(grouplists):
        if grouplists[idx]:
            recordmiss('Remove Group', vulnDict['badGroup']['points'][idx])
        else:
            recordhit('badGroup', vulnDict['badGroup']['points'][idx], '')


def useringroup():
    for idx, item in enumerate(vulnDict['userInGroup']['keywords']):
        f = open('UserGroup.bat', 'x')
        f.write('@echo off\nnet localgroup' + vulnDict['userInGroup']['keywords'][idx] + ' > UserGroups.txt\n')
        f.close()
        subprocess.Popen([r'UserGroup.bat'])
        time.sleep(1)
        with open('UserGroups.txt') as t:
            content = t.read().splitlines()
        t.close()
        for cont in content:
            if vulnDict['userInGroup']['keywords'][idx] in cont:
                recordhit('userInGroup', vulnDict['userInGroup']['points'][idx], '')
            else:
                recordmiss('User Not In Group', vulnDict['userInGroup']['points'][idx])
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
    for k in vulnDict['checkStartup']['keywords']:
        if k in content:
            recordhit('Program Removed from Startup', vulnDict['checkStartup']['points'][0], '')
        else:
            recordmiss('Startup', vulnDict['checkStartup']['points'][0])


def filecontainstext():
    for idx, item in enumerate(vulnDict['fileContainsText']['keywords']):
        f = open(vulnDict['fileContainsText']['keywords'][idx], 'r')
        content = f.read().splitlines()
        infile = False
        for c in content:
            if vulnDict['fileContainsText']['keywords'][idx] in c:
                infile = True
        if infile:
            recordhit(vulnDict['fileContainsText']['message'][idx], vulnDict['fileContainsText']['points'][idx], '')
        else:
            recordmiss('File Does Not Contains Text', vulnDict['fileContainsText']['points'][idx])


def filenolongercontains():
    for idx, item in enumerate(vulnDict['fileNoLongerContains']['keywords']):
        f = open(vulnDict['fileNoLongerContains']['keywords'][idx], 'r')
        content = f.read().splitlines()
        infile = False;
        for c in content:
            if vulnDict['fileNoLongerContains']['keywords'][idx] in c:
                infile = True
        if not infile:
            recordhit(vulnDict['fileNoLongerContains']['message'][idx], vulnDict['fileNoLongerContains']['points'][idx], '')
        else:
            recordmiss('File Still Contains Text', vulnDict['fileNoLongerContains']['points'][idx])


def services(option):
    m = open('getServices.ps1', 'w+')
    m.write('Get-Service | Select-Object Name,status,startType | Format-Table -AutoSize > services.txt')
    m.close()
    runpowershell('getServices')
    p = open('services.txt', 'r', encoding='utf-16-le')
    content = p.read().splitlines()
    p.close()
    for c in content:
        if option == 'badService':
            for idx, bs in vulnDict['badService']['keywords']:
                if bs in c:
                    if 'Disabled' in c and 'Stopped' in c:
                        recordhit('Disabled ' + bs, vulnDict['badService']['points'][idx], '')
                    else:
                        recordmiss('Service', vulnDict['badService']['points'][idx])
        if option == 'goodService':
            for i in range(len(vulnDict['goodService']['keywords'])):
                if vulnDict['goodService']['keywords'][i] in c:
                    if vulnDict['goodService']['extrakeywords'][i] in c and vulnDict['goodService']['message'][i] in c:
                        recordhit('Configured ' + vulnDict['goodService']['keywords'][i] + " service correctly", vulnDict['goodService']['points'][i], '')
                    else:
                        recordmiss('Service', vulnDict['goodService']['points'][i])
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
        for idx, gp in vulnDict['goodProgram']['keywords']:
            installed = False
            for c in content:
                if gp in c:
                    installed = True
            if installed:
                recordhit('Good program installed', vulnDict['goodProgram']['points'][idx], '')
            else:
                recordmiss('Program', vulnDict['goodProgram']['points'][idx])
    if option == 'badProgram':
        for idx, bp in vulnDict['badProgram']['keywords']:
            installed = False
            for c in content:
                if bp in c:
                    installed = True
            if not installed:
                recordhit('Bad program uninstalled', vulnDict['badProgram']['points'][idx], '')
            else:
                recordmiss('Program', vulnDict['badProgram']['points'][idx])
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
        recordhit('Virus & threat protection enabled', vulnDict['antiVirus']['points'][0], '')
    else:
        recordmiss('Virus & threat protection', vulnDict['antiVirus']['points'][0])
    if os.path.exists('getSecurity.ps1'):
        os.remove('getSecurity.ps1')
    if os.path.exists('security.txt'):
        os.remove('security.txt')


def badfile():
    for idx, item in enumerate(vulnDict['badFile']['keywords']):
        f = open('badfile.bat', 'x')
        f.write('@echo off\nif EXIST "' + vulnDict['badFile']['keywords'][idx] + '" echo y > check.txt\nif NOT EXIST "' + vulnDict['badFile']['keywords'][idx] + '" echo n > check.txt')
        f.close()
        subprocess.Popen([r'badfile.bat'])
        time.sleep(1)
        with open('check.txt') as t:
            if 'n' in t.read():
                recordhit('badFile', vulnDict['badFile']['points'][idx], '')
            else:
                recordmiss('Remove bad file', vulnDict['badFile']['points'][idx])
        t.close()
        os.remove('badfile.bat')
        os.remove('check.txt')


def usermanagement():
    writetohtml(('<H3>USER MANAGEMENT</H3>'))
    if vulnDict['goodUser']['enable']:
        gooduser()
    if vulnDict['badUser']['enable']:
        baduser()
    if vulnDict['newUser']['enable']:
        newuser()
    if vulnDict['changePassword']['enable']:
        '''changepassword()'''
    if vulnDict['goodAdmin']['enable']:
        goodadmin()
    if vulnDict['badAdmin']['enable']:
        badadmin()
    if vulnDict['goodGroup']['enable']:
        goodgroup()
    if vulnDict['badGroup']['enable']:
        badgroup()
    if vulnDict['userInGroup']['enable']:
        useringroup()


def securitypolicies():
    writetohtml(('<H3>SECURITY POLICIES</H3>'))
    if vulnDict['disableGuest']['enable']:
        disableguest()
    if vulnDict['disableAdmin']['enable']:
        disableadmin()
    if vulnDict['checkFirewall']['enable']:
        checkfirewall()
    if vulnDict['minPassAge']['enable']:
        localgrouppolicy('minPassAge')
    if vulnDict['maxPassAge']['enable']:
        localgrouppolicy('maxPassAge')
    if vulnDict['maxLoginTries']['enable']:
        localgrouppolicy('maxLoginTries')
    if vulnDict['checkPassLength']['enable']:
        localgrouppolicy('checkPassLength')
    if vulnDict['checkPassHist']['enable']:
        localgrouppolicy('checkPassHist')
    if vulnDict['checkPassCompx']['enable']:
        localgrouppolicy('checkPassCompx')
    if vulnDict['requireCTRL_ALT_DEL']['enable']:
        localgrouppolicy('requireCTRL_ALT_DEL')
    if vulnDict['dontDisplayLastUser']['enable']:
        localgrouppolicy('dontDisplayLastUser')
    if vulnDict['updateAutoInstall']['enable']:
        '''updateautoinstall()'''


def programmanagement():
    writetohtml(('<H3>PROGRAMS</H3>'))
    if vulnDict['goodProgram']['enable']:
        programs('goodProgram')
    if vulnDict['badProgram']['enable']:
        programs('badProgram')
    if vulnDict['goodService']['enable']:
        services('goodservice')
    if vulnDict['badService']['enable']:
        services('badservice')


def filemanagement():
    writetohtml(('<H3>FILE MANAGEMENT</H3>'))
    if vulnDict['forensics']['enable']:
        forensicquestion()
    if vulnDict['badFile']['enable']:
        badfile()
    if vulnDict['checkHosts']['enable']:
        '''checkhosts()'''
    if vulnDict['fileContainsText']['enable']:
        filecontainstext()
    if vulnDict['fileNoLongerContains']['enable']:
        filenolongercontains()


def miscpoints():
    writetohtml(('<H3>MISCELLANEOUS</H3>'))
    if vulnDict['checkStartup']['enable']:
        checkstartup()
    if vulnDict['taskScheduler']['enable']:
        '''taskscheduler()'''
    if vulnDict['antiVirus']['enable']:
        antivirus()


# --------- Main Loop ---------#
w = balloontip.WindowsBalloonTip()
while True:
    checkrunas()
    posPoints = 0
    posVuln = 0
    totalPoints = 0
    totalVuln = 0
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
#  checkhosts
#  taskscheduler
# TODO add points to all missess and add total