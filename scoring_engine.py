import ctypes, os, sys, subprocess, time
import win32com.client
import fileinput
import balloontip

Desktop = 'B:/Users/Shaun/Desktop/'
silentMiss = 'y'
FTPServer = 'y'
forensicCount = []
forensicsPath1 = 'B:/Users/Shaun/Desktop/Question1.txt'
forensicAnswer = 'gb)'
forensicValue = '5'
disableGuest = 'y'
disableGuestValue = '5'
disableAdministrator = 'y'
disableAdministratorValue = '7'
requireCTRL_ALT_DEL = 'y'
requireCTRL_ALT_DELValue = '7'
checkFirewall = 'y'
checkFirewallValue = '7'
minPassAge = 'y'
minPassAgeValue = '7'
maxPassAge = 'y'
maxPassAgeValue = '7'
maxLoginTries = 'y'
maxLoginTriesValue = '7'
checkPassHist = 'y'
checkPassHistValue = '7'
checkPassCompx = 'y'
checkPassCompxValue = '7'
updateAutoInstall = 'y'
updateAutoInstallValue = '6'
index = 'C:/CyberPatriot/'

# Program Base Variables
posPoints = 0
posVuln = 0
totalPoints = 0
totalVuln = 0
prePoints = 0
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

    f = open('user.txt','r', encoding='utf-16-le')
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

def checkFirewall():
    f = open ('firewall.bat', 'x')
    f.write('@echo off\nnetsh advfirewall show private > status.bat\nnetsh advfirewall show public >> status.bat')
    f.close()
    subprocess.call('./firewall.bat')
    with open('status.txt') as t:
            content = t.read().splitlines()
    t.close()
    statuson = 'true';
    for cont in content:
        if cont != '':
            status = cont.split('                       ')
            if status[1]!='ON':
                statuson = 'false'
    if statuson == 'true':
        recordHit('checkFirewall',checkFirewallValue,'')
    else:
        recordMiss('checkFirewall')
    os.remove('firewall.bat')
    os.remove('status.txt')