import ctypes, os, sys, subprocess
import win32com.client
import fileinput

Desktop = 'B:/Users/Shaun/Desktop/'
silentMiss = 'y'
FTPServer = 'y'
forensicsPath1 = 'B:/Users/Shaun/Desktop/Question1.txt'
forensicsAnswer1 = 'gb)'
checkForensicsQuestion1Value = '5'
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

if ctypes.windll.shell32.IsUserAnAdmin() == 0:
    print("You are not admin")
    exit()

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

def recordMiss(name, points):
    global totalPoints
    global totalVuln
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
    if totalPoints < prePoints:
        prePoints = totalPoints
# Option Check
