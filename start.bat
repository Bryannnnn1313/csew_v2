python.exe configurator.py

pyinstaller -y -F -i "C:/Users/CyberPatriot/Desktop/Scoring Engine/scoring_engine_logo_windows_icon_5TN_icon.ico" --add-data "C:/Users/CyberPatriot/Desktop/Scoring Engine/balloontip.py";"." --add-data "C:/Users/CyberPatriot/Desktop/Scoring Engine/admin_test.py";"." "C:/Users/CyberPatriot/Desktop/Scoring Engine/configurator.py"

pyinstaller -y -F -w -i "C:/Users/CyberPatriot/Desktop/scoring_engine_logo_windows_icon_5TN_icon.ico" --add-data "C:/Users/CyberPatriot/Desktop/balloontip.py";"." --add-data "C:/Users/CyberPatriot/Desktop/admin_test.py";"." "C:/Users/CyberPatriot/Desktop/scoring_engine.py"


    balloonPath = os.path.abspath('Scoring_engine/installer.py')
    scoringPath = os.path.abspath('Scoring_engine/configurator.py')
    adminPath = os.path.abspath('Scoring_engine/admin_test.py')
    iconPath = os.path.abspath('Scoring_engine/scoring_engine_logo_windows_icon_5TN_icon.ico')
    command = 'pyinstaller -y -F -i "' + iconPath + '" --add-data "' + balloonPath + '";"." --add-data "' + adminPath + '";"." "' + scoringPath + '"'
    installer.convert(command)
    exit()