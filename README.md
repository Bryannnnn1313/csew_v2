# CSEW
## Cyberpatriot Scoring Engine: Windows

CSEW is a scoring engine written in Python for scoring Windows CyberPatriot-like image. It is configured by adding scoring options into the save_data.db and running the scoringEngine executable.

## Scorable Actions
### Gaining Points
- Disable Guest Account
- Disable Administrator Account
- Add user to admin group
- Remove user from admin group
- Add user per the ReadMe
- Remove user per the ReadMe
- Add user to a group per the ReamMe
- Remove user to a group per the ReadMe
- Turn on Domain Firewall
- Turn on Private Firewall
- Turn on Public Firewall
- Give Points if Port 'X' is open
- Give Points if Port 'X' is closed
- Enable 'Disable Do Not Require CTRL_ALT_DEL'
- Enable 'Don't Display Last User'
- Enable a minimum password age of at least 30 days
- Enable a maximum password age of at least 60 days
- Enable a minimum password length between 10-20 characters
- Enable maximum Login tries between 5-10 attempts
- Enable lockout duration to 30 minutes
- Enable louckout reset duration to 30 minutes
- Enable password history to be between 5-10 passwords
- Enable password complexity
- Disable reversible password Encryption
- Enable audit account login 
- Enable audit account management
- Enable audit directory settings access
- Enable audit events
- Enable audit access
- Enable audit policy change
- Enable audit privilege use
- Enable audit process tracking
- Enable audit system events
- Installing programs per ReadMe
- Removing programs per ReadMe
- Editing a service per ReadMe
- Answering the Forencics Questions
- Removing a bad file
- Adding text to a file
- Removing text from a file
-  
### Losing Points
- Deleting "good" users*
- Editing a necessary service*
- removing critical programs
### Notes
- The checking for remove.add text flags check for a complete string existence. If you want a series of strings, it is best to break them into individual flags. a single letter can interfere with the text input.
- The point removal will neutralize if the flag is fixed if points is granted for maintaining flag.
  	ie: Deleting 'John' removes 5 points. Adding him back will return 4 points at a net gain of -1 if points are granted for keeping 'John'. If points are not granted for maintaining 'John' then there is no points returned for adding the user back.

CSEL can be run with "silent misses" which simulates a CyberPatriot round where you have no idea where the points are until you earn them. It can also be run with the silent misses turned off which is helpful when you are debugging or when you have very inexperienced students who might benefit from the help. This mode gives you a general idea where the points are missing. CSEL can also create a scoreboard report that will be placed on the desktop, granting the user access to points gained or lost. 
##Install 
## CLI
1. Set up your image and put your vulnerabilities in place.
3. Clone into CSEL by typing: sudo git clone https://github.com/Bryannnnn1313/CSELv2/configurator.git
4. Run '''bash
sudo run ./configurator
''' to start the UI. 
6. Once you have checked all the flags and click run, you can (and should) delete the configurator executable.

## GUI
1. To install download the Following
**Important Note**: Your students _will_ be able to see the vulnerabilities if you leave the CSEL folder behind or if they cat the executable file that is created in /etc/CYBERPATRIOT. I tell my students where the file is and that they should stay away from it. It is practice, after all.

## How to use 
### Landing Page
![Landing Page](https://github.com/Bryannnnn1313/CSELv2/blob/master/Config%201st%20Screen.png)
   - Commit will launch the ScoringEngine and force close the configurator
   - Checking Silent Miss allows makes the missed points invisible in the Score Report
   - Server Mode allows you set up an FTP server so that the students can compete with each other(WIP)
   - Total Points displays the total points available to the students
   - Total Vulnerabilities shows you the count of Vulnerabilities
### Category Pages
![Category Page](https://github.com/Bryannnnn1313/CSELv2/blob/master/Config%20Account%20Management.png)
   - The Vulnerabilities will be labeled on the left
   - The center describes the Vulnerabilities
   - If there is a Modify tab, there vulnerability may take more than 1 flag and and may need more input
### Modify Page
![Modify Page](https://github.com/Bryannnnn1313/CSELv2/blob/master/Config%20Modify.png)
   - The points will be on the left
   - Center will be any additional inputs needed, A drop down is available, but manual input is possible.
   - If flag is no longer needed, then you can remove it, if you don't it will be added into the database.
### Report Page
![Report Generator](https://github.com/Bryannnnn1313/CSELv2/blob/master/Report%20Generation.png)
   - This page creates an html page with every flag to keep on hand.
### Score Report
![Score Report](https://github.com/Bryannnnn1313/CSELv2/blob/master/ScoreReport.png)
   - This page is created when the the 'Commit' is pressed.
