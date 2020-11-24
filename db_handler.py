import sys, os

from sqlalchemy import orm
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy as sa

from tkinter import StringVar, IntVar

try:
    # PyInstaller creates a temp folder and stores path in _MEIPASS
    base_path = sys._MEIPASS
    passExist = True
    base_path = 'C:/CyberPatriot/'
    if not os.path.exists(base_path):
        os.makedirs(base_path)
except Exception:
    base_path = os.path.abspath(".")
    passExist = False
db = os.path.join(base_path, 'save_data.db')

base = declarative_base()
engine = sa.create_engine('sqlite:///' + db)
base.metadata.bind = engine
session = orm.scoped_session(orm.sessionmaker())(bind=engine)


class SettingsModel(base):
    __tablename__ = "Settings"
    id = sa.Column(sa.Integer, primary_key=True)
    style = sa.Column(sa.String(128), nullable=False, default="black")
    desktop = sa.Column(sa.Text, nullable=False, default=" ")
    silent_mode = sa.Column(sa.Boolean, nullable=False, default=False)
    server_mode = sa.Column(sa.Boolean, nullable=False, default=False)
    server_name = sa.Column(sa.String(255))
    server_user = sa.Column(sa.String(255))
    server_pass = sa.Column(sa.String(128))
    tally_points = sa.Column(sa.Integer, nullable=False, default=0)
    tally_vuln = sa.Column(sa.Integer, nullable=False, default=0)
    current_points = sa.Column(sa.Integer, nullable=False, default=0)
    current_vuln = sa.Column(sa.Integer, nullable=False, default=0)

    def __init__(self, **kwargs):
        super(SettingsModel, self).__init__(**kwargs)


class Settings:
    def __init__(self):
        if session.query(SettingsModel).scalar() is None:
            self.settings = SettingsModel()
            session.add(self.settings)
            session.commit()
        else:
            self.settings = session.query(SettingsModel).one()

    def get_settings(self, config=True):
        if config:
            return {"Style": StringVar(value=self.settings.style), "Desktop": StringVar(value=self.settings.desktop), "Silent Mode": StringVar(value=self.settings.silent_mode), "Server Mode": StringVar(value=self.settings.server_mode), "Server Name": StringVar(value=self.settings.server_name), "Server User": StringVar(value=self.settings.server_user), "Server Password": StringVar(value=self.settings.server_pass), "Tally Points": StringVar(value=self.settings.tally_points), "Tally Vulnerabilities": StringVar(value=self.settings.tally_vuln)}
        else:
            return {"Desktop": self.settings.desktop, "Silent Mode": self.settings.silent_mode, "Server Mode": self.settings.server_mode, "Server Name": self.settings.server_name, "Server User": self.settings.server_user, "Server Password": self.settings.server_pass, "Tally Points": self.settings.tally_points, "Tally Vulnerabilities": self.settings.tally_vuln, "Current Points": self.settings.current_points, "Current Vulnerabilities": self.settings.current_vuln}

    def update_table(self, entry):
        self.settings.style = entry["Style"].get()
        self.settings.desktop = entry["Desktop"].get()
        self.settings.silent_mode = (True if int(entry["Silent Mode"].get()) == 1 else False)
        self.settings.server_mode = (True if int(entry["Server Mode"].get()) == 1 else False)
        self.settings.server_name = entry["Server Name"].get()
        self.settings.server_user = entry["Server User"].get()
        self.settings.server_pass = entry["Server Password"].get()
        self.settings.tally_points = entry["Tally Points"].get()
        self.settings.tally_vuln = entry["Tally Vulnerabilities"].get()
        session.commit()

    def update_score(self, entry):
        self.settings.current_points = entry["Current Points"]
        self.settings.current_vuln = entry["Current Vulnerabilities"]


class CategoryModels(base):
    __tablename__ = "Vulnerability Categories"
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String(128), nullable=False, unique=True)
    description = sa.Column(sa.Text, nullable=False)

    def __init__(self, **kwargs):
        super(CategoryModels, self).__init__(**kwargs)


class Categories:
    categories = {
        "Account Management": "This section is for scoring user policies. The options that will take multiple test points can be setup by clicking the `Modify` button. Once the `Modify` button is clicked that option will automatically be enabled. Make sure the option is enabled and the points are set for the options you want scored.",
        "Local Policy": "This section is for scoring Local Security Policies. Each option has a defined range that they be testing listed in their description. Make sure the option is enabled and the points are set for the options you want scored.",
        "Program Management": "This section is for scoring program manipulation. The options that will take multiple test points can be setup by clicking the `Modify` button. Once the `Modify` button is clicked that option will automatically be enabled. Make sure the option is enabled and the points are set for the options you want scored.",
        "File Management": "This section is for scoring file manipulation. The options that will take multiple test points can be setup by clicking the `Modify` button. Once the `Modify` button is clicked that option will automatically be enabled. Make sure the option is enabled and the points are set for the options you want scored.",
        "Miscellaneous": "This section is for scoring the options that do not fit into and of the other or multiple catagories. The options that will take multiple test points can be setup by clicking the `Modify` button. Once the `Modify` button is clicked that option will automatically be enabled. Make sure the option is enabled and the points are set for the options you want scored."
    }

    def __init__(self):
        loaded_categories = []
        for cat in session.query(CategoryModels):
            loaded_categories.append(cat.name)
        for cat in self.categories:
            if cat not in loaded_categories:
                name = cat
                description = self.categories[cat]
                category = CategoryModels(name=name, description=description)
                session.add(category)
        session.commit()

    def get_categories(self):
        return session.query(CategoryModels)


class VulnerabilityTemplateModel(base):
    __tablename__ = "Vulnerability Template"
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String(128), nullable=False, unique=True)
    category = sa.Column(sa.Integer, sa.ForeignKey("Vulnerability Categories.id"))
    definition = sa.Column(sa.Text, nullable=False)
    description = sa.Column(sa.Text)
    checks = sa.Column(sa.Text)

    def __init__(self, **kwargs):
        super(VulnerabilityTemplateModel, self).__init__(**kwargs)


base.metadata.create_all()


class OptionTables:
    models = {}
    checks_list = {}

    def __init__(self, vulnerability_templates=None):
        loaded_vulns_templates = []
        for vuln_templates in session.query(VulnerabilityTemplateModel):
            loaded_vulns_templates.append(vuln_templates.name)
        if vulnerability_templates != None:
            for name in vulnerability_templates:
                if name not in loaded_vulns_templates:
                    category = session.query(CategoryModels).filter_by(name=vulnerability_templates[name]["Category"]).one().id
                    definition = vulnerability_templates[name]["Definition"]
                    description = vulnerability_templates[name]["Description"] if "Description" in vulnerability_templates[name] else None
                    checks = vulnerability_templates[name]["Checks"] if "Checks" in vulnerability_templates[name] else None
                    vuln_template = VulnerabilityTemplateModel(name=name, category=category, definition=definition, description=description, checks=checks)
                    session.add(vuln_template)
        session.commit()

    def initialize_option_table(self):
        for vuln_template in session.query(VulnerabilityTemplateModel):
            name = vuln_template.name
            checks_list = vuln_template.checks.split(',') if vuln_template.checks is not None else []
            checks_dict = {}
            self.checks_list.update({name: {}})
            for checks in checks_list:
                chk = checks.split(':')
                checks_dict.update({chk[0]: chk[1]})
                self.checks_list[name].update({chk[0]: chk[0]})
            create_option_table(name, checks_dict, self.models)
        base.metadata.create_all()

        for name in self.models:
            try:
                if session.query(self.models[name]).scalar() is None:
                    vuln_base = self.models[name]()
                    session.add(vuln_base)
            except:
                pass
        session.commit()

    def get_option_template(self, vulnerability):
        return session.query(VulnerabilityTemplateModel).filter_by(name=vulnerability).one()

    def get_option_template_by_category(self, category):
        return session.query(VulnerabilityTemplateModel).filter_by(category=category)

    def get_option_table(self, vulnerability, config=True):
        vuln_dict = {}
        for vuln in session.query(self.models[vulnerability]):
            if config:
                vuln_dict.update({vuln.id: {"Enabled": IntVar(value=vuln.Enabled), "Points": IntVar(value=vuln.Points), "Checks": {}}})
                for checks in vars(vuln):
                    if not checks.startswith("_") and checks != "id" and checks != "Enabled" and checks != "Points":
                        if type(vars(vuln)[checks]) == int or type(vars(vuln)[checks]) == bool:
                            vuln_dict[vuln.id]["Checks"].update({checks: IntVar(value=vars(vuln)[checks])})
                        else:
                            vuln_dict[vuln.id]["Checks"].update({checks: StringVar(value=vars(vuln)[checks])})
            else:
                vuln_dict.update({vuln.id: {"Enabled": vuln.Enabled, "Points": vuln.Points}})
                for checks in vars(vuln):
                    if not checks.startswith("_") and checks != "id" and checks != "Enabled" and checks != "Points":
                        vuln_dict[vuln.id].update({checks: vars(vuln)[checks]})
        return vuln_dict

    def add_to_table(self, vulnerability, **kwargs):
        vuln = self.models[vulnerability](**kwargs)
        session.add(vuln)
        session.commit()
        return vuln

    def update_table(self, vulnerability, entry):
        for vuln in session.query(self.models[vulnerability]):
            vuln_update = {"Enabled": (True if int(entry[vuln.id]["Enabled"].get()) == 1 else False), "Points": entry[vuln.id]["Points"].get()}
            for checks in vars(vuln):
                if not checks.startswith("_") and checks != "id" and checks != "Enabled" and checks != "Points":
                    vuln_update.update({checks: entry[vuln.id]["Checks"][checks].get()})
            session.query(self.models[vulnerability]).filter_by(id=vuln.id).update(vuln_update)
            session.commit()


    def remove_from_table(self, vulnerability, vuln_id):
        vuln = session.query(self.models[vulnerability]).filter_by(id=vuln_id).one()
        session.delete(vuln)
        session.commit()


def create_option_table(name, option_categories, option_models):
    attr_dict = {'__tablename__': name,
                 'id': sa.Column(sa.Integer, primary_key=True),
                 'Enabled': sa.Column(sa.Boolean, nullable=False, default=False),
                 'Points': sa.Column(sa.Integer, nullable=False, default=0)}
    for cat in option_categories:
        if option_categories[cat] == "Int":
            attr_dict.update({cat: sa.Column(sa.Integer, default=0)})
        elif option_categories[cat] == "Str":
            attr_dict.update({cat: sa.Column(sa.Text, default="")})

    option_models.update({name: type(name, (base,), attr_dict)})


'''
vulnerability_template = {"Forensic": {"Definition": 'This section is for scoring forensic questions. To score a forensic question be sure to check "Enable". To add more questions press the "Add" button. To remove questions press the "X" button next to the question you want to remove. \nDo note that the answers are case sensitive.',
                                       "Checks": 'Question:Str,Answers:Str,Location:Str',
                                       "Category": 'Forensic'},
                          "Disable Guest": {"Definition": 'Enable this to score the competitor for disabling the Guest account.',
                                            "Category": 'Account Management'},
                          "Disable Admin": {"Definition": 'Enable this to score the competitor for disabling the Administrator account.',
                                            "Category": 'Account Management'},
                          "Critical Users": {"Definition": 'Enable this to penalize the competitor for removing a user.',
                                             "Description": 'This will penalize the competitor for removing a user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can Category the user name in the field. Otherwise use the drop down to select a user. Do not make the point value negative.',
                                             "Checks": 'User Name:Str',
                                             "Category": 'Account Management'},
                          "Add Admin": {"Definition": 'Enable this to score the competitor for elevating a user to an Administrator.',
                                        "Description": 'This will score the competitor for elevating a user to an Administrator. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can Category the user name in the field. Otherwise use the drop down to select a user.',
                                        "Checks": 'User Name:Str',
                                        "Category": 'Account Management'},
                          "Remove Admin": {"Definition": 'Enable this to score the competitor for demoting a user to Standard user.',
                                           "Description": 'This will score the competitor for demoting a user to Standard user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can Category the user name in the field. Otherwise use the drop down to select a user.',
                                           "Checks": 'User Name:Str',
                                           "Category": 'Account Management'},
                          "Add User": {"Definition": 'Enable this to score the competitor for adding a user.',
                                       "Description": 'This will score the competitor for adding a user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can Category the user name in the field. Otherwise use the drop down to select a user.',
                                       "Checks": 'User Name:Str',
                                       "Category": 'Account Management'},
                          "Remove User": {"Definition": 'Enable this to score the competitor for removing a user.',
                                          "Description": 'This will score the competitor for removing a user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can Category the user name in the field. Otherwise use the drop down to select a user.',
                                          "Checks": 'User Name:Str',
                                          "Category": 'Account Management'},
                          "User Change Password": {"Definition": '(WIP)Enable this to score the competitor for changing a users password.',
                                                   "Description": 'This will score the competitor for changing a users password. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can Category the user name in the field. Otherwise use the drop down to select a user.',
                                                   "Checks": 'User Name:Str',
                                                   "Category": 'Account Management'},
                          "Add User to Group": {"Definition": 'Enable this to score the competitor for adding a user to a group other than the Administrative group.',
                                                "Description": 'This will score the competitor for adding a user to a group other than the Administrative group. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user  and group per line. To add users or group that are not on the computer, then you can type the user or group name in the field. Otherwise use the drop down to select a user or group.',
                                                "Checks": 'User Name:Str,Group Name:Str',
                                                "Category": 'Account Management'},
                          "Remove User from Group": {"Definition": 'Enable this to score the competitor for removing a user from a group other than the Administrative group.',
                                                     "Description": 'This will score the competitor for removing a user from a group other than the Administrative group. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user and group per line. To add users or group that are not on the computer, then you can type the user or group name in the field. Otherwise use the drop down to select a user or group.',
                                                     "Checks": 'User Name:Str,Group Name:Str',
                                                     "Category": 'Account Management'},
                          "Do Not Require CTRL_ALT_DEL": {"Definition": 'Enable this to score the competitor for disabling Do Not Require CTRL_ALT_DEL.',
                                                          "Category": 'Local Policy'},
                          "Turn On Domain Firewall": {"Definition": '(WIP)Enable this to score the competitor for turning on the domain firewall profile. Does not work for Windows Server.',
                                                      "Category": 'Local Policy'},
                          "Turn On Private Firewall": {"Definition": '(WIP)Enable this to score the competitor for turning on the private firewall profile. Does not work for Windows Server.',
                                                       "Category": 'Local Policy'},
                          "Turn On Public Firewall": {"Definition": '(WIP)Enable this to score the competitor for turning on the public firewall profile. Does not work for Windows Server.',
                                                      "Category": 'Local Policy'},
                          "Don't Display Last User": {"Definition": 'Enable this to score the competitor for enabling Don\'t Display Last User.',
                                                      "Category": 'Local Policy'},
                          "Minimum Password Age": {"Definition": 'Enable this to score the competitor for setting the minimum password age to 30, 45, or 60.',
                                                   "Category": 'Local Policy'},
                          "Maximum Password Age": {"Definition": 'Enable this to score the competitor for setting the maximum password age to 60, 75, or 90.',
                                                   "Category": 'Local Policy'},
                          "Minimum Password Length": {"Definition": 'Enable this to score the competitor for setting the minimum password length between 10 and 20.',
                                                      "Category": 'Local Policy'},
                          "Maximum Login Tries": {"Definition": 'Enable this to score the competitor for setting the maximum login tries between 5 and 10.',
                                                  "Category": 'Local Policy'},
                          "Lockout Duration": {"Definition": 'Enable this to score the competitor for setting the lockout duration to 30.',
                                               "Category": 'Local Policy'},
                          "Lockout Reset Duration": {"Definition": 'Enable this to score the competitor for setting the lockout reset duration to 30.',
                                                     "Category": 'Local Policy'},
                          "Password History": {"Definition": 'Enable this to score the competitor for setting the password history between 5 and 10.',
                                               "Category": 'Local Policy'},
                          "Password Complexity": {"Definition": 'Enable this to score the competitor for enabling password complexity.',
                                                  "Category": 'Local Policy'},
                          "Reversible Password Encryption": {"Definition": 'Enable this to score the competitor for disabling reversible encryption.',
                                                             "Category": 'Local Policy'},
                          "Audit Account Login": {"Definition": 'Enable this to score the competitor for setting account login audit to success and failure.',
                                                  "Category": 'Local Policy'},
                          "Audit Account Management": {"Definition": 'Enable this to score the competitor for setting account management audit to success and failure.',
                                                       "Category": 'Local Policy'},
                          "Audit Directory Settings Access": {"Definition": 'Enable this to score the competitor for setting directory settings access audit to success and failure.',
                                                              "Category": 'Local Policy'},
                          "Audit Logon Events": {"Definition": 'Enable this to score the competitor for setting login events audit to success and failure.',
                                                 "Category": 'Local Policy'},
                          "Audit Object Access": {"Definition": 'Enable this to score the competitor for setting object access audit to success and failure.',
                                                  "Category": 'Local Policy'},
                          "Audit Policy Change": {"Definition": 'Enable this to score the competitor for setting policy change audit to success and failure.',
                                                  "Category": 'Local Policy'},
                          "Audit Privilege Use": {"Definition": 'Enable this to score the competitor for setting privilege use audit to success and failure.',
                                                  "Category": 'Local Policy'},
                          "Audit Process Tracking": {"Definition": 'Enable this to score the competitor for setting process tracking audit to success and failure.',
                                                     "Category": 'Local Policy'},
                          "Audit System Events": {"Definition": 'Enable this to score the competitor for setting system events audit to success and failure.',
                                                  "Category": 'Local Policy'},
                          "Critical Programs": {"Definition": 'Enable this to penalize the competitor for removing a program.',
                                                "Description": 'This will penalize the competitor for removing a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                                "Checks": 'Program Name:Str',
                                                "Category": 'Program Management'},
                          "Good Program": {"Definition": 'Enable this to score the competitor for installing a program.',
                                           "Description": 'This will score the competitor for installing a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                           "Checks": 'Program Name:Str',
                                           "Category": 'Program Management'},
                          "Bad Program": {"Definition": 'Enable this to score the competitor for uninstalling a program.',
                                          "Description": 'This will score the competitor for uninstalling a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                          "Checks": 'Program Name:Str',
                                          "Category": 'Program Management'},
                          "Update Program": {"Definition": '(WIP)Enable this to score the competitor for updating a program.',
                                             "Description": '(WIP)This will score the competitor for updating a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                             "Checks": 'Program Name:Str',
                                             "Category": 'Program Management'},
                          "Add Feature": {"Definition": '(WIP)Enable this to score the competitor for adding a feature.',
                                          "Description": '(WIP)This will score the competitor for adding a feature. To add more features press the "Add" button. To remove a feature press the "X" button next to the feature you want to remove. Keep it one feature per line.',
                                          "Checks": 'Feature Name:Str',
                                          "Category": 'Program Management'},
                          "Remove Feature": {"Definition": '(WIP)Enable this to score the competitor for removing a feature.',
                                             "Description": '(WIP)This will score the competitor for removing a feature. To add more features press the "Add" button. To remove a feature press the "X" button next to the feature you want to remove. Keep it one feature per line.',
                                             "Checks": 'Feature Name:Str',
                                             "Category": 'Program Management'},
                          "Critical Services": {"Definition": 'Enable this to penalize the competitor for modifying a services run ability.',
                                                "Description": 'This will penalize the competitor for modifying a services run ability. To add more services press the "Add" button. To remove a service press the "X" button next to the service you want to remove. Keep it one service per line.',
                                                "Checks": 'Service Name:Str,Service State:Str,Service Start Mode:Str',
                                                "Category": 'Program Management'},
                          "Services": {"Definition": 'Enable this to score the competitor for modifying a services run ability.',
                                       "Description": 'This will score the competitor for modifying a services run ability. To add more services press the "Add" button. To remove a service press the "X" button next to the service you want to remove. Keep it one service per line. The name can be the services system name or the displayed name.',
                                       "Checks": 'Service Name:Str,Service State:Str,Service Start Mode:Str',
                                       "Category": 'Program Management'},
                          "Bad File": {"Definition": 'Enable this to score the competitor for deleting a file.',
                                       "Description": 'This will score the competitor for deleting a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                       "Checks": 'File Path:Str',
                                       "Category": 'File Management'},
                          "Check Hosts": {"Definition": '(WIP)Enable this to score the competitor for clearing the hosts file.',
                                          "Description": '(WIP)This will score the competitor for clearing the hosts file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                          "Checks": 'Text:Str',
                                          "Category": 'File Management'},
                          "Add Text to File": {"Definition": 'Enable this to score the competitor for adding text to a file.',
                                               "Description": 'This will score the competitor for adding text to a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                               "Checks": 'Text to Add:Str,File Path:Str',
                                               "Category": 'File Management'},
                          "Remove Text From File": {"Definition": 'Enable this to score the competitor for removing text from a file.',
                                                    "Description": 'This will score the competitor for removing text from a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                                    "Checks": 'Text to Remove:Str,File Path:Str',
                                                    "Category": 'File Management'},
                          "File Permissions": {"Definition": '(WIP)Enable this to score the competitor for changing the permissions a user has on a file.',
                                               "Description": '(WIP)This will score the competitor for changing the permissions a user has on a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                               "Checks": 'Users to Modify:Str,Permission to Set:Str,File Path:Str',
                                               "Category": 'File Management'},
                          "Anti-Virus": {"Definition": 'Enable this to score the competitor for installing an anti-virus. Not windows defender.',
                                         "Category": 'Miscellaneous'},
                          "Update Check Period": {"Definition": '(WIP)Enable this to score the competitor for setting the period windows checks for updates to once a week.',
                                                  "Category": 'Miscellaneous'},
                          "Update Auto Install": {"Definition": '(WIP)Enable this to score the competitor for setting windows updates to automatically install updates.',
                                                  "Category": 'Miscellaneous'},
                          "Task Scheduler": {"Definition": '(WIP)Enable this to score the competitor for removing a task from the task scheduler.',
                                             "Description": '(WIP)This will score the competitor for removing a task from the task scheduler. To add more tasks press the "Add" button. To remove a task press the "X" button next to the task you want to remove. Keep it one task per line.',
                                             "Checks": 'Task Name:Str',
                                             "Category": 'Miscellaneous'},
                          "Check Startup": {"Definition": '(WIP)Enable this to score the competitor for removing or disabling a program from the startup.',
                                            "Description": '(WIP)This will score the competitor for removing or disabling a program from the startup. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                            "Checks": 'Program Name:Str',
                                            "Category": 'Miscellaneous'},
                          }
Vulnerabilities = OptionTables(vulnerability_template)
Vulnerabilities.initialize_option_table()
'''
'''
temp = Vulnerabilities.add_to_table('Remove User', **{"enabled": True, "points": 10, "User Name": 'Shaun'})
Vulnerabilities.remove_from_table('Remove User', 3)
'''
'''vulnerability_settings.update({"Main Menu": {"Style": StringVar(), "Desktop Checkbox": IntVar(), "Desktop Entry": StringVar(), "Silent Mode": IntVar(), "Server Mode": IntVar(), "Server Name": StringVar(), "Server User Name": StringVar(), "Server Password": StringVar(), "Tally Points": StringVar()}, "Forensic": {"Enabled": IntVar(), "Categories": {"Points": [IntVar()],  "Question": [StringVar()], "Answer": [StringVar()]}, "Location": ['']},
                                       "Account Management": {"Disable Guest": {"Definition": 'Enable this to score the competitor for disabling the Guest account.',
                                                                                "Enabled": IntVar(),
                                                                                "Categories": {'Points': [IntVar()]}},
                                                              "Disable Admin": {"Definition": 'Enable this to score the competitor for disabling the Administrator account.',
                                                                                "Enabled": IntVar(),
                                                                                "Categories": {'Points': [IntVar()]}},
                                                              "Critical Users": {"Definition": 'Enable this to penalize the competitor for removing a user.',
                                                                                 "Modify Definition": 'This will penalize the competitor for removing a user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user. Do not make the point value negative.',
                                                                                 "Enabled": IntVar(),
                                                                                 "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                              "Add Admin": {"Definition": 'Enable this to score the competitor for elevating a user to an Administrator.',
                                                                            "Modify Definition": 'This will score the competitor for elevating a user to an Administrator. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                                                            "Enabled": IntVar(),
                                                                            "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                              "Remove Admin": {"Definition": 'Enable this to score the competitor for demoting a user to Standard user.',
                                                                               "Modify Definition": 'This will score the competitor for demoting a user to Standard user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                                                               "Enabled": IntVar(),
                                                                               "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                              "Add User": {"Definition": 'Enable this to score the competitor for adding a user.',
                                                                           "Modify Definition": 'This will score the competitor for adding a user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                                                           "Enabled": IntVar(),
                                                                           "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                              "Remove User": {"Definition": 'Enable this to score the competitor for removing a user.',
                                                                              "Modify Definition": 'This will score the competitor for removing a user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                                                              "Enabled": IntVar(),
                                                                              "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                              "User Change Password": {"Definition": '(WIP)Enable this to score the competitor for changing a users password.',
                                                                                       "Modify Definition": 'This will score the competitor for changing a users password. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                                                                       "Enabled": IntVar(),
                                                                                       "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                              "Add User to Group": {"Definition": 'Enable this to score the competitor for adding a user to a group other than the Administrative group.',
                                                                                    "Modify Definition": 'This will score the competitor for adding a user to a group other than the Administrative group. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user  and group per line. To add users or group that are not on the computer, then you can type the user or group name in the field. Otherwise use the drop down to select a user or group.',
                                                                                    "Enabled": IntVar(),
                                                                                    "Categories": {'Points': [IntVar()], 'User Name': [StringVar()], 'Group Name': [StringVar()]}},
                                                              "Remove User from Group": {"Definition": 'Enable this to score the competitor for removing a user from a group other than the Administrative group.',
                                                                                         "Modify Definition": 'This will score the competitor for removing a user from a group other than the Administrative group. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user and group per line. To add users or group that are not on the computer, then you can type the user or group name in the field. Otherwise use the drop down to select a user or group.',
                                                                                         "Enabled": IntVar(),
                                                                                         "Categories": {'Points': [IntVar()], 'User Name': [StringVar()], 'Group Name': [StringVar()]}}},
                                       "Local Policy Options": {"Do Not Require CTRL_ALT_DEL": {"Definition": 'Enable this to score the competitor for disabling Do Not Require CTRL_ALT_DEL.',
                                                                                                "Enabled": IntVar(),
                                                                                                "Categories": {'Points': [IntVar()]}},
                                                                "Turn On Domain Firewall": {"Definition": '(WIP)Enable this to score the competitor for turning on the domain firewall profile. Does not work for Windows Server.',
                                                                                            "Enabled": IntVar(),
                                                                                            "Categories": {'Points': [IntVar()]}},
                                                                "Turn On Private Firewall": {"Definition": '(WIP)Enable this to score the competitor for turning on the private firewall profile. Does not work for Windows Server.',
                                                                                             "Enabled": IntVar(),
                                                                                             "Categories": {'Points': [IntVar()]}},
                                                                "Turn On Public Firewall": {"Definition": '(WIP)Enable this to score the competitor for turning on the public firewall profile. Does not work for Windows Server.',
                                                                                            "Enabled": IntVar(),
                                                                                            "Categories": {'Points': [IntVar()]}},
                                                                "Don't Display Last User": {"Definition": 'Enable this to score the competitor for enabling Don\'t Display Last User.',
                                                                                            "Enabled": IntVar(),
                                                                                            "Categories": {'Points': [IntVar()]}}},
                                       "Local Policy Password": {"Minimum Password Age": {"Definition": 'Enable this to score the competitor for setting the minimum password age to 30, 45, or 60.',
                                                                                          "Enabled": IntVar(),
                                                                                          "Categories": {'Points': [IntVar()]}},
                                                                 "Maximum Password Age": {"Definition": 'Enable this to score the competitor for setting the maximum password age to 60, 75, or 90.',
                                                                                          "Enabled": IntVar(),
                                                                                          "Categories": {'Points': [IntVar()]}},
                                                                 "Minimum Password Length": {"Definition": 'Enable this to score the competitor for setting the minimum password length between 10 and 20.',
                                                                                             "Enabled": IntVar(),
                                                                                             "Categories": {'Points': [IntVar()]}},
                                                                 "Maximum Login Tries": {"Definition": 'Enable this to score the competitor for setting the maximum login tries between 5 and 10.',
                                                                                         "Enabled": IntVar(),
                                                                                         "Categories": {'Points': [IntVar()]}},
                                                                 "Lockout Duration": {"Definition": 'Enable this to score the competitor for setting the lockout duration to 30.',
                                                                                      "Enabled": IntVar(),
                                                                                      "Categories": {'Points': [IntVar()]}},
                                                                 "Lockout Reset Duration": {"Definition": 'Enable this to score the competitor for setting the lockout reset duration to 30.',
                                                                                            "Enabled": IntVar(),
                                                                                            "Categories": {'Points': [IntVar()]}},
                                                                 "Password History": {"Definition": 'Enable this to score the competitor for setting the password history between 5 and 10.',
                                                                                      "Enabled": IntVar(),
                                                                                      "Categories": {'Points': [IntVar()]}},
                                                                 "Password Complexity": {"Definition": 'Enable this to score the competitor for enabling password complexity.',
                                                                                         "Enabled": IntVar(),
                                                                                         "Categories": {'Points': [IntVar()]}},
                                                                 "Reversible Password Encryption": {"Definition": 'Enable this to score the competitor for disabling reversible encryption.',
                                                                                                    "Enabled": IntVar(),
                                                                                                    "Categories": {'Points': [IntVar()]}}},
                                       "Local Policy Audit": {"Audit Account Login": {"Definition": 'Enable this to score the competitor for setting account login audit to success and failure.',
                                                                                      "Enabled": IntVar(),
                                                                                      "Categories": {'Points': [IntVar()]}},
                                                              "Audit Account Management": {"Definition": 'Enable this to score the competitor for setting account management audit to success and failure.',
                                                                                           "Enabled": IntVar(),
                                                                                           "Categories": {'Points': [IntVar()]}},
                                                              "Audit Directory Settings Access": {"Definition": 'Enable this to score the competitor for setting directory settings access audit to success and failure.',
                                                                                                  "Enabled": IntVar(),
                                                                                                  "Categories": {'Points': [IntVar()]}},
                                                              "Audit Logon Events": {"Definition": 'Enable this to score the competitor for setting login events audit to success and failure.',
                                                                                     "Enabled": IntVar(),
                                                                                     "Categories": {'Points': [IntVar()]}},
                                                              "Audit Object Access": {"Definition": 'Enable this to score the competitor for setting object access audit to success and failure.',
                                                                                      "Enabled": IntVar(),
                                                                                      "Categories": {'Points': [IntVar()]}},
                                                              "Audit Policy Change": {"Definition": 'Enable this to score the competitor for setting policy change audit to success and failure.',
                                                                                      "Enabled": IntVar(),
                                                                                      "Categories": {'Points': [IntVar()]}},
                                                              "Audit Privilege Use": {"Definition": 'Enable this to score the competitor for setting privilege use audit to success and failure.',
                                                                                      "Enabled": IntVar(),
                                                                                      "Categories": {'Points': [IntVar()]}},
                                                              "Audit Process Tracking": {"Definition": 'Enable this to score the competitor for setting process tracking audit to success and failure.',
                                                                                         "Enabled": IntVar(),
                                                                                         "Categories": {'Points': [IntVar()]}},
                                                              "Audit System Events": {"Definition": 'Enable this to score the competitor for setting system events audit to success and failure.',
                                                                                      "Enabled": IntVar(),
                                                                                      "Categories": {'Points': [IntVar()]}}},
                                       "Program Management": {"Critical Programs": {"Definition": 'Enable this to penalize the competitor for removing a program.',
                                                                                    "Modify Definition": 'This will penalize the competitor for removing a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                                                                    "Enabled": IntVar(),
                                                                                    "Categories": {'Points': [IntVar()], 'Program Name': [StringVar()]}},
                                                              "Good Program": {"Definition": 'Enable this to score the competitor for installing a program.',
                                                                               "Modify Definition": 'This will score the competitor for installing a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                                                               "Enabled": IntVar(),
                                                                               "Categories": {'Points': [IntVar()], 'Program Name': [StringVar()]}},
                                                              "Bad Program": {"Definition": 'Enable this to score the competitor for uninstalling a program.',
                                                                              "Modify Definition": 'This will score the competitor for uninstalling a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                                                              "Enabled": IntVar(),
                                                                              "Categories": {'Points': [IntVar()], 'Program Name': [StringVar()]}},
                                                              "Update Program": {"Definition": '(WIP)Enable this to score the competitor for updating a program.',
                                                                                 "Modify Definition": '(WIP)This will score the competitor for updating a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                                                                 "Enabled": IntVar(),
                                                                                 "Categories": {'Points': [IntVar()], 'Program Name': [StringVar()]}},
                                                              "Add Feature": {"Definition": '(WIP)Enable this to score the competitor for adding a feature.',
                                                                              "Modify Definition": '(WIP)This will score the competitor for adding a feature. To add more features press the "Add" button. To remove a feature press the "X" button next to the feature you want to remove. Keep it one feature per line.',
                                                                              "Enabled": IntVar(),
                                                                              "Categories": {'Points': [IntVar()], 'Feature Name': [StringVar()]}},
                                                              "Remove Feature": {"Definition": '(WIP)Enable this to score the competitor for removing a feature.',
                                                                                 "Modify Definition": '(WIP)This will score the competitor for removing a feature. To add more features press the "Add" button. To remove a feature press the "X" button next to the feature you want to remove. Keep it one feature per line.',
                                                                                 "Enabled": IntVar(),
                                                                                 "Categories": {'Points': [IntVar()], 'Feature Name': [StringVar()]}},
                                                              "Critical Services": {"Definition": 'Enable this to penalize the competitor for modifying a services run ability.',
                                                                                    "Modify Definition": 'This will penalize the competitor for modifying a services run ability. To add more services press the "Add" button. To remove a service press the "X" button next to the service you want to remove. Keep it one service per line.',
                                                                                    "Enabled": IntVar(),
                                                                                    "Categories": {'Points': [IntVar()], 'Service Name': [StringVar()], 'Service State': [StringVar()], 'Service Start Mode': [StringVar()]}},
                                                              "Services": {"Definition": 'Enable this to score the competitor for modifying a services run ability.',
                                                                           "Modify Definition": 'This will score the competitor for modifying a services run ability. To add more services press the "Add" button. To remove a service press the "X" button next to the service you want to remove. Keep it one service per line. The name can be the services system name or the displayed name.',
                                                                           "Enabled": IntVar(),
                                                                           "Categories": {'Points': [IntVar()], 'Service Name': [StringVar()], 'Service State': [StringVar()], 'Service Start Mode': [StringVar()]}}},
                                       "File Management": {"Bad File": {"Definition": 'Enable this to score the competitor for deleting a file.',
                                                                        "Modify Definition": 'This will score the competitor for deleting a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                                                        "Enabled": IntVar(),
                                                                        "Categories": {'Points': [IntVar()], 'File Path': [StringVar()]}},
                                                           "Check Hosts": {"Definition": '(WIP)Enable this to score the competitor for clearing the hosts file.',
                                                                           "Modify Definition": '(WIP)This will score the competitor for clearing the hosts file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                                                           "Enabled": IntVar(),
                                                                           "Categories": {'Points': [IntVar()], 'Text': [StringVar()]}},
                                                           "Add Text to File": {"Definition": 'Enable this to score the competitor for adding text to a file.',
                                                                                "Modify Definition": 'This will score the competitor for adding text to a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                                                                "Enabled": IntVar(),
                                                                                "Categories": {'Points': [IntVar()], 'Text to Add': [StringVar()], 'File Path': [StringVar()]}},
                                                           "Remove Text From File": {"Definition": 'Enable this to score the competitor for removing text from a file.',
                                                                                     "Modify Definition": 'This will score the competitor for removing text from a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                                                                     "Enabled": IntVar(),
                                                                                     "Categories": {'Points': [IntVar()], 'Text to Remove': [StringVar()], 'File Path': [StringVar()]}},
                                                           "File Permissions": {"Definition": '(WIP)Enable this to score the competitor for changing the permissions a user has on a file.',
                                                                                "Modify Definition": '(WIP)This will score the competitor for changing the permissions a user has on a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                                                                "Enabled": IntVar(),
                                                                                "Categories": {'Points': [IntVar()], 'Users to Modify': [StringVar()], 'Permission to Set': [StringVar()], 'File Path': [StringVar()]}}},
                                       "Miscellaneous": {"Anti-Virus": {"Definition": 'Enable this to score the competitor for installing an anti-virus. Not windows defender.',
                                                                        "Enabled": IntVar(),
                                                                        "Categories": {'Points': [IntVar()]}},
                                                         "Update Check Period": {"Definition": '(WIP)Enable this to score the competitor for setting the period windows checks for updates to once a week.',
                                                                                 "Enabled": IntVar(),
                                                                                 "Categories": {'Points': [IntVar()]}},
                                                         "Update Auto Install": {"Definition": '(WIP)Enable this to score the competitor for setting windows updates to automatically install updates.',
                                                                                 "Enabled": IntVar(),
                                                                                 "Categories": {'Points': [IntVar()]}},
                                                         "Task Scheduler": {"Definition": '(WIP)Enable this to score the competitor for removing a task from the task scheduler.',
                                                                            "Modify Definition": '(WIP)This will score the competitor for removing a task from the task scheduler. To add more tasks press the "Add" button. To remove a task press the "X" button next to the task you want to remove. Keep it one task per line.',
                                                                            "Enabled": IntVar(),
                                                                            "Categories": {'Points': [IntVar()], 'Task Name': [StringVar()]}},
                                                         "Check Startup": {"Definition": '(WIP)Enable this to score the competitor for removing or disabling a program from the startup.',
                                                                           "Modify Definition": '(WIP)This will score the competitor for removing or disabling a program from the startup. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                                                           "Enabled": IntVar(),
                                                                           "Categories": {'Points': [IntVar()], 'Program Name': [StringVar()]}}}})
        vulnerability_settings["Main Menu"]["Tally Points"].set("Vulnerabilities: 0 Total Points: 0")'''
