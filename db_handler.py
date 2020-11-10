from sqlalchemy import orm
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy as sa

base = declarative_base()
engine = sa.create_engine('sqlite:///save_data.db')
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
    server_pass = sa.Column(sa.String(128))
    tally_points = sa.Column(sa.Integer, nullable=False, default=0)
    tally_vuln = sa.Column(sa.Integer, nullable=False, default=0)

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

    def get_settings(self):
        return self.settings


class VulnerabilityTemplateModel(base):
    __tablename__ = "Vulnerability Template"
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String(128), nullable=False, unique=True)
    type = sa.Column(sa.String, nullable=False)
    definition = sa.Column(sa.Text, nullable=False)
    description = sa.Column(sa.Text)
    categories = sa.Column(sa.Text)

    def __init__(self, **kwargs):
        super(VulnerabilityTemplateModel, self).__init__(**kwargs)


base.metadata.create_all()


class OptionTables:
    models = {}

    def __init__(self, vulnerability_templates):
        loaded_vulns_templates = []
        for vuln_templates in session.query(VulnerabilityTemplateModel):
            loaded_vulns_templates.append(vuln_templates.name)
        for name in vulnerability_templates:
            if name not in loaded_vulns_templates:
                type = vulnerability_templates[name]["Type"]
                definition = vulnerability_templates[name]["Definition"]
                description = vulnerability_templates[name]["Description"] if "Description" in vulnerability_templates[name] else None
                categories = vulnerability_templates[name]["Categories"] if "Categories" in vulnerability_templates[name] else None
                vuln_template = VulnerabilityTemplateModel(name=name, type=type, definition=definition, description=description, categories=categories)
                session.add(vuln_template)
        session.commit()

    def initialize_option_table(self):
        for vuln_template in session.query(VulnerabilityTemplateModel):
            name = vuln_template.name
            category_list = vuln_template.categories.split(',') if vuln_template.categories is not None else []
            category_dict = {}
            for category in category_list:
                cat = category.split(':')
                category_dict.update({cat[0]: cat[1]})
            create_option_table(name, category_dict, self.models)
        base.metadata.create_all()

    def get_option_table(self, vulnerability):
        return session.query(self.models[vulnerability])

    def add_to_table(self, vulnerability, **kwargs):
        vuln = self.models[vulnerability](**kwargs)
        session.add(vuln)
        session.commit()
        return vuln

    def remove_from_table(self, vulnerability, vuln_id):
        vuln = session.query(self.models[vulnerability]).filter_by(id=vuln_id).one()
        session.delete(vuln)
        session.commit()


def create_option_table(name, option_categories, option_models):
    attr_dict = {'__tablename__': name,
                 'id': sa.Column(sa.Integer, primary_key=True),
                 'enabled': sa.Column(sa.Boolean, nullable=False, default=False),
                 'points': sa.Column(sa.Integer, nullable=False, default=0)}
    for cat in option_categories:
        if option_categories[cat] == "Int":
            attr_dict.update({cat: sa.Column(sa.Integer, default=0)})
        elif option_categories[cat] == "Str":
            attr_dict.update({cat: sa.Column(sa.Text)})

    option_models.update({name: type(name, (base,), attr_dict)})


ettings = Settings()
s = ettings.get_settings()
print(s.style)
ettings.set_setting("desktop", "home")

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
