from sqlalchemy import orm
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy as sa

models = {}
base = declarative_base()
engine = sa.create_engine('sqlite:///save_data.db')
base.metadata.bind = engine
session = orm.scoped_session(orm.sessionmaker())(bind=engine)

# after this:
# base == db.Model
# session == db.session
# other db.* values are in sa.*
# ie: old: db.Column(db.Integer,db.ForeignKey('s.id'))
#     new: sa.Column(sa.Integer,sa.ForeignKey('s.id'))
# except relationship, and backref, those are in orm
# ie: orm.relationship, orm.backref
# so to define a simple model


class SettingsModel(base):
    __tablename__ = "Settings"
    id = sa.Column(sa.Integer, primary_key=True)
    style = sa.Column(sa.String(128), nullable=False)
    desktop = sa.Column(sa.Text, nullable=False)
    silent_mode = sa.Column(sa.Boolean, nullable=False)
    server_mode = sa.Column(sa.Boolean, nullable=False)
    server_name = sa.Column(sa.String(255))
    server_pass = sa.Column(sa.String(128))
    tally_points = sa.Column(sa.Integer, nullable=False, default=0)
    tally_vuln = sa.Column(sa.Integer, nullable=False, default=0)

    def __init__(self, *args, **kwargs):
        super(SettingsModel, self).__init__(**kwargs)


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


base.metadata.create_all()

vulnerability_template = {"Forensic": {"Definition": 'This section is for scoring forensic questions. To score a forensic question be sure to check "Enable". To add more questions press the "Add" button. To remove questions press the "X" button next to the question you want to remove. \nDo note that the answers are case sensitive.',
                                       "Categories": 'Question:Str,Answers:Str,Location:Str',
                                       "Type": 'Forensic'},
                          "Disable Guest": {"Definition": 'Enable this to score the competitor for disabling the Guest account.',
                                            "Type": 'Account Management'},
                          "Disable Admin": {"Definition": 'Enable this to score the competitor for disabling the Administrator account.',
                                            "Type": 'Account Management'},
                          "Critical Users": {"Definition": 'Enable this to penalize the competitor for removing a user.',
                                             "Description": 'This will penalize the competitor for removing a user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user. Do not make the point value negative.',
                                             "Categories": 'User Name:Str',
                                             "Type": 'Account Management'},
                          "Add Admin": {"Definition": 'Enable this to score the competitor for elevating a user to an Administrator.',
                                        "Description": 'This will score the competitor for elevating a user to an Administrator. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                        "Categories": 'User Name:Str',
                                        "Type": 'Account Management'},
                          "Remove Admin": {"Definition": 'Enable this to score the competitor for demoting a user to Standard user.',
                                           "Description": 'This will score the competitor for demoting a user to Standard user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                           "Categories": 'User Name:Str',
                                           "Type": 'Account Management'},
                          "Add User": {"Definition": 'Enable this to score the competitor for adding a user.',
                                       "Description": 'This will score the competitor for adding a user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                       "Categories": 'User Name:Str',
                                       "Type": 'Account Management'},
                          "Remove User": {"Definition": 'Enable this to score the competitor for removing a user.',
                                          "Description": 'This will score the competitor for removing a user. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                          "Categories": 'User Name:Str',
                                          "Type": 'Account Management'},
                          "User Change Password": {"Definition": '(WIP)Enable this to score the competitor for changing a users password.',
                                                   "Description": 'This will score the competitor for changing a users password. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user per line. To add users that are not on the computer, then you can type the user name in the field. Otherwise use the drop down to select a user.',
                                                   "Categories": 'User Name:Str',
                                                   "Type": 'Account Management'},
                          "Add User to Group": {"Definition": 'Enable this to score the competitor for adding a user to a group other than the Administrative group.',
                                                "Description": 'This will score the competitor for adding a user to a group other than the Administrative group. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user  and group per line. To add users or group that are not on the computer, then you can type the user or group name in the field. Otherwise use the drop down to select a user or group.',
                                                "Categories": 'User Name:Str,Group Name:Str',
                                                "Type": 'Account Management'},
                          "Remove User from Group": {"Definition": 'Enable this to score the competitor for removing a user from a group other than the Administrative group.',
                                                     "Description": 'This will score the competitor for removing a user from a group other than the Administrative group. To add more users press the "Add" button. To remove a user press the "X" button next to the user you want to remove. Keep it one user and group per line. To add users or group that are not on the computer, then you can type the user or group name in the field. Otherwise use the drop down to select a user or group.',
                                                     "Categories": 'User Name:Str,Group Name:Str',
                                                     "Type": 'Account Management'},
                          "Do Not Require CTRL_ALT_DEL": {"Definition": 'Enable this to score the competitor for disabling Do Not Require CTRL_ALT_DEL.',
                                                          "Type": 'Local Policy'},
                          "Turn On Domain Firewall": {"Definition": '(WIP)Enable this to score the competitor for turning on the domain firewall profile. Does not work for Windows Server.',
                                                      "Type": 'Local Policy'},
                          "Turn On Private Firewall": {"Definition": '(WIP)Enable this to score the competitor for turning on the private firewall profile. Does not work for Windows Server.',
                                                       "Type": 'Local Policy'},
                          "Turn On Public Firewall": {"Definition": '(WIP)Enable this to score the competitor for turning on the public firewall profile. Does not work for Windows Server.',
                                                      "Type": 'Local Policy'},
                          "Don't Display Last User": {"Definition": 'Enable this to score the competitor for enabling Don\'t Display Last User.',
                                                      "Type": 'Local Policy'},
                          "Minimum Password Age": {"Definition": 'Enable this to score the competitor for setting the minimum password age to 30, 45, or 60.',
                                                   "Type": 'Local Policy'},
                          "Maximum Password Age": {"Definition": 'Enable this to score the competitor for setting the maximum password age to 60, 75, or 90.',
                                                   "Type": 'Local Policy'},
                          "Minimum Password Length": {"Definition": 'Enable this to score the competitor for setting the minimum password length between 10 and 20.',
                                                      "Type": 'Local Policy'},
                          "Maximum Login Tries": {"Definition": 'Enable this to score the competitor for setting the maximum login tries between 5 and 10.',
                                                  "Type": 'Local Policy'},
                          "Lockout Duration": {"Definition": 'Enable this to score the competitor for setting the lockout duration to 30.',
                                               "Type": 'Local Policy'},
                          "Lockout Reset Duration": {"Definition": 'Enable this to score the competitor for setting the lockout reset duration to 30.',
                                                     "Type": 'Local Policy'},
                          "Password History": {"Definition": 'Enable this to score the competitor for setting the password history between 5 and 10.',
                                               "Type": 'Local Policy'},
                          "Password Complexity": {"Definition": 'Enable this to score the competitor for enabling password complexity.',
                                                  "Type": 'Local Policy'},
                          "Reversible Password Encryption": {"Definition": 'Enable this to score the competitor for disabling reversible encryption.',
                                                             "Type": 'Local Policy'},
                          "Audit Account Login": {"Definition": 'Enable this to score the competitor for setting account login audit to success and failure.',
                                                  "Type": 'Local Policy'},
                          "Audit Account Management": {"Definition": 'Enable this to score the competitor for setting account management audit to success and failure.',
                                                       "Type": 'Local Policy'},
                          "Audit Directory Settings Access": {"Definition": 'Enable this to score the competitor for setting directory settings access audit to success and failure.',
                                                              "Type": 'Local Policy'},
                          "Audit Logon Events": {"Definition": 'Enable this to score the competitor for setting login events audit to success and failure.',
                                                 "Type": 'Local Policy'},
                          "Audit Object Access": {"Definition": 'Enable this to score the competitor for setting object access audit to success and failure.',
                                                  "Type": 'Local Policy'},
                          "Audit Policy Change": {"Definition": 'Enable this to score the competitor for setting policy change audit to success and failure.',
                                                  "Type": 'Local Policy'},
                          "Audit Privilege Use": {"Definition": 'Enable this to score the competitor for setting privilege use audit to success and failure.',
                                                  "Type": 'Local Policy'},
                          "Audit Process Tracking": {"Definition": 'Enable this to score the competitor for setting process tracking audit to success and failure.',
                                                     "Type": 'Local Policy'},
                          "Audit System Events": {"Definition": 'Enable this to score the competitor for setting system events audit to success and failure.',
                                                  "Type": 'Local Policy'},
                          "Critical Programs": {"Definition": 'Enable this to penalize the competitor for removing a program.',
                                                "Description": 'This will penalize the competitor for removing a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                                "Categories": 'Program Name:Str',
                                                "Type": 'Program Management'},
                          "Good Program": {"Definition": 'Enable this to score the competitor for installing a program.',
                                           "Description": 'This will score the competitor for installing a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                           "Categories": 'Program Name:Str',
                                           "Type": 'Program Management'},
                          "Bad Program": {"Definition": 'Enable this to score the competitor for uninstalling a program.',
                                          "Description": 'This will score the competitor for uninstalling a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                          "Categories": 'Program Name:Str',
                                          "Type": 'Program Management'},
                          "Update Program": {"Definition": '(WIP)Enable this to score the competitor for updating a program.',
                                             "Description": '(WIP)This will score the competitor for updating a program. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                             "Categories": 'Program Name:Str',
                                             "Type": 'Program Management'},
                          "Add Feature": {"Definition": '(WIP)Enable this to score the competitor for adding a feature.',
                                          "Description": '(WIP)This will score the competitor for adding a feature. To add more features press the "Add" button. To remove a feature press the "X" button next to the feature you want to remove. Keep it one feature per line.',
                                          "Categories": 'Feature Name:Str',
                                          "Type": 'Program Management'},
                          "Remove Feature": {"Definition": '(WIP)Enable this to score the competitor for removing a feature.',
                                             "Description": '(WIP)This will score the competitor for removing a feature. To add more features press the "Add" button. To remove a feature press the "X" button next to the feature you want to remove. Keep it one feature per line.',
                                             "Categories": 'Feature Name:Str',
                                             "Type": 'Program Management'},
                          "Critical Services": {"Definition": 'Enable this to penalize the competitor for modifying a services run ability.',
                                                "Description": 'This will penalize the competitor for modifying a services run ability. To add more services press the "Add" button. To remove a service press the "X" button next to the service you want to remove. Keep it one service per line.',
                                                "Categories": 'Service Name:Str,Service State:Str,Service Start Mode:Str',
                                                "Type": 'Program Management'},
                          "Services": {"Definition": 'Enable this to score the competitor for modifying a services run ability.',
                                       "Description": 'This will score the competitor for modifying a services run ability. To add more services press the "Add" button. To remove a service press the "X" button next to the service you want to remove. Keep it one service per line. The name can be the services system name or the displayed name.',
                                       "Categories": 'Service Name:Str,Service State:Str,Service Start Mode:Str',
                                       "Type": 'Program Management'},
                          "Bad File": {"Definition": 'Enable this to score the competitor for deleting a file.',
                                       "Description": 'This will score the competitor for deleting a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                       "Categories": 'File Path:Str',
                                       "Type": 'File Management'},
                          "Check Hosts": {"Definition": '(WIP)Enable this to score the competitor for clearing the hosts file.',
                                          "Description": '(WIP)This will score the competitor for clearing the hosts file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                          "Categories": 'Text:Str',
                                          "Type": 'File Management'},
                          "Add Text to File": {"Definition": 'Enable this to score the competitor for adding text to a file.',
                                               "Description": 'This will score the competitor for adding text to a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                               "Categories": 'Text to Add:Str,File Path:Str',
                                               "Type": 'File Management'},
                          "Remove Text From File": {"Definition": 'Enable this to score the competitor for removing text from a file.',
                                                    "Description": 'This will score the competitor for removing text from a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                                    "Categories": 'Text to Remove:Str,File Path:Str',
                                                    "Type": 'File Management'},
                          "File Permissions": {"Definition": '(WIP)Enable this to score the competitor for changing the permissions a user has on a file.',
                                               "Description": '(WIP)This will score the competitor for changing the permissions a user has on a file. To add more files press the "Add" button. To remove a file press the "X" button next to the file you want to remove. Keep it one file per line.',
                                               "Categories": 'Users to Modify:Str,Permission to Set:Str,File Path:Str',
                                               "Type": 'File Management'},
                          "Anti-Virus": {"Definition": 'Enable this to score the competitor for installing an anti-virus. Not windows defender.',
                                         "Type": 'Miscellaneous'},
                          "Update Check Period": {"Definition": '(WIP)Enable this to score the competitor for setting the period windows checks for updates to once a week.',
                                                  "Type": 'Miscellaneous'},
                          "Update Auto Install": {"Definition": '(WIP)Enable this to score the competitor for setting windows updates to automatically install updates.',
                                                  "Type": 'Miscellaneous'},
                          "Task Scheduler": {"Definition": '(WIP)Enable this to score the competitor for removing a task from the task scheduler.',
                                             "Description": '(WIP)This will score the competitor for removing a task from the task scheduler. To add more tasks press the "Add" button. To remove a task press the "X" button next to the task you want to remove. Keep it one task per line.',
                                             "Categories": 'Task Name:Str',
                                             "Type": 'Miscellaneous'},
                          "Check Startup": {"Definition": '(WIP)Enable this to score the competitor for removing or disabling a program from the startup.',
                                            "Description": '(WIP)This will score the competitor for removing or disabling a program from the startup. To add more programs press the "Add" button. To remove a program press the "X" button next to the program you want to remove. Keep it one program per line.',
                                            "Categories": 'Program Name:Str',
                                            "Type": 'Miscellaneous'},
                          }
loaded_vulns_templates = []
for vuln_templates in session.query(VulnerabilityTemplateModel):
    loaded_vulns_templates.append(vuln_templates.name)

for name in vulnerability_template:
    if name not in loaded_vulns_templates:
        type = vulnerability_template[name]["Type"]
        definition = vulnerability_template[name]["Definition"]
        description = vulnerability_template[name]["Description"] if "Description" in vulnerability_template[name] else None
        categories = vulnerability_template[name]["Categories"] if "Categories" in vulnerability_template[name] else None
        vuln_template = VulnerabilityTemplateModel(name=name, type=type, definition=definition, description=description, categories=categories)
        session.add(vuln_template)
session.commit()

for vuln_template in session.query(VulnerabilityTemplateModel):
    name = vuln_template.name
    category_list = vuln_template.categories.split(',') if vuln_template.categories is not None else []
    category_dict = {}
    for category in category_list:
        cat = category.split(':')
        category_dict.update({cat[0]: cat[1]})
    create_option_table(name, category_dict, models)
base.metadata.create_all()

temp = models['Remove User'](**{"enabled": True, "points": 10, "User Name": 'Shaun'})
session.add(temp)
session.commit()
