from sqlalchemy import orm
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy as sa

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
    desctiption = sa.Column(sa.Text, nullable=False)
    additional_description = sa.Column(sa.Text)
    catagories = sa.Column(sa.Text, nullable=False)

    def __init__(self, *args, **kwargs):
        super(VulnerabilityTemplateModel, self).__init__(**kwargs)


def add_option_table(name, option_categories, option_models):
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


models = {}
add_option_table("Add Users", {'User Name': 'Str'}, models)
add_option_table("Add Admin", {'User Name': 'Str'}, models)
base.metadata.create_all()
