from . import db, login_manager
from flask_login import UserMixin

'''
Gets loads the User's info from the user table
@Pram user_id :: int, User's uid
'''
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


'''
CREATE TABLE "User" (
    "uid"   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    "username"  TEXT NOT NULL UNIQUE,
    "passwd"  TEXT NOT NULL,
    "dateAdded" INTEGER NOT NULL,
    "isAdmin"   TEXT NOT NULL DEFAULT 'false'
)'''
class User(db.Model, UserMixin):
    uid = db.Column(db.Integer, nullable=False, primary_key=True, autoincrement=True, unique=True)
    username = db.Column(db.String(10), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    dateAdded = db.Column(db.Integer, nullable=False)
    isAdmin = db.Column(db.String(5), nullable=False, default='false')
    postCount = db.Column(db.Integer, nullable=False, default=0)
    items_addedByUid = db.relationship('Items', cascade='all,delete')
    session_uid = db.relationship('Sessions', cascade='all,delete')
    removedItems_removedByUid = db.relationship('RemovedItems', cascade='all,delete',
                                                foreign_keys='RemovedItems.removedByUid')
    removedByUid_addedByUid = db.relationship('RemovedItems', cascade='all,delete',
                                              foreign_keys='RemovedItems.addedByUid')

    # Override get_id method inherited from UserMixin
    def get_id(self):
        return self.uid


'''
CREATE TABLE "RemovedItems" (
    "rid"   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    "removedByUid"  INTEGER NOT NULL,
    "addedByUid"    INTEGER NOT NULL,
    "item"  TEXT NOT NULL,
    "dateAdded" INTEGER NOT NULL,
    "dateRemoved"   INTEGER NOT NULL,
    FOREIGN KEY("addedByUid") REFERENCES "User"("uid"),
    FOREIGN KEY("removedByUid") REFERENCES "User"("uid")
)'''
class RemovedItems(db.Model):
    rid = db.Column(db.Integer, nullable=False, primary_key=True, autoincrement=True)
    removedByUid = db.Column(db.Integer, db.ForeignKey(User.uid, ondelete='CASCADE'), nullable=False)
    addedByUid = db.Column(db.Integer, db.ForeignKey(User.uid, ondelete='CASCADE'), nullable=False)
    item = db.Column(db.String(200), nullable=False)
    dateAdded = db.Column(db.Integer, nullable=False)
    dateRemoved = db.Column(db.Integer, nullable=False)


'''
CREATE TABLE "Items" (
    "iid"   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    "addedByUid"    INTEGER NOT NULL,
    "item"  TEXT NOT NULL,
    "dateAdded" INTEGER NOT NULL,
    FOREIGN KEY("addedByUid") REFERENCES "User"("uid")
)'''
class Items(db.Model):
    iid = db.Column(db.Integer, primary_key=True, nullable=False, unique=True, autoincrement=True)
    addedByUid = db.Column(db.Integer, db.ForeignKey(User.uid, ondelete='CASCADE'), nullable=False)
    item = db.Column(db.String(200), nullable=False)
    dateAdded = db.Column(db.Integer, nullable=False)


'''
CREATE TABLE "Sessions" (
    "session"   TEXT NOT NULL UNIQUE,
    "uid"   INTEGER NOT NULL,
    "dateIssued"    INTEGER NOT NULL,
    "laseUsed"  INTEGER NOT NULL,
    "ip"    TEXT NOT NULL,
    "useragent" TEXT NOT NULL,
    PRIMARY KEY("session"),
    FOREIGN KEY("uid") REFERENCES "User"("uid")
)'''
class Sessions(db.Model):
    sid = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    uid = db.Column(db.Integer, db.ForeignKey(User.uid, ondelete='CASCADE'), nullable=False)
    ip = db.Column(db.String(15), nullable=False)
    useragent = db.Column(db.String(500), nullable=False)
    issueddate = db.Column(db.Integer, nullable=False)
