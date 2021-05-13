from WebApp import db, bcrypt
from WebApp.models import User, Sessions, RemovedItems, Items
from datetime import datetime
from WebApp.models import User, Items, RemovedItems
import time
import confuse

'''
Gets the seconds since epoch
'''
def getEpoch():
    return int(time.time())


'''
Converts an epoch time stamp to a readable date
@Pram epoch :: int
'''
def epochToDate(epoch):
    return datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M')


# Make the admin
def makeAdmin():
    # get one-time default password
    config_file = confuse.Configuration('WebApp', __name__)
    config_file.set_file('config.yml')
    random_password = config_file['WebApp']['default_admin_password'].get()
    # Hash password
    hashed_password = bcrypt.generate_password_hash(random_password).decode('utf-8')
    # Add user, ID will AI
    admin = User(username='admin', password=hashed_password, dateAdded=getEpoch(), isAdmin='true')
    # Commit user
    db.session.add(admin)
    db.session.commit()


def addItem(text):
    anItem = Items(addedByUid=1, item=text, dateAdded=getEpoch())
    db.session.add(anItem)
    db.session.commit()


# Add the triggers
def addTrigger():
    # The Sql that will add a trigger
    # The trigger adds one to the user's post count when they post
    updatePostCountSQL = '''
CREATE TRIGGER updatePostCount 
after INSERT 
on items
BEGIN
    UPDATE user
    SET postCount = user.postCount+1
    WHERE user.uid in
    (
        select addedByUid
        from items
        where iid in 
            (select max(iid)
            from items)
    );
END;'''

    db.session.execute(updatePostCountSQL)
    db.session.commit()


# This will add the views we need
def addViews():
    # itemsPage SQL we will run
    addItemsPageViewSql = '''
CREATE VIEW itemsPage
AS
SELECT Items.iid, User.username, Items.item, Items.dateAdded
from Items
inner join User on Items.addedByUid = User.uid;'''

    # View for removed items page
    # Outputs a table with rid, addedBy, item, dateAdded, dateRemoved, removedBy
    removedItemsPageViewSql = '''
CREATE VIEW removedItemsPage
AS
select * from 
(
    SELECT removed_items.rid, user.username as addedBy ,removed_items.item, removed_items.dateAdded, removed_items.dateRemoved
    from removed_items
    inner join User on removed_items.addedByUid = user.uid
)
NATURAL join
(   
    SELECT removed_items.rid, user.username as removedBy,removed_items.item, removed_items.dateAdded, removed_items.dateRemoved
    from removed_items
    inner join User on removed_items.removedByUid = user.uid
);'''

    # Makes view for login log
    sessionLogViewSQL = '''
CREATE VIEW sessionLog
AS
SELECT Sessions.sid,Sessions.uid, User.username, Sessions.ip, Sessions.useragent, Sessions.issueddate
from Sessions
inner join User on Sessions.uid = User.uid;'''
    # Add view by running SQL
    db.session.execute(sessionLogViewSQL)
    db.session.execute(addItemsPageViewSql)
    db.session.execute(removedItemsPageViewSql)
    db.session.commit()


# Make the DB and add the admin
def makeDB():
    # make 
    db.create_all()
    # Add Triggers
    addTrigger()
    # Add views
    addViews()
    # add admin
    makeAdmin()
    # Make entry to tell them how add users
    addItem("Add another user! Go to settings > Add Invite Key")


# Log the user to get a login history
def logUser(request, current_user):
    recordLength = 30
    # Keep the logged sessions to 30
    sessions = db.session. \
        query(Sessions). \
        filter(Sessions.uid == current_user.uid). \
        order_by(Sessions.issueddate)
    # Check if session entries have exceeded the recordLength
    if sessions.count() > recordLength - 1:
        # Make a list of all the old sessions we want to remove
        removeSessions = sessions[:-(recordLength - 1)]
        # removed each logged session
        for log in removeSessions:
            db.session.delete(log)
        db.session.commit()
    # Make a new entry for the current login
    newSession = Sessions(
        uid=current_user.uid,
        ip=request.remote_addr,
        useragent=str(request.user_agent),
        issueddate=getEpoch()
    )
    # Add it to the database
    db.session.add(newSession)
    db.session.commit()


# Moves items to removedItems table
def removeItem(itemID, removedByUid):
    myitem = db.session.query(Items).filter(Items.iid == itemID).first()
    try:
        if myitem:
            removedItem = RemovedItems(
                removedByUid=removedByUid,
                addedByUid=myitem.addedByUid,
                item=myitem.item,
                dateAdded=myitem.dateAdded,
                dateRemoved=getEpoch()
            )
            db.session.add(removedItem)
            db.session.delete(myitem)
            db.session.commit()
    # TODO catch errors and be more helpful
    except:
        db.session.rollback()


def checkDefaultPassword():
    # TODO get default password
    # Get config
    config_file = confuse.Configuration('WebApp', __name__)
    config_file.set_file('config.yml')

    # get the admin
    user = User.query.filter_by(username='admin').first()

    # Check password
    if user and bcrypt.check_password_hash(user.password, config_file['WebApp']['default_admin_password'].get(str)):
        return True
    else:
        return False


