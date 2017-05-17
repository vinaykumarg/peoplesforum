from google.appengine.ext import db
import datetime
# User model for google datastore
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    created  = db.DateTimeProperty(auto_now_add = True)

def get_user_by_name(user_name):
    return User.gql("WHERE username = '%s'"%user_name).get()


class Querydbase(db.Model):
    questionid = db.StringProperty(required=True)
    username = db.StringProperty(required=True)
    subject = db.StringProperty(required = True)
    question = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    published = db.DateTimeProperty(auto_now_add = True)
    likes = db.IntegerProperty(default= 0)

    def get_all(username):
        return Querydbase.gql("select * from Querydbase ").get()

class Reply(db.Model):
    post = db.StringProperty(required=True)
    author = db.StringProperty(required = True)
    text = db.StringProperty(required = True)
    created_date = db.DateTimeProperty(auto_now_add = True)
    approved_comment = db.BooleanProperty(default=True)