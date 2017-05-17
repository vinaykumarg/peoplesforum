import os
import re
import cgi
import webapp2
import jinja2
import logging
import utils
import models
from models import User, Querydbase, Reply
from google.appengine.ext import db
import datetime
count = 0
# Set log level to debug
logging.getLogger().setLevel(logging.ERROR)

# Initialize jinja templating environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# Wiki page model for google datastore
class Wiki(db.Model):
    urlpath = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

def wiki_key(name = 'default'):
    return db.Key.from_path('wikis', name)

def get_wikipage_by_path(pagepath):
    return Wiki.gql("WHERE urlpath = '%s'"%pagepath).get()

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Signup(WikiHandler):

    def render_signup(self, 
                      username="", 
                      nameerror="", 
                      passworderror="", 
                      verifyerror="",
		      email="", 
                      emailerror=""):
        self.render("wiki-signup-form.html", 
                    username=username, 
                    nameerror=nameerror,
                    passworderror=passworderror, 
                    verifyerror=verifyerror,
                    email=email, 
                    emailerror=emailerror)

    # given user_id and pwhash, create user_id cookie
    def put_user_id_cookie(self, user_id, pwhash):
        hash = pwhash.split('|')[0]
        return '%s|%s'%(user_id, hash)

    def get(self):
        self.render_signup()

    def post(self):
        user_name     = self.request.get('username')
        user_password = self.request.get('password')
        user_verify   = self.request.get('verify')
        user_email    = self.request.get('email')

        name     = utils.valid_username(user_name)
        password = utils.valid_password(user_password)
        verify   = utils.valid_verify(user_verify, user_password)
        email    = utils.valid_email(user_email)

        nameerror = passworderror = verifyerror = emailerror = ""

        if not name:
            nameerror = "That's not a valid username"

        if not password:
            passworderror = "That's not a valid password"

        if password and not verify:
            verifyerror = "Your passwords didn't match"

        if user_email and not email:
            emailerror = "That's not a valid email"

        if (not (name and password and verify)) or (user_email and not email):
            self.render_signup(user_name, nameerror, passworderror, 
                               verifyerror, user_email, emailerror)
        else:
            # lookup user
            u = User.gql("WHERE username = '%s'"%user_name).get()

            # If user already exists
            if u:
                nameerror = "That user already exists"
                self.render_signup(user_name, nameerror, passworderror, 
                                   verifyerror, user_email, emailerror)		
            else:
                # make salted password hash
                h = utils.make_pw_hash(user_name, user_password)
                u = User(username=user_name, password=h)
                u.put()
                user_id = u.key().id()
                uid_cookie = str(self.put_user_id_cookie(user_id, h))
                self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/"%uid_cookie)
                self.redirect("/")

class Login(WikiHandler):

    def render_login(self, username="", error=""):
        self.render("wiki-login-form.html", username=username, error=error)

    # given user_id and pwhash, create user_id cookie
    def put_user_id_cookie(self, user_id, pwhash):
	    hash = pwhash.split('|')[0]
	    return '%s|%s'%(user_id, hash)

    def get(self):
	    self.render_login()

    def post(self):
        user_name     = self.request.get('username')
        user_password = self.request.get('password')

        # Look up user
        u = models.get_user_by_name(user_name)
        if not u or not utils.valid_pw(user_name, user_password, u.password):
           error = "Invalid login"
           self.render_login(user_name, error)
        else:
            user_id = u.key().id()
            uid_cookie = str(self.put_user_id_cookie(user_id, u.password))
            self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/"%uid_cookie)
            self.redirect("/showqu")            


class Logout(WikiHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/")            

#
# We arrive here either because 1) a user is logged in and clicked on the edit link for a page or 2) someone directly
# typed in the _edit link but is not logged in.
# We validate the user is logged in and if so we display the edit page, otherwise redirect to the wiki page.
# we take the new content entered in the post form and update the page contents.
#
class addcomment(WikiHandler):
    def post(self):
        a = self.request.get("key")
        self.response.out.write(a)
    def rendercom(self, key):
        
        self.render("addcomment.html", key = key)



class postquestion(WikiHandler):
    def get(self):
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        if username:
            self.render("askquestion.html",user = username)
        else:
            self.redirect("/")
    def post(self):
        
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        question = self.request.get('question')
        subject = self.request.get('subject')

        if question:
            published = datetime.datetime.now()
            created = datetime.datetime.now()
            count = Querydbase.all().count()
            g = Querydbase(questionid = str(count), username = username, subject = subject, question = question);
            count = count+1
            g.put()
            # self.response.out.write(subject)
            self.redirect('/')
        else :

            self.redirect("/postquestion")
        

class show(WikiHandler):
    """docstring for show"""
    def get(self):
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        # logging.error("wikipage get, cookie %s  pagepath %s\n", cookie, pagepath)
        if username:
            a = "Datastructures"
            h = Querydbase.all()
            com = Reply.all()
            f = datetime.timedelta(0,19800)
            self.render("base.html",h = h, f =f, user = username, comment = com, subject = a)
        else :
            self.response.out.write("Sdf")
class showos(WikiHandler):
    """docstring for show"""
    def get(self):
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        # logging.error("wikipage get, cookie %s  pagepath %s\n", cookie, pagepath)
        if username:
            a = "OperatingSystems"
            h = Querydbase.all().filter("subject =", a)
            com = Reply.all()
            f = datetime.timedelta(0,19800)
            self.render("base.html",h = h, f =f, user = username, comment = com, subject= a)
        else :
            self.response.out.write("Sdf")

class showc(WikiHandler):
    """docstring for show"""
    def get(self):
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        # logging.error("wikipage get, cookie %s  pagepath %s\n", cookie, pagepath)
        if username:
            a = "C"
            h = Querydbase.all().filter("subject =", a)
            com = Reply.all()
            f = datetime.timedelta(0,19800)
            self.render("base.html",h = h, f =f, user = username, comment = com, subject = a)
        else :
            self.response.out.write("Sdf")
class showjava(WikiHandler):
    """docstring for show"""
    def get(self):
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        # logging.error("wikipage get, cookie %s  pagepath %s\n", cookie, pagepath)
        if username:
            a = "Java"
            h = Querydbase.all().filter("subject = ", a)
            com = Reply.all()
            f = datetime.timedelta(0,19800)
            self.render("base.html",h = h, f =f, user = username, comment = com, subject= a)
        else :
            self.response.out.write("Sdf")
class showweb(WikiHandler):
    """docstring for show"""
    def get(self):
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        # logging.error("wikipage get, cookie %s  pagepath %s\n", cookie, pagepath)
        if username:
            a = "Webprogramming"
            h = Querydbase.all().filter("subject = ", a)
            com = Reply.all()
            f = datetime.timedelta(0,19800)
            self.render("base.html",h = h, f =f, user = username, comment = com, subject= a)
        else :
            self.response.out.write("Sdf")
class koke(WikiHandler):
    def post(self):
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        questionid = self.request.get("foo")
        address_k = db.Key.from_path('Querydbase', int(questionid))
        address = db.get(address_k)
        address.likes = address.likes+1
        address.put()
        self.redirect('/showqu')

class commentpage(WikiHandler):
    def post(self):
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        a = self.request.get("key")
        b = self.request.get("comment")
        a = a.replace(" ", "")
        u = Querydbase.gql("WHERE questionid = '%s'"%a).get()
        cor = Reply(post=a, author=username, text=b)
        cor.put()
        self.redirect('/showqu')
        
class WikiPage(WikiHandler):
    def get(self):
        cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        # logging.error("wikipage get, cookie %s  pagepath %s\n", cookie, pagepath)
        # editurl = "/_edit" + pagepath
        # mywikipage = get_wikipage_by_path(pagepath)
        # If page already exists in Wiki, retreive content and display
        if username:
            self.redirect("/showqu")
        else:
            self.render("index.html")

DEBUG = True
jaffa = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/postquestion', postquestion),
                               ('/showqu', show),
                               ("/showos", showos),
                               ("/showjava", showjava),
                               ("/showc", showc),
                               ("/showweb", showweb),
                               # ('/_edit' + PAGE_RE, EditPage),
                               ("/addcomment" ,addcomment),
                               ("/poscomment", commentpage),
                               ("/like", koke),
                               # (PAGE_RE, WikiPage),
                               ('/', WikiPage)
                               ],
                              debug=DEBUG)


