import webapp2
from utils import escape_html, rot13
from utils import valid_username, valid_password, valid_email
from utils import USER_RE,PASS_RE, EMAIL_RE
from utils import hash_str, make_secure_val, check_secure_val
from utils import user_exists, make_salt, make_pw_hash, valid_pw
from utils import IP_URL, get_coords, gmaps_img
import cgi
import logging # add logging.debug ('some string') <prints in console
import json

from google.appengine.api import users, memcache
from google.appengine.ext import db

import jinja2
import os


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)
    
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
    
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def site_login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def site_logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):###5
            self.format = 'json'
        else:
            self.format = 'html'

# Home Page
class MainPage(webapp2.RequestHandler):
    def get(self):
        self.response.out.write(render_str('base_site.html'))
        

# sign-up res and verification NOW WITH DB!
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    account_created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls,uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        # could use gql here, instead used datastore's procedural code
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class SignUp(BaseHandler):
  def get(self):
    self.render('signup-form.html')

  def post(self):
    have_error = False
    self.username = self.request.get('username')
    self.password = self.request.get('password')
    self.verify = self.request.get('verify')
    self.email = self.request.get('email')
    
    params = dict(username = self.username,
                      email = self.email)
    
    if not valid_username(self.username):
        params['error_username'] = "That's not a valid username."
        have_error = True

    u = User.by_name(self.username)
    if u:
        params['error_username'] = "That username has been taken."
        have_error = True
    
    if not valid_password(self.password):
        params['error_password'] = "That's not a valid password."
        have_error = True
    elif self.password != self.verify:
        params['error_verify'] = "Your passwords didn't match."
        have_error = True
    
    if not valid_email(self.email):
        params['error_email'] = "that's not a valid email"
        have_error = True
    
    if have_error:
        self.render('signup-form.html', **params)
    else:
        u = User.register(self.username, self.password, self.email)
        u.put()
                
        self.site_login(u)
        self.redirect('/blog/welcome') #?username=' + username)
        #self.redirect('/blog/dbdisplay')

# make sure this is working!
class DBDisplay(BaseHandler):
    def render_db(self):
        users = db.GqlQuery("SELECT * FROM User")
        
        self.render('dbdisplay.html', users = users)
    
    def get(self):
        self.render_db()

class Login(BaseHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u= User.login(username, password)
        if u:
            self.site_login(u)
            self.redirect('/blog/welcome')
        else:
            error = 'Invalid login'
            self.render('login-form.html', error = error)

class Logout(BaseHandler):
    def get(self):
        self.site_logout()
        #self.redirect('/blog/signup')
        self.redirect('/')

class Welcome(BaseHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)#.split('|')[0])
        else:
            self.redirect('/blog/signup')

# Rot13
class Rot13Page(BaseHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        text = self.request.get('text')
        if text:
            self.render('rot13-form.html', text = rot13(text))
        else:
            self.redirect('/rot13')

# Guest Book
class GuestMain(BaseHandler):
    def get(self):
        user = users.get_current_user()

        if user:
            self.response.headers['Content-Type'] = 'text/plain'
            self.write('Hello, ' + user.nickname())
        else:
            self.redirect(users.create_login_url(self.request.uri))

class Guestbook(BaseHandler):
    def post(self):
        self.write('<html><body>You wrote:<pre>')
        self.write(cgi.escape(self.request.get('content')))
        self.write('</pre></body></html>')

# Ascii art
#def art_key(group = 'default'):
#    return db.Key.from_path('arts', group)

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author_loc = db.GeoPtProperty()

def top_arts(update = False):
    key = 'top'
    arts = memcache.get(key)
    if arts is None or update:
        logging.error("DB QUERY")
        arts = db.GqlQuery("SELECT * "
                           "FROM Art "
                           "ORDER BY created DESC "
                           "LIMIT 10")
                           #art_key)WHERE ANCESTOR IS :1

    # prevent running multiple arts queries on Art db (expensive!).
        arts = list(arts)
        memcache.set(key, arts)
    return arts

class Ascii(BaseHandler):
    def render_ascii(self, title="", art="", error=""):
        arts = top_arts()

        # if we have arts coords, make an image url
        img_url = None
        points = filter(None, (a.author_loc for a in arts))
        if points:
            img_url = gmaps_img(points)

        self.render('asciichan.html', title=title, art=art,
                    error=error, arts=arts, img_url=img_url)
    
    def get(self):
        """ print IP """
        #self.write(self.request.remote_addr)
        """ print coords at top of page """
        #self.write(repr(get_coords(self.request.remote_addr)))

        return self.render_ascii()
    
    def post(self):
        title = self.request.get('title')
        art = self.request.get('art')

        if title and art:
            p = Art(title = title, art = art)
            coords = get_coords(self.request.remote_addr) # lookup the user's coordinates from their IP
            if coords:
                p.author_loc = coords # if we have coordinates, add them to Art
            
            p.put()
            # rerun the query and update the cache
            top_arts(True)

            self.redirect('/ascii')
        else:
            error = "we need both a title and some artwork!"
            self.render_ascii(title, art, error)

# Blog
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

    def as_dict(self):###5
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class BlogFront(BaseHandler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        if self.format == 'html':###5
            self.render('front.html', posts = posts)
        else:
            return self.render_json([p.as_dict() for p in posts])

class NewPost(BaseHandler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render('newpost.html', subject = subject, content = content, error = error)

class Permalink(BaseHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if self.format == 'html':###5
            self.render("permalink.html", post = post)
        else:
            self.render_json(post.as_dict())

# counting visits with Cookies
class Count(BaseHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)

        visits += 1

        new_cookie_val = make_secure_val(str(visits))
        
        self.response.headers.add_header('Set-Cookie', 'visits=%s'
                                         % new_cookie_val)

        if visits == 10:
            self.write("Almost there, keep going!")
        elif visits == 20:
            self.response.headers['Content-Type'] = 'text/html'
            self.response.out.write('<img src="http://media.tumblr.com/tumblr_l0xi7u49bX1qzso2v.jpg" alt="cookie">Please don\'t eat me!')
        else:
            self.write("I've seen you %s times.." % visits)


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/rot13', Rot13Page),
                               ('/guest', GuestMain),
                               ('/sign', Guestbook),
                               ('/ascii', Ascii),
                               ('/blog/?(?:\.json)?', BlogFront),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)(?:\.json)?', Permalink),
                               ('/cookie', Count),
                               ('/blog/signup', SignUp),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/welcome', Welcome),
                               ('/blog/dbdisplay', DBDisplay)
                               ],
                              debug=True)