#list and dictionary for date validation
months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']

month_abbvs = dict((m[:3].lower(), m) for m in months)

#basic date validation                       
def valid_day(day):
    if day and day.isdigit():
        day = int(day)
        if day > 0 and day <= 31:
            return day

def valid_month(month):
    if month:
        short_month = month[:3].lower()
        return month_abbvs.get(short_month)

def valid_year(year):
    if year and year.isdigit():
        year = int(year)
        if year > 1900 and year < 2020:
            return year

#html escaping
import cgi

def escape_html(s):
    return cgi.escape(s, quote = True)

#rot13 cypher

def rot13(s):
    rot_s = ''
    for e in s:
        if ord('a') <= ord(e) <= ord('z'):
            rot_s = rot_s + chr(((ord(e) - 84) % 26) + 97)
        elif ord('A') <= ord(e) <= ord('Z'):
            rot_s = rot_s + chr(((ord(e) - 52) % 26) + 65)
        else:
            rot_s = rot_s + e
    return rot_s

#reg exes for password,usrname,email checks
import re
from string import letters

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return USER_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#hashing passwords
import random
import string
import hashlib

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

#hashing cookies (so that cookie fraud can't happen)
import hmac
from somewheresafe import secret

def hash_str(s):
    return hmac.new(secret,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" %(s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

#check if user already in DB
from google.appengine.ext import db

def user_exists(username):
    users = db.GqlQuery("SELECT * FROM User")
    for user in users:
        if user.username == username:
            return True

# get coordinates from google maps from user's IP
import urllib2
from xml.dom import minidom
import json

IP_URL = "http://www.datasciencetoolkit.org/ip2coordinates/" #"http://api.hostip.info/?ip=" 
def get_coords(ip):
    #ip = "4.2.2.2" # hard-coded IP for dev | comment out before deploying
    #ip = "23.24.209.141" # Udacity's office IP
    ip = "86.173.48.96" # my IP
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except urllib2.URLError:
        return # want logging in here to cheat if ip service is down.

    if content:
        d = json.loads(content)
        #d = minidom.parseString(content)
        lat = d[ip]["latitude"]
        lon = d[ip]["longitude"]
        if lat and lon: 
        #coords = d.getElementsByTagName("gml:coordinates")
        #if coords and coords[0].childNodes[0].nodeValue:
        #    lon, lat = coords[0].childNodes[0].nodeValue.split(',')
            return db.GeoPt(lat, lon)

# create static gmaps using list of coordinates.
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
    markers = '&'.join('markers=%s,%s' % (p.lat, p.lon)
                         for p in points)
    return GMAPS_URL + markers
