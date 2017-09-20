#Import all the requirement library for the application

import os
import re
import random
import hashlib
import hmac
from string import letters
import datetime
import time
import webapp2
import jinja2
import logging

from google.appengine.ext import db


#loading the jinja invironment for using in the application
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
#Special secret word use to encrypt the password
secret = 'fart'

#Function use to render the template html file to the webpage
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#Function us to encrypt the password
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#Function us to check if password is valided.
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# This class handle all the webpage request to the website
class BlogHandler(webapp2.RequestHandler):
    
    #initialized the current username of the website to ""
    currentusername = ""
    
    # function use to write the template to client
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    # function use to load the template and display it on the webpage
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    # funtion use to write the template to the webpage
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # function use to store the username in to cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=30) # 30 days from now
        expired_date = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; expires=%s ;Path=/' % (name, cookie_val, expired_date))

    # function use to check if there is username store in the cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # function uses to store username into cookie
    def login(self, user):
        logging.info('login called')
        self.set_secure_cookie('user_id', str(user.key().id()))

    # function use to logout by clearing username from cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    # this function is start when the application is started
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        global currentusername

        if self.user:
            self.currentname = User.by_id(int(uid)).name
            currentusername = User.by_id(int(uid)).name
        else:
            self.currentname =""
            currentusername = ""
    
    # function use to return the current username who is login 
    @classmethod
    def getcurrentuser(cls):
        return currentusername

    # function use to set the delete the current user who is login
    @classmethod
    def resetcurrentuser(cls):
        global currentusername
        currentusername = ""

# This is the main function where the program start
class MainPage(BlogHandler):
    def get(self):
        self.redirect("/blog")
        return


# function uses to make random string for creating password
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# function uses to encrypt the password
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# function use to valid the username and password with the given username 
# and password and hashed password 
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# function use to get user's key
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# The User entity
# The User entity is the data structure for user data. It has name, 
# pw_hash and email properties
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    #get the user by user id
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())
    #get the user from the database filter by name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    # User's method use to add user into datastore
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    # Function uses to check if the user data is valid in the database
    # if so return the User object
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

#function uses to return the blog key
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

#function uses to return the like key
def like_key(name = 'default'):
    return db.Key.from_path('likes', name)

#function uses to return the comment key
def comment_key(name = 'default'):
    return db.Key.from_path('comments', name)

#the Post data structure and method
# this set the entity Post in the datastore
class Post(db.Model):
    username = db.StringProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        #replace the new line with <br> for render into html
        self._render_text = self.content.replace('\n', '<br>')      
        posts= self
        #get the comments for the post
        comments = Comment.getComment(str(posts.key().id()))
        #get all likes for the post
        likes = Like.alllikes(posts.username,str(posts.key().id()))
        #check if the current user like the post
        islike = Like.is_user_likepost(posts.username, str(posts.key().id()))
        currentuser = BlogHandler.getcurrentuser()
        #render the post.html template file to the html client file
        return render_str("post.html", p = self, commentcount = comments.count() , likecount = likes.count(), currentuser = currentuser , isuserlike = islike)
    
    # this function render the signle_post.html file when user click on the link of detail post
    def render_singlepost(self, currentuser=""):
     #replace the new line with <br> for render into html
        self._render_text = self.content.replace('\n', '<br>')      
        posts= self
        #get the comments for the post
        comments = Comment.getComment(str(posts.key().id()))
        #get all likes for the post
        likes = Like.alllikes(posts.username,str(posts.key().id()))
        #check if the current user like the post
        islike = Like.is_user_likepost(posts.username, str(posts.key().id()))
        currentuser = BlogHandler.getcurrentuser()
        #render the post.html template file to the html client file
        return render_str("single_post.html", p = self, commentcount = comments.count() , likecount = likes.count(), currentuser = currentuser , isuserlike = islike)
        #return render_str("single_post.html", p = self, currentuser = currentuser)

#Comment entity
class Comment(db.Model):
    username = db.StringProperty(required = True)
    postid = db.StringProperty(required = True)
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    #method to get all comments of a post by postid
    @classmethod
    def getComment(cls,postid):
        #return User.get_by_id(uid, parent = users_key())
        return Comment.all().filter('postid = ', postid)

    #method to delete post by postid
    @classmethod
    def deletecomment(cls, commentid):
            #comment = Comment.all().filter('id = ' , commentid)
            #logging.info(comment.count())

            key = db.Key.from_path('Comment', commentid, parent= comment_key())
            result = db.delete(key)            
            logging.info('delete comment : %s' , comment_key())
            return True

#class to add or update the comment for a post to database
class CommentPost(BlogHandler):
    def get(self):
        if not self.user:           
            self.redirect("/login")
            return

    def post(self):
        if not self.user:
            self.redirect("/login")
            return
        editstatus = self.request.get('editstatus')
        comment = self.request.get('comment')
        postid = self.request.get('postid')
        username=self.request.get('username')

        if comment and username and postid:
            if editstatus == 'No':
                c = Comment(parent = comment_key(), username = username, comment = comment, postid = postid)
                c.put()
                commentid = c.key().id()
            else:
                commentid = self.request.get('commentid')
                editcomment = comment_exists(commentid)
                if editcomment:
                    editcomment.comment = comment
                    editcomment.put()  
            
            self.redirect('/blog/%s' % postid)
            return
        else:
            self.redirect('/blog/%s' % postid)
            return

#class to  handle the delete comment request
class CommentDelete(BlogHandler):
    def get(self):
        if not self.user:
            self.redirect("/login")
            return

        commentid = self.request.get('commentid')
        postid = self.request.get('postid')

        comment = comment_exists(commentid)
        userowns_comment = user_owns_comment(BlogHandler.getcurrentuser(),commentid)
        if comment and userowns_comment:
                Comment.deletecomment(int(commentid))
                return self.redirect('/blog/%s' % postid)
        else:
            return self.redirect('/blog/%s' % postid)
            

#handle the commend edit request
class CommentEdit(BlogHandler):
    
    def get(self):
        if self.user:
            postid = self.request.get('postid')
            commentid = self.request.get('commentid')

            post = post_exists(postid)
            editcomment = comment_exists(commentid)
            userowns_comment = user_owns_comment(BlogHandler.getcurrentuser(),commentid)

            if not post:
                self.error(404)
                return
            if editcomment and userowns_comment:
                comments = Comment.all().filter('postid = ', str(postid)).order('-created')
                self.render("permalink.html", post = post , currentuser= self.currentname, comments = comments, editcomment = editcomment, isedit='Yes')
                return
            else:
                return self.error(404)             
        else:
            return self.redirect("/login")
           
#this where the blog start by displaying all posts for the front page
class BlogFront(BlogHandler):
    def get(self):
        logging.info("Blog front %s", self.user)
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

#this where the detail for each post is display for individual post
class PostPage(BlogHandler):
    def get(self, post_id):
        post = post_exists(post_id)
        if not post:
            self.error(404)
            return
        comments = Comment.all().filter('postid = ', str(post_id)).order('-created')       
        self.render("permalink.html", post = post , currentuser= self.currentname, comments = comments , isedit = 'No')

#handle the new post request
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
            return
        else:
            self.redirect("/login")
            return

    def post(self):
        if not self.user:
            self.redirect('/blog')
            return
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), username = self.user.name, subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

#handle the post edit request
class PostEdit(BlogHandler):
    
    def get(self, post_id):
        if self.user:
            post = post_exists(post_id)

            if not post:
                self.error(404)
                return

            self.render("editpost.html", post = post)
        else:
            self.redirect("/login")
            return

    def post(self):
        if not self.user:
            self.redirect('/login')
            return

        post_id = self.request.get("post_id")
        post = post_exists(post_id)

        if not post:
            self.error(404)
            return
        
        userowns_post = user_owns_post(BlogHandler.getcurrentuser(),post_id)

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content and userowns_post:
            post.subject = subject
            post.content = content
            
            #p = Post(parent = blog_key(), key_id = post_id, username = self.user.name, subject = subject, content = content)
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("editpost.html", username=username, subject=subject, content=content, error=error)

#handle post delete request
class DeletePost(BlogHandler):  
    def get(self, post_id):
        if self.user:
            post = user_owns_post(BlogHandler.getcurrentuser(), post_id)
            if post:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                db.delete(key)
            self.redirect('/blog')
        else:
            self.redirect("/login")
            return

# Like entity uses to store user like data
class Like(db.Model):
    username = db.StringProperty(required = True)
    postid = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
    #method to store user like data into datastore
    @classmethod
    def user_like_post(cls, username, post_id):
        like = Like(username = username, postid = post_id)
        like.put()

    #method uses to check if user like post or not
    @classmethod
    def is_user_likepost(cls, username, post_id):
        like = Like.all().filter('postid = ', str(post_id))
        logging.info("Count post = %s" , like.count())
        like.filter('username = ', username)
        #logging.info("Count after username filter = %s" , like.count())
        if like.count() > 0:
            return True
        else:
            return False
    
    #method uses to return all like from the database for a post
    @classmethod
    def alllikes(cls, username, post_id):
        likes = Like.all().filter('postid = ', str(post_id) )
        return likes    

    #method uses to delete like from database
    @classmethod
    def unlike(cls, username, post_id):
            like = Like.all().filter('postid = ', str(post_id))
            like.filter('username = ', username)
            if like.count() > 0 :
                tobedeletelike = like.get()
                key = db.Key.from_path('Like', tobedeletelike.key().id())
                db.delete(key)           
            return True
       
#to handle when user likes the post
class userLike(BlogHandler):
    def get(self):
        if self.user:
            logging.info("User is logged in %s" , self.user)
        else:
            logging.info("User is not logged in %s" , self.user)
            self.redirect('/login')
            return
 
        postid = self.request.get('postid')
        username=self.request.get('username')        

        if username and postid:
            islike = Like.is_user_likepost(username , postid)
            if not islike:
                l = Like( username = username, postid = postid, like= True)
                l.put()
                likeid = l.key().id()
            self.redirect('/blog')
        else:
            error = "can't like this post!"

# to handle when user unlike the post
class userunlike(BlogHandler):
    def get(self):
        if not self.user:
            self.redirect("/login")
            return

        postid = self.request.get('postid')
        username=self.request.get('username')        

        if username and postid:
            islike = Like.unlike(username , postid)
            self.redirect('/blog')
        else:
            error = "can't unlike this post!"
            logging.info(error)
            #self.redirect('/blog/%s' % postid)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#Handle the user signup process
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

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

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

# implement to insert user information into database
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

#Render loging form and verify the user information againts the database
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

# Handle the user logout process.
class Logout(BlogHandler):
    def get(self):
        BlogHandler.resetcurrentuser()
        self.logout()
        self.redirect('/blog')

def post_exists(postid):
    key = db.Key.from_path('Post', int(postid),parent=blog_key())
    post = db.get(key)
    logging.info("post is %s" , post)
    if post:
        return post  
    else:
        return


def comment_exists(commentid):
     commentkey = db.Key.from_path('Comment', int(commentid), parent=comment_key())
     comment = db.get(commentkey)
     if comment:
         return comment
     else:
         return

def user_owns_post(username,postid):
    key = db.Key.from_path('Post', int(postid),parent=blog_key())
    post = db.get(key)
    if post:
        if (post.username == username ):
            return post
        else:
            return
    else:
        return

def user_owns_comment(username, commentid):
     commentkey = db.Key.from_path('Comment', int(commentid), parent=comment_key())
     comment = db.get(commentkey)
     if comment:
         logging.info('data username =%s , current username =%s' , comment.username,username)
         if (comment.username == username):
             return comment
         else:
             return
     else:
         return

        
 
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/deletecomment', CommentDelete),
                               ('/editcomment', CommentEdit),
                               ('/unlikepost', userunlike ),
                               ('/comment', CommentPost),
                               ('/likepost', userLike),
                               ('/editpost/?', PostEdit),
                               ('/editpost/([0-9]+)', PostEdit),
                               ('/deletepost/([0-9]+)', DeletePost),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
