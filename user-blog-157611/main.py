import os
import webapp2
import jinja2
import codecs
import re
import hashlib
import hmac
import random
from string import letters
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

secret = 'UTCCwqJk7y2jWTpjtQzJqb2'

#=GLOBAL===================================================


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# get the key from blog table


def blog_key(name='default'):
    return db.Key.from_path('Blog', name)

# create a function to create secure cookie values


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# create a function to check secure cookie values


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# make salt for to secure the password


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# create password hash with name, password and the salt


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(''.join([name, pw, salt])).hexdigest()
    return '%s,%s' % (salt, h)

# check if password is valid by hashing and comparing to existing hashed
# password


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# get the key from User table


def users_key(group='default'):
    return db.Key.from_path('users', group)

# define what a valid username is
USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')


def valid_username(username):
    return username and USER_RE.match(username)

# define what a valid password is
PASS_RE = re.compile(r'^.{3,20}$')


def valid_password(password):
    return password and USER_RE.match(password)


#=HANDLER====================================================

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # securely set a cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # read the cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # set a cookie when the user logs in
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # reset the cookie when the user logs out
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # get the user from secure cookie when we initialize pages
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

#=USER====================================================

# create a database to store user info


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # get user with userid
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    # get user with name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    # register by hashing the password first
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)
    # login by checking the password first

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

#=BLOG====================================================

# create a database to store blog posts


class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.ReferenceProperty(User,
                                required=True,
                                collection_name="blogs")

    # show line breaks in blog content correctly when page is rendered
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", post=self)

#=LIKES====================================================

# create a database to store all likes


class Like(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)

    # get number of likes for a blog id
    @classmethod
    def by_blog_id(cls, blog_id):
        l = Like.all().filter('post =', blog_id)
        return l.count()

    # get number of likes for a blog and user id
    @classmethod
    def check_like(cls, blog_id, user_id):
        cl = Like.all().filter(
            'post =', blog_id).filter(
            'user =', user_id)
        return cl.count()


#=UNLIKES====================================================

# create a database to store all unlikes
class Unlike(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)

    # get number of unlikes for a blog id
    @classmethod
    def by_blog_id(cls, blog_id):
        ul = Unlike.all().filter('post =', blog_id)
        return ul.count()

    # get number of unlikes for a blog and user id
    @classmethod
    def check_unlike(cls, blog_id, user_id):
        cul = Unlike.all().filter(
            'post =', blog_id).filter(
            'user =', user_id)
        return cul.count()

#=COMMENTS====================================================

# create a database to store all comments


class Comment(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    text = db.TextProperty(required=True)

    # get number of comments for a blog id
    @classmethod
    def count_by_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id)
        return c.count()

    # get all comments for a specific blog id
    @classmethod
    def all_by_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id).order('created')
        return c

#=MAIN-PAGE====================================================


class MainPage(Handler):

    def get(self):
        # get all blog posts
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        # if there are any existing blog posts render the page with those posts
        if blogs:
            self.render("blogs.html", blogs=blogs)

#=NEW-POST====================================================


class NewPost(Handler):

    def get(self):
        # if user is logged in take us to newpost page
        if self.user:
            self.render("newpost.html")
        # otherwise take us to login page
        else:
            self.redirect("/login")

    def post(self):
        if self.user:
        
            # get the subject, content of the post and username of the user
            subject = self.request.get("subject")
            content = self.request.get("content").replace('\n', '<br>')
            user_id = User.by_name(self.user.name)

            # if we have a subject and content of the post add it to the database
            # and redirect us to the post page
            if subject and content:
                a = Blog(
                    parent=blog_key(),
                    subject=subject,
                    content=content,
                    user=user_id)
                a.put()
                self.redirect('/post/%s' % str(a.key().id()))
            # othersie throw and error to let the user know that both subject and
            # content are required
            else:
                post_error = "Please enter a subject and the blog content"
                self.render(
                    "newpost.html",
                    subject=subject,
                    content=content,
                    post_error=post_error)
        else:
             self.redirect("/login")
#=POST-PAGE====================================================


class PostPage(Handler):

    def get(self, blog_id):
        # get the key for the blog post
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)

        # if the post does not exist throw a 404 error
        if not post:
            self.error(404)
            return
        # get likes, unlikes, comments for the blog post
        likes = Like.by_blog_id(post)
        unlikes = Unlike.by_blog_id(post)
        post_comments = Comment.all_by_blog_id(post)
        comments_count = Comment.count_by_blog_id(post)

        # render the page and show blog content, likes, unlikes, comments, etc.
        self.render(
            "post.html",
            post=post,
            likes=likes,
            unlikes=unlikes,
            post_comments=post_comments,
            comments_count=comments_count)

    def post(self, blog_id):
        # get all the necessary parameters
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)
        user_id = User.by_name(self.user.name)
        comments_count = Comment.count_by_blog_id(post)
        post_comments = Comment.all_by_blog_id(post)
        likes = Like.by_blog_id(post)
        unlikes = Unlike.by_blog_id(post)
        previously_liked = Like.check_like(post, user_id)
        previously_unliked = Unlike.check_unlike(post, user_id)

        # check if the user is logged in
        if self.user:
            # if the user clicks on like
            if self.request.get("like"):
                # first check if the user is trying to like his own post
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    # then check if the user has liked this post before
                    if previously_liked == 0:
                        # add like to the likes database and refresh the page
                        l = Like(
                            post=post, user=User.by_name(
                                self.user.name))
                        l.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))
                    # otherwise if the user has liked this post before throw
                    # and error
                    else:
                        error = "You have already liked this post"
                        self.render(
                            "post.html",
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            error=error,
                            comments_count=comments_count,
                            post_comments=post_comments)
                # otherwise if the user is trying to like his own post throw an
                # error
                else:
                    error = "You cannot like your own posts"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        error=error,
                        comments_count=comments_count,
                        post_comments=post_comments)
            # if the user clicks on unlike
            if self.request.get("unlike"):
                # first check if the user is trying to unlike his own post
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    # then check if the user has unliked this post before
                    if previously_unliked == 0:
                        # add unlike to the unlikes database and refresh the
                        # page
                        ul = Unlike(
                            post=post, user=User.by_name(
                                self.user.name))
                        ul.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))
                    # otherwise if the user has unliked this post before throw
                    # and error
                    else:
                        error = "You have already unliked this post"
                        self.render(
                            "post.html",
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            error=error,
                            comments_count=comments_count,
                            post_comments=post_comments)
                # otherwise if the user is trying to unlike his own post throw
                # an error
                else:
                    error = "You cannot unlike your own posts"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        error=error,
                        comments_count=comments_count,
                        post_comments=post_comments)
            # if the user clicks on add comment get the comment text first
            if self.request.get("add_comment"):
                comment_text = self.request.get("comment_text")
                # check if there is anything entered in the comment text area
                if comment_text:
                    # add comment to the comments database and refresh page
                    c = Comment(
                        post=post, user=User.by_name(
                            self.user.name), text=comment_text)
                    c.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % str(post.key().id()))
                # otherwise if nothing has been entered in the text area throw
                # an error
                else:
                    comment_error = "Please enter a comment in the text area to post"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comments_count=comments_count,
                        post_comments=post_comments,
                        comment_error=comment_error)
            # if the user clicks on edit post
            if self.request.get("edit"):
                # check if the user is the author of this post
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    # take the user to edit post page
                    self.redirect('/edit/%s' % str(post.key().id()))
                # otherwise if the user is not the author of this post throw an
                # error
                else:
                    error = "You cannot edit other user's posts"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comments_count=comments_count,
                        post_comments=post_comments,
                        error=error)
            # if the user clicks on delete
            if self.request.get("delete"):
                # check if the user is the author of this post
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    # delete the post and redirect to the main page
                    db.delete(key)
                    time.sleep(0.1)
                    self.redirect('/')
                # otherwise if the user is not the author of this post throw an
                # error
                else:
                    error = "You cannot delete other user's posts"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comments_count=comments_count,
                        post_comments=post_comments,
                        error=error)
        # otherwise if the user is not logged in take them to the login page
        else:
            self.redirect("/login")

#=DELETE-COMMENT====================================================


class DeleteComment(Handler):

    def get(self, post_id, comment_id):
        # get the comment from the comment id
        comment = Comment.get_by_id(int(comment_id))
        # check if there is a comment associated with that id
        if comment:
            # check if this user is the author of this comment
            if comment.user.name == self.user.name:
                # delete the comment and redirect to the post page
                db.delete(comment)
                time.sleep(0.1)
                self.redirect('/post/%s' % str(post_id))
            # otherwise if this user is not the author of this comment throw an
            # error
            else:
                self.write("You cannot delete other user's comments")
        # otherwise if there is no comment associated with that id throw an
        # error
        else:
            self.write("This comment no longer exists")

#=EDIT-COMMENT====================================================


class EditComment(Handler):

    def get(self, post_id, comment_id):
        # get the blog and comment from blog id and comment id
        post = Blog.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id))
        # check if there is a comment associated with that id
        if comment:
            # check if this user is the author of this comment
            if comment.user.name == self.user.name:
                # take the user to the edit comment page and load the content
                # of the comment
                self.render("editcomment.html", comment_text=comment.text)
            # otherwise if this user is the author of this comment throw and
            # error
            else:
                error = "You cannot edit other users' comments'"
                self.render("editcomment.html", edit_error=error)
        # otherwise if there is no comment associated with that ID throw an
        # error
        else:
            error = "This comment no longer exists"
            self.render("editcomment.html", edit_error=error)

    def post(self, post_id, comment_id):
        # if the user clicks on update comment
        if self.request.get("update_comment"):
            # get the comment for that comment id
            comment = Comment.get_by_id(int(comment_id))
            # check if this user is the author of this comment
            if comment.user.name == self.user.name:
                # update the text of the comment and redirect to the post page
                comment.text = self.request.get('comment_text')
                comment.put()
                time.sleep(0.1)
                self.redirect('/post/%s' % str(post_id))
            # otherwise if this user is the author of this comment throw and
            # error
            else:
                error = "You cannot edit other users' comments'"
                self.render(
                    "editcomment.html",
                    comment_text=comment.text,
                    edit_error=error)
        # if the user clicks on cancel take the user to the post page
        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(post_id))

#=EDIT-POST====================================================


class EditPost(Handler):

    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)

        # check if the user is logged in
        if self.user:
            # check if this user is the author of this post
            if post.user.key().id() == User.by_name(self.user.name).key().id():
                # take the user to the edit post page
                self.render("editpost.html", post=post)
            # otherwise if this user is not the author of this post throw an
            # error
            else:
                self.response.out.write("You cannot edit other user's posts")
        # otherwise if the user is not logged in take them to the login page
        else:
            self.redirect("/login")

    def post(self, blog_id):
        # get the key for this blog post
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)

        # if the user clicks on update comment
        if self.request.get("update"):

            # get the subject, content and user id when the form is submitted
            subject = self.request.get("subject")
            content = self.request.get("content").replace('\n', '<br>')

            # check if this user is the author of this post
            if post.user.key().id() == User.by_name(self.user.name).key().id():
                # check if both the subject and content are filled
                if subject and content:
                    # update the blog post and redirect to the post page
                    post.subject = subject
                    post.content = content
                    post.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % str(post.key().id()))
                # otherwise if both subject and content are not filled throw an
                # error
                else:
                    post_error = "Please enter a subject and the blog content"
                    self.render(
                        "editpost.html",
                        subject=subject,
                        content=content,
                        post_error=post_error)
            # otherwise if this user is not the author of this post throw an
            # error
            else:
                self.response.out.write("You cannot edit other user's posts")
        # if the user clicks cancel take them to the post page
        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(post.key().id()))

#=SIGNUP====================================================


class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        # get the username, password, verify and emails field that the user
        # entered
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        # if the username is not valid throw an error
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        # if the password is not valid through an error
        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        # if the password and verify password don't match throw an error
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        # if we have an error render the page with the error and keep the
        # entered values
        if have_error:
            self.render("signup.html", **params)

        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

#=REGISTER====================================================


class Register(Signup):

    def done(self):
        # check if the username already exists
        u = User.by_name(self.username)
        # if the username already exists throw an error
        if u:
            error = 'That user already exists.'
            self.render('signup.html', error_username=error)
        # otherwise if the username doesn't exist yet add the user, login the
        # user in and redirect to welcome page
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

#=WELCOME====================================================


class Welcome(Handler):

    def get(self):
        # check is the user is logged in
        if self.user:
            # show the welcome message with the user's username
            self.render("welcome.html", username=self.user.name)
        # otherwise if the user is not logged in take the user to the login
        # page
        else:
            self.redirect("/login")

#=LOGIN====================================================


class Login(Handler):

    def get(self):
        self.render('login.html')

    def post(self):
        # get the username and password entered by the user
        username = self.request.get('username')
        password = self.request.get('password')

        # get the user account associated with that username and password
        u = User.login(username, password)

        # if there is a user account associated with that username and password
        if u:
            # login and redirect to the welcome page
            self.login(u)
            self.redirect('/welcome')
        # otherwise if there isn't a user account associated with that username
        # and password throw an error
        else:
            error = 'Invalid login'
            self.render('login.html', error=error)

#=LOGOUT====================================================


class Logout(Handler):

    def get(self):
        # check is the user is logged in
        if self.user:
            # logout the user and take the user to the signup page
            self.logout()
            self.redirect("/signup")
        # otherwise if the user is not logged in take the user to the login
        # page and throw an error
        else:
            error = 'You need to be logged in to be able to log out. Please log in.'
            self.render('login.html', error=error)

#====================================================

app = webapp2.WSGIApplication([
    ('/', MainPage), 
    ('/newpost', NewPost),
    ('/post/([0-9]+)', PostPage), 
    ('/login', Login),
    ('/logout', Logout), 
    ('/signup', Register), 
    ('/welcome', Welcome),
    ('/edit/([0-9]+)', EditPost), 
    ('/blog/([0-9]+)/editcomment/([0-9]+)', EditComment),
    ('/blog/([0-9]+)/deletecomment/([0-9]+)', DeleteComment),
], debug=True)
