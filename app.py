import logging
import bcrypt
import concurrent.futures
import os.path

import tornado.escape
from tornado import gen
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
from tornado.options import define, options

logger = logging.getLogger("app")

define("port", default=8888, help="run on the given port", type=int)

# A thread pool to be used for password hashing with bcrypt.
executor = concurrent.futures.ThreadPoolExecutor(2)


# TODO: for test
class User(object):
    id = 1234
    name = 'User Name'
    hashed_password = '$2b$12$ghbwXijyYEm1lq2j2IKydeDjyjJdajTRnhizQYMTs2zvSgfJS/NqC'

USER = User()


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            xsrf_cookies=True,
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            debug=True,
        )
        super(Application, self).__init__(handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_id = self.get_secure_cookie("user")
        return user_id


class HomeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        logger.info('current user ID: {}'.format(self.current_user))
        self.render("home.html")


class AuthLoginHandler(BaseHandler):
    def get(self):
        self.render("login.html", error=None)

    @gen.coroutine
    def post(self):
        logger.info('logging in with email:{}, password:{}'.format(self.get_argument('email'), self.get_argument('password')))

        # TODO: get user metadata from database
        user = USER

        hashed_password = yield executor.submit(
            bcrypt.hashpw, 
            tornado.escape.utf8(self.get_argument("password")),
            tornado.escape.utf8(user.hashed_password))

        if hashed_password == user.hashed_password:
            self.set_secure_cookie("user", str(user.id))
            self.redirect(self.get_argument("next", "/"))
        else:
            self.render("login.html", error="incorrect password")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
