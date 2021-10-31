#!/usr/bin/env/python3
''' This program creates a web page using flask. The structure
of the page is one home page and three supporting pages. there
is also a secure login and registration page'''

import datetime
import os
import string
from passlib.hash import sha256_crypt
from flask import Flask
from flask import flash
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from markupsafe import escape


APP = Flask( # create Flask object and set attributes
    __name__,
    template_folder='templates',
    static_folder='static'
)

APP.secret_key = 'fasfFASDFA$@#%#RAF4'

class User:
    '''Class creates user objects to track username and
    login status'''
    def __init__(self, username):
        '''Default contructor'''
        self._username = username
        self._logged = False

    def __repr__(self):
        '''For printing object'''
        return 'Username: ' + self.username

    @property
    def username(self) -> str:
        '''Getter'''
        return self._username

    @property
    def logged(self) -> bool:
        '''Getter'''
        return self._logged

    @username.setter
    def username(self, candidate_username) -> None:
        '''Setter'''
        self._username = candidate_username

    @logged.setter
    def logged(self, status) -> None:
        '''Setter'''
        self._logged = status



CURRENT_APP_USER = User('sdfasdf') # Instantiate user object for later use




@APP.context_processor
def inject_date():
    ''' create datetime object and return it in a dict
    so that it will be accessible in home template '''
    current_date = datetime.datetime.today()
    return dict(date=current_date)

@APP.route("/", methods=['GET', 'POST'])
def home():
    ''' render home page '''
    if CURRENT_APP_USER.logged:
        return render_template("lab_6_home.html")
    return redirect(url_for('login'))

@APP.route("/page1")
def page_1():
    ''' render page 1 '''
    return render_template("lab_6_child1.html")

@APP.route("/page2")
def page_2():
    ''' render page 2 '''
    return render_template("lab_6_child2.html")

@APP.route("/page3")
def page_3():
    ''' render page 3 '''
    return render_template("lab_6_child3.html")

@APP.route("/register", methods=['GET', 'POST'])
def register():
    ''' Render registration page and handle request data with validation
    for username and password '''
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']
        with open('cred.txt', 'r') as file:
            if not file:
                with open('CommonPassword.txt', 'r') as pass_file:
                    for pass_line in pass_file:
                        if password.lower() == pass_line.strip():
                            flash('This password is too common. \
                                  Please choose another')
                            return render_template('register.html')
                if not username:
                    flash('Please enter a username', 'Username Error')
                    return render_template("register.html")
                if not password:
                    flash('Please enter a password', 'Password Error')
                    return render_template("register.html")
                if (not any(character in string.ascii_lowercase
                            for character in password)):
                    flash('Make sure password has at least \
                          one lowercse letter', 'Password Error')
                    return render_template("register.html")
                if (not any(character in string.ascii_uppercase
                            for character in password)):
                    flash('Make sure password has at least \
                          one uppercse letter', 'Password Error')
                    return render_template("register.html")
                if (not any(character in string.digits
                            for character in password)):
                    flash('Make sure password has at least \
                          one digit', 'Password Error')
                    return render_template("register.html")
                if (not any(character in string.punctuation
                            for character in password)):
                    flash('Make sure password has at least \
                          one punctuation character', 'Password Error')
                    return render_template("register.html")
                if (any(character in '<>/\'\"' for character in username)
                        or any(character in '<>/\'\"' for character in password)):
                    flash('Please do not enter characters \
                          like <>/\'\"', 'Character Error')
                    return render_template("register.html")
                if password == username:
                    flash('Make sure password is not the \
                          same as username', 'Password Error')
                    return render_template("register.html")
                if len(password) < 12:
                    flash('Make sure password is at least \
                          12 charcters', 'Password Error')
                    return render_template("register.html")
                if password == 'password':
                    flash('Please choose a diferent password', 'Password Error')
                    return render_template("register.html")
                if password == 'pass123':
                    flash('Please choose a diferent password', 'Password Error')
                    return render_template("register.html")
                if password == 'ABC123':
                    flash('Please choose a diferent password', 'Password Error')
                    return render_template("register.html")
                with open('CommonPassword.txt', 'r') as pass_file:
                    for pass_line in pass_file:
                        if password == pass_line:
                            flash('This password is too common. \
                                  Please choose another')
                            return render_template('register.html')
                hash_pass = sha256_crypt.hash(password)
                with open('cred.txt', 'a') as file:
                    file.write(username + ' ' + hash_pass + ' \n')
            else:
                with open('CommonPassword.txt', 'r') as pass_file:
                    for pass_line in pass_file:
                        if password.lower() == pass_line.strip():
                            flash('This password is too common. \
                                  Please choose another')
                            return render_template('register.html')
                for line in file:
                    if line.split()[0] == username:
                        flash('That username is already in use', 'Username Error')
                        return render_template("register.html")
                if not username:
                    flash('Please enter a username', 'Username Error')
                    return render_template("register.html")
                if not password:
                    flash('Please enter a password', 'Password Error')
                    return render_template("register.html")
                if (not any(character in string.ascii_lowercase
                            for character in password)):
                    flash('Make sure password has at least one \
                          lowercse letter', 'Password Error')
                    return render_template("register.html")
                if (not any(character in string.ascii_uppercase
                            for character in password)):
                    flash('Make sure password has at least one \
                          uppercse letter', 'Password Error')
                    return render_template("register.html")
                if (not any(character in string.digits
                            for character in password)):
                    flash('Make sure password has at least one \
                          digit', 'Password Error')
                    return render_template("register.html")
                if (not any(character in string.punctuation
                            for character in password)):
                    flash('Make sure password has at least one \
                          punctuation character', 'Password Error')
                    return render_template("register.html")
                if (any(character in '<>/\'\"' for character in username)
                        or any(character in '<>/\'\"' for character in password)):
                    flash('Please do not enter characters like \
                          <>/\'\"', 'Character Error')
                    return render_template("register.html")
                if password == username:
                    flash('Make sure password is not the same \
                          as username', 'Password Error')
                    return render_template("register.html")
                if len(password) < 12:
                    flash('Make sure password is at least \
                          12 charcters', 'Password Error')
                    return render_template("register.html")
                if password == 'password':
                    flash('Please choose a diferent password', 'Password Error')
                    return render_template("register.html")
                if password == 'pass123':
                    flash('Please choose a diferent password', 'Password Error')
                    return render_template("register.html")
                if password == 'ABC123':
                    flash('Please choose a diferent password', 'Password Error')
                    return render_template("register.html")
                hash_pass = sha256_crypt.hash(password)
                with open('cred.txt', 'a') as file:
                    file.write(username + ' ' + hash_pass + ' \n')

                    return render_template('login.html')
    return render_template("register.html")

@APP.route("/login", methods=['GET', 'POST'])
def login():
    ''' Renders a login page that handles request data
    and redirects user to the home page if their data
    is consistent with data in the cred file '''
    failure = False
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with open('cred.txt', 'r') as file:
            for line in file:
                split_line = line.split()
                try:
                    if (split_line[0] == username and
                            sha256_crypt.verify(password, split_line[1].strip())):
                        CURRENT_APP_USER.username = username
                        CURRENT_APP_USER.logged = True
                        return redirect(url_for('home'))
                    else:
                        failure = True
                except IndexError:
                    with open('log.txt', 'a') as file:
                        file.write(f'IndexError when trying to \
                        log in--Date={datetime.datetime.today()}--\
                        IP={request.remote_addr}\n')
            if failure:
                with open('log.txt', 'a') as file:
                    file.write(f'Failed login attempt--\
                    Date={datetime.datetime.today()}--\
                    IP={request.remote_addr}\n')
                    failure = False
                    flash('Not a valid login')
                    return render_template('login.html')
    return render_template('login.html')

@APP.route("/logout", methods=['GET', 'POST'])
def logout():
    ''' Log out the user and redirect to login page '''
    if request.method == 'POST':
        CURRENT_APP_USER.logged = False
        return redirect(url_for('login'))



@APP.route("/update", methods=['GET', 'POST'])
def update():
    ''' Ask user to verify current credentials and then enter
    a new password to overwrite their current password.
    Also verrifies and enforces the integrity of the password.'''
    failure = False
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password1 = request.form['password1']
        password2 = request.form['password2']
        with open('cred.txt', 'r') as file:
            for line in file:
                split_line = line.split()
                try:
                    if (split_line[0] == username and
                            sha256_crypt.verify(password, split_line[1].strip())):
                        CURRENT_APP_USER.username = username
                        CURRENT_APP_USER.logged = True
                        with open('CommonPassword.txt', 'r') as pass_file:
                            for pass_line in pass_file:
                                if password1.lower() == pass_line.strip():
                                    flash('This password is too common. \
                                          Please choose another')
                                    return render_template('update.html')
                        if not password1:
                            flash('Please enter a password', 'Password Error')
                            return render_template("update.html")
                        if (not any(character in string.ascii_lowercase
                                    for character in password1)):
                            flash('Make sure password has at least one \
                                  lowercse letter', 'Password Error')
                            return render_template("update.html")
                        if (not any(character in string.ascii_uppercase
                                    for character in password1)):
                            flash('Make sure password has at least one \
                                  uppercse letter', 'Password Error')
                            return render_template("update.html")
                        if (not any(character in string.digits
                                    for character in password1)):
                            flash('Make sure password has at least one \
                                  digit', 'Password Error')
                            return render_template("update.html")
                        if (not any(character in string.punctuation
                                    for character in password1)):
                            flash('Make sure password has at least one \
                                  punctuation character', 'Password Error')
                            return render_template("update.html")
                        if (any(character in '<>/\'\"' for character in username)
                                or any(character in '<>/\'\"' for character in password1)):
                            flash('Please do not enter characters like \
                                  <>/\'\"', 'Character Error')
                            return render_template("update.html")
                        if password1 == username:
                            flash('Make sure password is not the same \
                                  as username', 'Password Error')
                            return render_template("update.html")
                        if len(password1) < 12:
                            flash('Make sure password is at least \
                                  12 charcters', 'Password Error')
                            return render_template("update.html")
                        if password1 == 'password':
                            flash('Please choose a diferent password', 'Password Error')
                            return render_template("update.html")
                        if password1 == 'pass123':
                            flash('Please choose a diferent password', 'Password Error')
                            return render_template("update.html")
                        if password1 == 'ABC123':
                            flash('Please choose a diferent password', 'Password Error')
                            return render_template("update.html")
                        if password1 == password2:
                            with open('new_cred.txt', 'w') \
                            as new_file, open('cred.txt', 'r') as file:
                                file_lines = file.readlines()
                                hash_pass = sha256_crypt.hash(password1)
                                new_line = f'{username} {hash_pass}'
                                for credential_line in file_lines:
                                    if credential_line.split()[0] == new_line.split()[0]:
                                        credential_line = new_line
                                        new_file.write(line)
                                    else:
                                        new_file.write(line)
                                os.remove('cred.txt')
                                os.rename('new_cred.txt', 'cred.txt')
                                flash('done')
                                return redirect(url_for('home'))
                except IndexError:
                    with open('log.txt', 'a') as file:
                        file.write(f'IndexError when trying to log in--\
                        Date={datetime.datetime.today()}--\
                        IP={request.remote_addr}\n')
                        return render_template('update.html')
            if failure:
                with open('log.txt', 'a') as file:
                    file.write(f'Failed login attempt--\
                    Date={datetime.datetime.today()}--\
                    IP={request.remote_addr}\n')
                    failure = False
                    flash('Not valid')
                    return render_template('update.html')
    return render_template('update.html')




def main():
    ''' Call the home function to launch the website'''
    home()


if __name__ == '__main__':
    main()
