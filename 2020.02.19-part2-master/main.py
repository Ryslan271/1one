import os

from flask import Flask, render_template, redirect
from flask_login import LoginManager
from models import db_session
from models.users import User, RegisterForm, LoginForm
from flask_restful import abort


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
db_session.global_init('sqlite.db')
login_manager = LoginManager()
login_manager.init_app(app)

f = False
men_page, reg, adm, rig = None, None, None, None


@app.route("/")
def home():
    global f, adm, men_page
    return render_template('Osnova.html', flag=f, admi=adm, men=men_page)


@app.route("/о_принцах_и_драконах")
def о_принцах_и_драконах():
    global f, adm, men_page
    return render_template('book/о_принцах_и_драконах.html', flag=f, admi=adm, men=men_page)


@app.route("/Чем_пахнет_луна")
def Чем_пахнет_луна():
    global f, adm, men_page
    return render_template('book/Чем_пахнет_луна.html', flag=f, admi=adm, men=men_page)


@app.route("/Чем_пахнет_луна2")
def Чем_пахнет_луна2():
    global f, adm, men_page
    return render_template('book/Чем_пахнет_луна2.html', flag=f, admi=adm, men=men_page)


@app.route("/zirka_li")
def zirka_li():
    global f, adm, men_page
    return render_template('book/zirka_li.html', flag=f, admi=adm, men=men_page)


@app.route("/day_neza")
def day_neza():
    global f, adm, men_page
    return render_template('book/day_neza.html', flag=f, admi=adm, men=men_page)


@app.route("/zerkalo")
def zerkalo():
    global f, adm, men_page
    return render_template('book/zerkalo.html', flag=f, admi=adm, men=men_page)


@app.route("/zerkalo2")
def zerkalo2():
    global f, adm, men_page
    return render_template('book/zerkalo2.html', flag=f, admi=adm, men=men_page)


@app.route("/elena")
def elena():
    global f, adm, men_page
    return render_template('book/elena.html', flag=f, admi=adm, men=men_page)


@app.route("/Как_простить_Драко_Малфоя")
def Как_простить_Драко_Малфоя():
    global f, adm, men_page
    return render_template('book/Как_простить_Драко_Малфоя.html', flag=f, admi=adm, men=men_page)


@app.route("/Как_простить_Драко_Малфоя2")
def Как_простить_Драко_Малфоя2():
    global f, adm, men_page
    return render_template('book/Как_простить_Драко_Малфоя2.html', flag=f, admi=adm, men=men_page)


@app.route("/Lyshee")
def lyshee():
    global f
    if f:
        return render_template('Lyshee.html', men=men_page, flag=f)
    else:
        abort(401)


@app.route("/O nas")
def onas():
    global f
    if f:
        return render_template('O nas.html', men=men_page, flag=f)
    else:
        abort(401)


@app.route("/Contact")
def contact():
    global f
    if f:
        return render_template('Contact.html', men=men_page, flag=f)
    else:
        abort(401)


@app.route("/girl")
def girl():
    global men_page, f
    men_page = False
    return render_template('Osnova.html', men=men_page, flag=f)


@app.route("/men")
def men():
    global men_page, f
    men_page = True
    return render_template('Osnova.html', men=men_page, flag=f)


@app.route("/Admin")
def admin():
    session = db_session.create_session()
    return render_template(
        'bases/admin.html',
        User=session.query(User).order_by(User.date.desc())
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    global f, men_page, reg, adm, rig
    if not f or rig:
        reg = True
        form = LoginForm()
        if form.validate_on_submit():
            if form.login.data == 'adminrys':
                if form.password.data == '123':
                    f, adm = True, True
                    rig = None
                    return render_template('Osnova.html', flag=f, admi=adm, men=men_page)
                else:
                    return render_template("Error/Admin_error.html", flag=f, admi=adm, men=men_page)

            session = db_session.create_session()
            if session.query(User).filter(User.login == form.login.data).first():
                user = session.query(User).filter(User.login == form.login.data).first()
                if user and user.check_password(form.password.data):
                    f = True
                    rig = None
                    return render_template('Osnova.html', flag=f, men=men_page)
                else:
                    return render_template('reg_and_log/login.html', title='Регистрация',
                                           log=True,
                                           form=form,
                                           reg=reg,
                                           message="Не правильный пароль")
            else:
                return render_template('reg_and_log/login.html', title='Регистрация',
                                       log=True,
                                       form=form,
                                       reg=reg,
                                       message="Такого пользователя нету в базе данных, может зарегистрируешься?")

        return render_template('reg_and_log/login.html', title='Авторизация', form=form, reg=reg)
    else:
        abort(401)


@app.route('/register', methods=['GET', 'POST'])
def register():
    global f, reg, rig
    reg = False
    if not rig:
        form = RegisterForm()
        if form.validate_on_submit():
            if form.password.data != form.password_again.data:
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Пароли не совпадают")

            session = db_session.create_session()
            if session.query(User).filter(User.login == form.login.data).first():
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Такой пользователь уже есть")
            if form.login.data == 'adminrys':
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Извините, но этот логин занят админом :)")
            if len(form.password.data) < 5 and len(form.login.data) < 5:
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Логин и пароль должны быть больше 5 символов")

            if len(form.password.data) < 5:
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Пароль слишком короткий, он должны быть больше 5 символов")
            if len(form.login.data) < 5:
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Логин слишком короткий, он должны быть больше 5 символов")

            user = User(
                login=form.login.data,
                hashed_password=form.password.data,
            )
            user.set_password(form.password.data)
            session.add(user)
            session.commit()
            f = True
            rig = True
            return redirect('/login')
        return render_template('reg_and_log/register.html', title='Регистрация', form=form, reg=reg, )
    else:
        abort(404)


@app.route('/delete_log', methods=['GET', 'POST'])
def delete_log():
    global f, men_page
    f = False
    men_page = None
    return render_template('Osnova.html', flag=f, admi=False)


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


@app.errorhandler(400)
def not_found_error(error):
    return render_template('Error/400.html'), 400


@app.errorhandler(401)
def not_found_error(error):
    return render_template('Error/401.html'), 401


@app.errorhandler(404)
def not_found_error(error):
    return render_template('Error/404.html'), 404


@app.errorhandler(500)
def not_found_error(error):
    return render_template('Error/500.html'), 500


@app.errorhandler(502)
def not_found_error(error):
    return render_template('Error/502.html'), 502


@app.errorhandler(503)
def not_found_error(error):
    return render_template('Error/503.html'), 503



if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
