#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, make_response
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_, text, UniqueConstraint
from sqlalchemy.sql.expression import not_
from sqlalchemy.sql import column, select, func, literal_column, alias
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from whoosh.analysis import StemmingAnalyzer
from whoosh.analysis import SimpleAnalyzer
from resizeimage import resizeimage
from flask_mail import Mail, Message
from PIL import Image
import flask_whooshalchemy as wa
import _mysql_exceptions
import datetime
import base64
import uuid
import time
import jwt
import os


app = Flask(__name__)
photos = UploadSet('photos', IMAGES)

app.config['SECRET_KEY'] = os.environ['SECRET']
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['DEBUG'] = True
app.config['WHOOSH_BASE'] = 'whoosh'
app.config['WHOOSH_ANALYZER'] = StemmingAnalyzer()
app.config['UPLOADED_PHOTOS_DEST'] = 'static/img'
app.config['MAIL_SERVER'] = os.environ['MAIL_SERVER']
app.config['MAIL_USERNAME'] = os.environ['MAIL_USERNAME']
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_PORT'] = 465

db = SQLAlchemy(app)
configure_uploads(app, photos)
mail = Mail(app)

serializer = URLSafeTimedSerializer(os.environ['SECRET'])


class User(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    confirmed = db.Column(db.Boolean, default=False)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), unique=True)
    address_id = db.Column(db.String(50))
    firstname = db.Column(db.String(50))
    middlename = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    password = db.Column(db.String(80))
    website = db.Column(db.String(80))
    avatar = db.Column(db.String(50))
    phone = db.Column(db.String(50))
    name = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class UserImage(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    image = db.Column(db.String(50))


class Address(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    firstname = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    street = db.Column(db.String(150))
    zipcode = db.Column(db.String(5))
    country = db.Column(db.String(50))
    suite = db.Column(db.String(50))
    state = db.Column(db.String(50))
    city = db.Column(db.String(50))
    user_id = db.Column(db.String(50))


class Location(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    zip = db.Column(db.String(5), unique=True, nullable=False)
    user_id = db.Column(db.String(50), nullable=False)
    lat = db.Column(db.Numeric(15,13), nullable=False)
    lng = db.Column(db.Numeric(15,13), nullable=False)
    city = db.Column(db.Text, nullable=False)


class Payment(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.String(50))
    product_id = db.Column(db.String(50))


class Order(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    visible = db.Column(db.Boolean, default=True)
    product_id = db.Column(db.String(50))
    address_id = db.Column(db.String(50))
    user_id = db.Column(db.String(50))
    status = db.Column(db.String(50))


class Currency(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(50))
    iso_code = db.Column(db.String(50))
    unit_symbol = db.Column(db.String(50))


class Inbox(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    subject = db.Column(db.String(50))
    message = db.Column(db.String(5000))
    creator_id = db.Column(db.String(50))
    parent_id = db.Column(db.String(50))
    user_id = db.Column(db.String(50))
    read = db.Column(db.Boolean, default=False)


class Product(db.Model):
    __tablename__ = 'product'
    __searchable__ = ['name', 'description']
    __analyzer__ = SimpleAnalyzer()

    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    shipping_fee = db.Column(db.Numeric, default=0)
    price = db.Column(db.Numeric, default=0)
    condition_id = db.Column(db.String(50))
    description = db.Column(db.Text)
    category_id = db.Column(db.String(50))
    currency_id = db.Column(db.String(30))
    address_id = db.Column(db.String(50))
    thumbnail = db.Column(db.String(500))
    user_id = db.Column(db.String(50))
    status = db.Column(db.String(50))
    name = db.Column(db.String(70))


class Wishlist(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    product_id = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.String(50), nullable=False)
    __table_args__ = (UniqueConstraint('product_id', 'user_id'),)


class Layout(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    background = db.Column(db.String(10))
    alert = db.Column(db.String(10))
    headline = db.Column(db.String(10))
    warning = db.Column(db.String(10))
    success = db.Column(db.String(10))
    teaser = db.Column(db.String(10))
    button = db.Column(db.String(10))
    navbar = db.Column(db.String(10))
    error = db.Column(db.String(10))
    info = db.Column(db.String(10))
    link = db.Column(db.String(10))
    text = db.Column(db.String(10))
    user_id = db.Column(db.String(50))


class ProductImage(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    image = db.Column(db.String(500))
    user_id = db.Column(db.String(50))
    product_id = db.Column(db.String(50))


# TODO: implement session id
class ProductTempImage(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    image = db.Column(db.String(500))


class ProductCategory(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    name = db.Column(db.String(50))
    description = db.Column(db.String(500))
    parent_id = db.Column(db.String(50))
    user_id = db.Column(db.String(50))


class ProductCondition(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    name = db.Column(db.String(50))
    description = db.Column(db.String(500))
    user_id = db.Column(db.String(50))


class Token(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    token = db.Column(db.String(500), unique=True)
    blacklisted = db.Column(db.Boolean)
    user_id = db.Column(db.String(50))


wa.whoosh_index(app, Product)


def token_blacklisted(token):
    token_result = Token.query.filter_by(token=token).first()

    if token_result and token_result.blacklisted:
        return True
    else:
        return False


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]

        if not token:
            return jsonify({'status': 'not authorized', 'message': 'Token is missing!'}), 401

        if token_blacklisted(token):
            return jsonify({'status': 'not authorized', 'message': 'Token is blacklisted!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except Exception as e:
            print e
            return jsonify({'status': 'not authorized', 'message': 'Token is invalid, please login again!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


def create_id():
    return str(uuid.uuid4()).split('-')[4]


def query_user_by_id(user_id):
    return User.query.filter_by(id=user_id, confirmed=True).first()


@app.route('/api/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    try:
        limit = int(request.args.get('limit'))
        page = int(request.args.get('page'))
    except ValueError as e:
        print e
        return jsonify({'status': 'not found', 'message': 'No user found!'}), 404

    users = User.query.paginate(page, limit, False)
    total = users.total
    output = []

    for user in users.items:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['confirmed'] = user.confirmed
        user_data['username'] = user.username
        user_data['website'] = user.website
        user_data['email'] = user.email
        user_data['phone'] = user.phone
        user_data['admin'] = user.admin
        user_data['name'] = user.name
        output.append(user_data)

    return jsonify({'status': 'success', 'total': total, 'users': output})


@app.route('/api/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'status': 'not found', 'message': 'No user found!'}), 404

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['firstname'] = user.firstname
    user_data['lastname'] = user.lastname
    user_data['website'] = user.website
    user_data['avatar'] = user.avatar
    user_data['email'] = user.email
    user_data['phone'] = user.phone
    user_data['admin'] = user.admin
    user_data['name'] = user.name

    return jsonify({'status': 'success', 'user': user_data})


@app.route('/api/user', methods=['POST'])
def create_user():
    data = request.get_json()

    if not data or not 'email' in data or not 'password' in data:
        return jsonify({'status': 'bad request', 'message': 'Please provide your email and password!'}), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')

    try:
        user_id = create_id()
        address_id = create_id()
        token_id = create_id()

        new_address = Address(id=address_id, user_id=user_id)

        new_user = User(id=user_id, public_id=user_id, password=hashed_password,
            email=data['email'], address_id=address_id, name=data['name'], admin=False)

        exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)

        token = jwt.encode(
            {'public_id': user_id, 'exp': exp}, app.config['SECRET_KEY'])

        new_token = Token(id=token_id, token=token, blacklisted=False, user_id=user_id)

        db.session.add(new_address)
        db.session.flush()

        db.session.add(new_user)
        db.session.flush()

        db.session.add(new_token)
        db.session.commit()

        return jsonify({'status': 'success', 'admin': False, 'token': token.decode('utf-8')})

    except NameError as e:
        print e
        return jsonify({'status': 'bad request', 'message': 'bad tbd.'}), 400
    except IntegrityError as e:
        db.session.rollback()
        return jsonify({'status': 'conflict', 'message': 'User already exists!'}), 409
    else:
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'New user created!'})


@app.route('/api/user/<public_id>', methods=['PUT'])
@token_required
def update_user(current_user, public_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()

    return update_user_query(user, data)


def update_user_query(user, data):
    try:
        user.firstname = data['firstname']
        user.lastname = data['lastname']
        user.username = data['username']
        user.website = data['website']
        user.phone = data['phone']
        user.email = data['email']
        db.session.flush()
    except KeyError as e:
        err_column = str(e).replace('\'', '')
        err = 'There was an error, please provide your {}!'.format(err_column)
        return jsonify({'status': 'error', 'message': err}), 500
    except IntegrityError as e:
        err_column = str(e).split(':')[1].split(' ')[1].split('.')[1]

        if err_column == 'email':
            err_column = 'email address'

        err = 'This {} already exists!'.format(err_column)
        db.session.rollback()
        return jsonify({'status': 'conflict', 'message': err}), 409
    else:
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Upated user {}'.format(user.public_id)})


@app.route('/api/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    if not current_user.admin:
        return jsonify({'status': 'not authorized', 'message': 'Cannot perform that function!'}), 401

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'status': 'not found', 'message': 'No user found!'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'The user has been deleted!'})


@app.route('/api/user/image/<user_id>', methods=['PUT'])
@token_required
def update_user_image(current_user, user_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.form
    print data

    for image in request.files.getlist('image'):
        user_image_id = create_id()
        filetype = image.mimetype.split('/')[1]
        name = '{}.{}'.format(user_image_id, filetype)
        path = 'static/img/{}'.format(name)
        image.save(path)
        print path

    user.avatar = path
    db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):
    request_token = request.headers.get('authorization').split(' ')[1]
    token = Token.query.filter_by(token=request_token).first()

    if token:
        token.blacklisted = True
        db.session.commit()

    return jsonify({'status': 'success', 'message': 'Successfully logged out!'})


@app.route('/api/status', methods=['GET'])
def login_status():
    request_token = request.headers.get('authorization').split(' ')[1]
    user = db.session.query(Token, User).filter(
        Token.token == request_token).filter(User.id == Token.user_id).first()

    try:
        jwt.decode(request_token, app.config['SECRET_KEY'])
        return jsonify({'status': 'success', 'message': 'You are logged in!', 'address_id': user.User.address_id, 'avatar': user.User.avatar, 'firstname': user.User.firstname, 'lastname': user.User.lastname, 'confirmed': user.User.confirmed, 'user_id': user.User.id, 'name': user.User.name})
    except AttributeError as e:
        return jsonify({'status': 'internal error', 'message': 'Oooopss, there was an error on our server!'}), 500
    except Exception as e:
        return jsonify({'status': 'not authorized', 'message': 'Please login!'}), 401


@app.route('/api/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'status': 'not authorized', 'message': 'Please provide your login credentials!'}), 401

    try:
        user = User.query.filter_by(email=auth.username).first()

    except Exception as e:
        print e
        return jsonify({'status': 'internal error', 'message': 'Oooopss, there was an error on our server!'}), 500

    if not user:
        return jsonify({'status': 'not authorized', 'message': 'Could not verify your credentials!'}), 401

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['confirmed'] = user.confirmed
    user_data['address_id'] = user.address_id
    user_data['username'] = user.username
    user_data['firstname'] = user.firstname
    user_data['lastname'] = user.lastname
    user_data['avatar'] = user.avatar
    user_data['email'] = user.email
    user_data['admin'] = user.admin
    user_data['name'] = user.name

    if check_password_hash(user.password, auth.password):
        exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)

        token = jwt.encode({'public_id': user.public_id,
                            'exp': exp}, app.config['SECRET_KEY'])

        token_id = create_id()
        new_token = Token(id=token_id, token=token,
                          blacklisted=False, user_id=user.id)
        db.session.add(new_token)
        db.session.commit()

        print user
        return jsonify({'status': 'success', 'token': token.decode('utf-8'), 'user': user_data})

    return jsonify({'status': 'not authorized', 'message': 'Could not verify your credentials!'}), 401


@app.route('/api/currencies', methods=['GET'])
def get_all_currencies():
    currencies = Currency.query.all()
    output = []

    for currency in currencies:
        currency_data = {}
        currency_data['id'] = currency.id
        currency_data['name'] = currency.name
        currency_data['iso_code'] = currency.iso_code
        currency_data['unit_symbol'] = currency.unit_symbol
        output.append(currency_data)

    return jsonify({'status': 'success', 'currencies': output})


@app.route('/api/currency/<currency_id>', methods=['GET'])
def get_currency_by_id(currency_id):
    currency = Currency.query.filter_by(id=currency_id).first()

    currency_data = {}
    currency_data['id'] = currency.id
    currency_data['name'] = currency.name
    currency_data['iso_code'] = currency.iso_code
    currency_data['unit_symbol'] = currency.unit_symbol

    return jsonify({'status': 'success', 'currency': currency_data})


@app.route('/api/category/<category_id>', methods=['GET'])
def get_category_by_id(category_id):
    category = ProductCategory.query.filter_by(id=category_id).first()

    category_data = {}
    category_data['id'] = category.id
    category_data['name'] = category.name
    category_data['description'] = category.description
    category_data['parent_id'] = category.parent_id
    category_data['user_id'] = category.user_id

    return jsonify({'status': 'success', 'category': category_data})


@app.route('/api/categories/<parent_id>', methods=['GET'])
def get_all_categories_from_parent_id(parent_id):
    categories = ProductCategory.query.filter_by(parent_id=parent_id).order_by(
        ProductCategory.name).all()

    output = []
    for category in categories:
        category_data = {}
        category_data['id'] = category.id
        category_data['name'] = category.name
        category_data['description'] = category.description
        category_data['parent_id'] = category.parent_id
        category_data['user_id'] = category.user_id
        output.append(category_data)

    return jsonify({'status': 'success', 'categories': output})


@app.route('/api/product-categories', methods=['GET'])
def get_all_product_categories():
    product_categories = ProductCategory.query.filter_by(parent_id='').order_by(
        ProductCategory.name).all()

    output = []
    for product_category in product_categories:
        product_category_data = {}
        product_category_data['id'] = product_category.id
        product_category_data['name'] = product_category.name
        product_category_data['description'] = product_category.description
        product_category_data['parent_id'] = product_category.parent_id
        product_category_data['user_id'] = product_category.user_id
        output.append(product_category_data)

    return jsonify({'status': 'success', 'product-categories': output})


@app.route('/api/product-categories/user', methods=['GET'])
@token_required
def get_all_product_categories_by_user(current_user):
    product_categories = ProductCategory.query.filter_by(
        user_id=current_user.id).order_by(ProductCategory.name).all()
    output = []

    for product_category in product_categories:
        product_category_data = {}
        product_category_data['id'] = product_category.id
        product_category_data['name'] = product_category.name
        product_category_data['parent_id'] = product_category.parent_id
        product_category_data['description'] = product_category.description
        product_category_data['user_id'] = product_category.user_id
        output.append(product_category_data)

    return jsonify({'status': 'success', 'product-categories': output})


@app.route('/api/product-category/<product_category_id>', methods=['DELETE'])
@token_required
def delete_product_category(current_user, product_category_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    product_category = ProductCategory.query.filter_by(
        id=product_category_id).first()

    if not product_category:
        return jsonify({'status': 'not found', 'message': 'No product category found!'}), 404

    db.session.delete(product_category)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item deleted!'})


@app.route('/api/product-category/<product_category_id>', methods=['PUT'])
@token_required
def update_product_category(current_user, product_category_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()

    product_category = ProductCategory.query.filter_by(id=product_category_id).first()

    if not product_category:
        return jsonify({'status': 'not found', 'message': 'No product found'}), 404

    product_category.name = data['name']
    product_category.parent_id = data['parent_id']
    product_category.description = data['description']
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item has been updated'})


@app.route('/api/product-category', methods=['POST'])
@token_required
def create_product_category(current_user):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()
    product_category_id = create_id()
    new_product_category = ProductCategory(id=product_category_id, name=data['name'],
        parent_id=data['parent'], description=data['description'], user_id=current_user.id)

    db.session.add(new_product_category)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'New product added!'})


@app.route('/api/products', methods=['GET'])
def get_all_products():
    products = db.session.query(Product,  User, Address,
        Currency, ProductImage, ProductCategory, ProductCondition,
        func.group_concat(ProductImage.image).label('product_images')).join(
        ProductCondition, Product.condition_id == ProductCondition.id).join(
        ProductCategory, Product.category_id == ProductCategory.id).join(
        ProductImage, Product.id == ProductImage.product_id).join(
        Currency, Product.currency_id == Currency.id).join(
        Address, Product.address_id == Address.id).join(
        User, Product.user_id == User.id).filter(
        Product.status != 'sold').group_by(Product.id).order_by(
        Product.created_date.desc()).all()

    output = []
    for product in products:
        product_data = {}
        product_data['id'] = product.Product.id
        product_data['name'] = product.Product.name
        product_data['price'] = str(product.Product.price)
        product_data['currency'] = product.Currency.unit_symbol
        product_data['condition'] = product.ProductCondition.name
        product_data['thumbnail'] = product.ProductImage.image
        product_data['description'] = product.Product.description
        product_data['shipping_fee'] = str(product.Product.shipping_fee)
        product_data['category'] = product.ProductCategory.name
        product_data['category_id'] = product.ProductCategory.id
        product_data['currency_id'] = product.Currency.id
        product_data['user_name'] = product.User.name
        product_data['image'] = product.product_images
        product_data['city'] = product.Address.city
        product_data['zip'] = product.Address.zipcode
        product_data['user_id'] = product.User.id
        output.append(product_data)

    return jsonify({'status': 'success', 'products': output})


@app.route('/api/product/category/<category_id>', methods=['GET'])
def get_all_products_by_category(category_id):
    products = db.session.query(Product, ProductImage, ProductCategory, User, Currency).join(
        ProductImage, Product.id == ProductImage.product_id).join(
        ProductCategory, Product.category_id == ProductCategory.id).join(
        Currency, Product.currency_id == Currency.id).join(
        User, Product.user_id == User.id).filter(
        Product.category_id == category_id).filter(Product.status != 'sold').group_by(Product.id).all()

    output = []
    for product in products:
        product_data = {}
        product_data['id'] = product.Product.id
        product_data['name'] = product.Product.name
        product_data['price'] = str(product.Product.price)
        product_data['currency'] = product.Currency.unit_symbol
        product_data['thumbnail'] = product.ProductImage.image
        product_data['description'] = product.Product.description
        product_data['category'] = product.ProductCategory.name
        product_data['category_id'] = product.ProductCategory.id
        product_data['user_name'] = product.User.name
        product_data['user_id'] = product.User.id
        output.append(product_data)

    return jsonify({'status': 'success', 'products': output})


@app.route('/api/product/user/<user_id>', methods=['GET'])
def get_all_products_by_user(user_id):
    products = db.session.query(Product, User, Currency, Address, ProductImage, ProductCategory).outerjoin(
        ProductImage, Product.id == ProductImage.product_id).join(
        Address, Product.address_id == Address.id).join(
        ProductCategory, Product.category_id == ProductCategory.id).join(
        Currency, Product.currency_id == Currency.id).join(
        User, Product.user_id == User.id).filter(
        User.id == user_id).group_by(Product.id).filter(Product.status != 'sold').all()

    output = []
    for product in products:
        product_data = {}
        product_data['id'] = product.Product.id
        product_data['name'] = product.Product.name
        product_data['price'] = str(product.Product.price)
        product_data['shipping_fee'] = str(product.Product.shipping_fee)
        product_data['currency'] = product.Currency.unit_symbol

        if hasattr(product.ProductImage, 'image'):
            product_data['thumbnail'] = product.ProductImage.image

        product_data['description'] = product.Product.description
        product_data['category'] = product.ProductCategory.name
        product_data['condition_id'] = product.Product.condition_id
        product_data['category_id'] = product.ProductCategory.id
        product_data['currency_id'] = product.Currency.id
        product_data['user_name'] = product.User.name
        product_data['user_id'] = product.User.id
        product_data['city'] = product.Address.city
        product_data['zip'] = product.Address.zipcode
        output.append(product_data)

    return jsonify({'status': 'success', 'products': output})


def get_user_name(user_id):
    return User.query.filter_by(id=user_id).first().name


def get_product_category_name(category_id):
    return ProductCategory.query.filter_by(id=category_id).first().name


def get_product_image(product_id):
    return ProductImage.query.filter_by(product_id=product_id).first().image


def get_currency_unit(currency_id):
    return Currency.query.filter_by(id=currency_id).first().unit_symbol


@app.route('/api/search/<search_query>', methods=['GET'])
def get_all_products_by_query(search_query):
    products = Product.query.whoosh_search(search_query).join(
        User, Product.user_id == User.id).all()

    output = []
    for product in products:
        product_data = {}
        product_data['id'] = product.id
        product_data['name'] = product.name
        product_data['price'] = str(product.price)
        product_data['currency'] = get_currency_unit(product.currency_id)
        product_data['thumbnail'] = get_product_image(product.id)
        product_data['description'] = product.description
        product_data['category'] = get_product_category_name(product.category_id)
        product_data['category_id'] = product.category_id
        product_data['user_name'] = product.User.name
        product_data['user_id'] = product.User.id
        output.append(product_data)

    return jsonify({'status': 'success', 'products': output})


@app.route('/api/product/<product_id>', methods=['GET'])
def get_one_product(product_id):
    product = db.session.query(Product, Currency, User, Address,
        Location, ProductCategory, ProductImage, ProductCondition,
        func.group_concat(ProductImage.image).label('product_images')).join(
        ProductCondition, ProductCondition.id == Product.condition_id).join(
        ProductCategory, Product.category_id == ProductCategory.id).join(
        ProductImage, ProductImage.product_id == Product.id).join(
        Currency, Product.currency_id == Currency.id).join(
        Address, Address.id == Product.address_id).outerjoin(
        Location, Location.zip == Address.zipcode).join(
        User, Product.user_id == User.id).filter(
        Product.id == product_id).first()

    if not product:
        return jsonify({'status': 'not found', 'message': 'No product found'}), 404

    product_data = {}
    product_data['id'] = product.Product.id
    product_data['name'] = product.Product.name
    product_data['price'] = str(product.Product.price)
    product_data['currency'] = product.Currency.unit_symbol
    product_data['thumbnail'] = product.Product.thumbnail
    product_data['condition'] = product.ProductCondition.name
    product_data['shipping_fee'] = str(product.Product.shipping_fee)
    product_data['total_amount'] = str(product.Product.price + product.Product.shipping_fee)
    product_data['description'] = product.Product.description
    product_data['category'] = product.ProductCategory.name
    product_data['category_id'] = product.ProductCategory.id

    if hasattr(product.Location, 'lat'):
        product_data['lat'] = str(product.Location.lat)

    if hasattr(product.Location, 'lng'):
        product_data['lng'] = str(product.Location.lng)

    if hasattr(product.Location, 'zip'):
        product_data['zip'] = str(product.Location.zip)

    if hasattr(product.Location, 'city'):
        product_data['city'] = str(product.Location.city)

    product_data['user_name'] = product.User.name
    product_data['user_id'] = product.User.id
    product_data['image'] = product.product_images

    return jsonify(product_data)


@app.route('/api/product/<product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()
    product = Product.query.filter_by(id=product_id, user_id=current_user.id).first()

    if not product:
        return jsonify({'status': 'not found', 'message': 'No product found'}), 404

    product.name = data['name']
    product.price = data['price']
    product.shipping_fee = data['shipping_fee']
    product.condition_id = data['condition_id']
    product.currency_id = data['currency_id']
    product.category_id = data['category_id']
    product.description = data['description']

    db.session.flush()
    db.session.commit()

    address = Address.query.filter_by(id=product.address_id, user_id=str(current_user.id)).first()

    address.zipcode = data['zip']
    address.city = data['city']

    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item has been updated'})


@app.route('/api/product/<product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    product = Product.query.filter_by(id=product_id).first()

    if not product:
        return jsonify({'status': 'not found', 'message': 'No product found!'}), 404

    db.session.delete(product)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item deleted!'})


@app.route('/api/tmp/image/<image_id>', methods=['GET'])
def get_tmp_image_by_id(image_id):
    image = ProductTempImage.query.filter_by(id=image_id).first()

    if not image:
        return 404

    image_data = {}
    image_data['id'] = image.id
    image_data['image'] = image.image

    return jsonify({'status': 'success', 'image': image_data})


@app.route('/api/tmp/image', methods=['POST'])
def upload_temp_image():
    upload_tmp_id = []

    for image in request.files.getlist('image'):
        tmp_image_id = create_id()
        filetype = image.mimetype.split('/')[1]
        name = '{}.{}'.format(tmp_image_id, filetype)
        path = 'static/img/{}'.format(name)
        image.save(path)

        try:
            with Image.open(path) as image:
                cover = resizeimage.resize_cover(
                    image, [800, 500], validate=False)
                cover.save(path, image.format)

                db.session.add(ProductTempImage(id=tmp_image_id, image=path))
                db.session.flush()
                db.session.commit()
                upload_tmp_id.append(tmp_image_id)
        except Exception as e:
            print e
            return jsonify({'status': 'fail'})

    return jsonify({'status': 'Saved new tmp image with id {}'.format(', '.join(upload_tmp_id)), 'image': upload_tmp_id})


@app.route('/api/product', methods=['POST'])
@token_required
def create_product(current_user):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()
    product_id = create_id()

    for tmp_image_id in data['image'].split(','):
        tmp_image = ProductTempImage.query.filter_by(id=tmp_image_id).first()

        image_id = create_id()

        db.session.add(ProductImage(id=image_id, image=tmp_image.image, user_id=str(current_user.id), product_id=product_id))
        db.session.flush()
        db.session.commit()

    try:
        address_id = create_id()
        new_address = Address(id=address_id, city=data['city'], zipcode=data['zip'], user_id=current_user.id)

        db.session.add(new_address)
        db.session.flush()
        db.session.commit()
    except Exception as e:
        print e
        return jsonify({'status': 'fail', 'message': 'Could not save address!'}), 500

    try:
        db.session.add(
            Product(id=product_id, name=data['name'], price=data['price'], description=data['description'],
                address_id=address_id, category_id=data['category_id'], currency_id=data['currency_id'], status='new',
                condition_id=data['condition_id'], shipping_fee=data['shipping_fee'], user_id=str(current_user.id))
        )
        db.session.flush()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'New product with id {} added!'.format(product_id)})
    except (Exception, _mysql_exceptions.DataError) as e:
        print e
        return jsonify({'status': 'fail', 'message': 'Please check that all content is well validated'}), 500


@app.route('/api/image', methods=['PUT'])
@token_required
def update_product_image(current_user):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.form
    print data

    product_id = data['product_id']

    for image in request.files.getlist('image'):
        product_image_id = create_id()
        filetype = image.mimetype.split('/')[1]
        name = '{}.{}'.format(product_image_id, filetype)
        path = 'static/img/{}'.format(name)
        image.save(path)

        try:
            with Image.open(path) as image:
                cover = resizeimage.resize_cover(
                    image, [800, 500], validate=False)
                cover.save(path, image.format)
                db.session.add(
                    ProductImage(
                        id=product_image_id, product_id=product_id, image=path)
                )
                db.session.flush()
                db.session.commit()

                return jsonify({'status': 'ok', 'message': 'image was uploaded', 'id': product_image_id})
        except Exception as e:
            print e


@app.route('/api/inbox', methods=['POST'])
@token_required
def create_message(current_user):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()
    message_id = create_id()
    new_message = Inbox(id=message_id, subject=data['subject'], user_id=data['user_id'],
        parent_id=data['parent_id'], message=data['message'], creator_id=current_user.id)

    db.session.add(new_message)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'New message send!'})


@app.route('/api/inbox/user/<user_id>/<message_id>', methods=['PUT'])
@token_required
def update_one_message(current_user, user_id, message_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    if current_user.id != user_id:
        return jsonify({'status': 'fail', 'message': 'Error, you are not allowed to do this action.'})

    data = request.get_json()
    message = Inbox.query.filter_by(id=message_id, user_id=current_user.id).first()

    if not message:
        return jsonify({'status': 'not found', 'message': 'No message with id {} found!'.format(message_id)}), 404

    message.read = data
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item has been updated'})


@app.route('/api/inbox/user/<user_id>/<message_id>', methods=['GET'])
@token_required
def get_one_message(current_user, user_id, message_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    message = db.session.query(Inbox, User).filter(Inbox.id == message_id).filter(
        Inbox.creator_id == User.id).filter(Inbox.user_id == user_id).first()

    if not message:
        return jsonify({'status': 'not found', 'message': 'No message found'}), 404

    inbox_data = {}
    inbox_data['id'] = message.Inbox.id
    inbox_data['read'] = message.Inbox.read
    inbox_data['created'] = message.Inbox.created_date
    inbox_data['subject'] = message.Inbox.subject
    inbox_data['message'] = message.Inbox.message
    inbox_data['parent_id'] = message.Inbox.parent_id
    inbox_data['user_name'] = message.User.name
    inbox_data['avatar'] = message.User.avatar
    inbox_data['user_id'] = message.User.id

    return jsonify(inbox_data)


@app.route('/api/inbox/user/<user_id>/<message_id>', methods=['DELETE'])
@token_required
def delete_one_message(current_user, user_id, message_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    if current_user.id != user_id:
        return jsonify({'status': 'fail', 'message': 'Error, you are not allowed to query this content.'})

    message = Inbox.query.filter_by(id=message_id).first()

    if not message:
        return jsonify({'status': 'not found', 'message': 'No message found'}), 404

    db.session.delete(message)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'The message has been deleted!'})


@app.route('/api/inbox/user/<user_id>', methods=['GET'])
@token_required
def get_all_messages_by_user(current_user, user_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    if current_user.id == user_id:
        messages = db.session.query(Inbox, User).filter(
            Inbox.creator_id == User.id).filter(Inbox.user_id == user_id).all()

        output = []
        for message in messages:
            inbox_data = {}
            inbox_data['id'] = message.Inbox.id
            inbox_data['read'] = message.Inbox.read
            inbox_data['created'] = message.Inbox.created_date
            inbox_data['subject'] = message.Inbox.subject
            inbox_data['message'] = message.Inbox.message
            inbox_data['parent_id'] = message.Inbox.parent_id
            inbox_data['user_name'] = message.User.name
            inbox_data['user_id'] = message.User.id
            output.append(inbox_data)

        return jsonify({'status': 'success', 'messages': output})

    return jsonify({'status': 'fail', 'message': 'Error, you are not allowed to query this content.'})


@app.route('/api/image/<image_id>', methods=['DELETE'])
@token_required
def delete_one_image(current_user, image_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    image = ProductImage.query.filter_by(id=image_id).first()

    if not image:
        return jsonify({'status': 'not found', 'message': 'No image found'}), 404

    db.session.delete(image)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'The image with the id {} has been deleted!'.format(image_id)})


@app.route('/api/image/product/<product_id>', methods=['GET'])
def get_one_image(product_id):
    images = db.session.query(ProductImage).filter_by(
        product_id=product_id).all()

    output = []
    for image in images:
        image_data = {}
        image_data['id'] = image.id
        image_data['user_id'] = image.user_id
        image_data['image'] = image.image
        output.append(image_data)

    return jsonify({'status': 'success', 'images': output})


@app.route('/api/layout/user/<user_id>', methods=['GET'])
def get_layout(user_id):
    layout = Layout.query.filter_by(user_id=user_id).first()

    if not layout:
        return jsonify({'status': 'not found', 'message': 'Layout was not found'}), 404

    layout_data = {}
    layout_data['id'] = layout.id
    layout_data['user_id'] = layout.user_id
    layout_data['background'] = layout.background
    layout_data['headline'] = layout.headline
    layout_data['success'] = layout.success
    layout_data['warning'] = layout.warning
    layout_data['navbar'] = layout.navbar
    layout_data['teaser'] = layout.teaser
    layout_data['button'] = layout.button
    layout_data['error'] = layout.error
    layout_data['alert'] = layout.alert
    layout_data['info'] = layout.info
    layout_data['link'] = layout.link
    layout_data['text'] = layout.text

    return jsonify({'status': 'success', 'layout': layout_data})


@app.route('/api/layout', methods=['POST'])
@token_required
def create_layout(current_user):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()
    layout_id = create_id()
    new_layout = Layout(id=layout_id, background=data['background'], user_id=str(current_user.id),
                        headline=data['headline'], warning=data['warning'],
                        error=data['error'], success=data['success'], info=data['info'],
                        teaser=data['teaser'], navbar=data['navbar'], button=data['button'],
                        link=data['link'], alert=data['alert'], text=data['text'])


    db.session.add(new_layout)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'New layout with d {} was created!'.format(layout_id), 'id': layout_id})


@app.route('/api/layout/<layout_id>', methods=['PUT'])
@token_required
def update_layout(current_user, layout_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()

    layout = Layout.query.filter_by(id=layout_id).first()

    if not layout:
        return jsonify({'status': 'not found', 'message': 'No layout found'}), 404

    layout.background = data['background']
    layout.headline = data['headline']
    layout.success = data['success']
    layout.warning = data['warning']
    layout.navbar = data['navbar']
    layout.teaser = data['teaser']
    layout.button = data['button']
    layout.error = data['error']
    layout.alert = data['alert']
    layout.info = data['info']
    layout.link = data['link']
    layout.text = data['text']

    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Layout has been updated'})


@app.route('/api/confirm/user/<user_id>', methods=['GET'])
@token_required
def resend_confirmaton_token(current_user, user_id):
    if current_user.id != user_id:
        return jsonify({'status': 'fail', 'message': 'Error, you are not allowed to do this action.'}), 401

    user = User.query.filter_by(id=user_id, confirmed=False).first()

    if user:
        try:
            token = serializer.dumps(user.email)
            link = 'https://juuwl.de/confirm/{}'.format(token)
            msg = Message('Confirm your juuwl.de account', sender='mail@juuwl.com', recipients=[user.email])
            msg.body = 'Confirm your email address to complete your juuwl.de account.\nIt\'s easy — just click the link below.\n\n{}'.format(link)

            try:
                mail.send(msg)
            except SMTPAuthenticationError as e:
                print e
            except SMTPServerDisconnected as e:
                print e
            except SMTPException as e:
                print e

            return jsonify({'status': 'success', 'message': 'Confirmation mail has been send to {}'.format(user.email)})

        except Exception as e:
            return e

    return jsonify({'status': 'fail', 'message': 'User is already confirmed'})


@app.route('/api/confirm', methods=['POST'])
def create_confirmaton_token():
    data = request.get_json()

    email = data['email']
    user = User.query.filter_by(email=email, confirmed=True).first()

    if not user:
        try:
            token = serializer.dumps(email)
            link = 'https://juuwl.de/confirm/{}'.format(token)
            msg = Message('Confirm your juuwl.de account', sender='mail@juuwl.com', recipients=[email])
            msg.body = 'Confirm your email address to complete your juuwl.de account.\nIt\'s easy — just click the link below.\n\n{}'.format(link)

            try:
                mail.send(msg)
            except SMTPAuthenticationError as e:
                print e
            except SMTPServerDisconnected as e:
                print e
            except SMTPException as e:
                print e

            return jsonify({'status': 'success', 'message': 'Confirmation mail has been send to {}'.format(email)})
        except Exception as e:
            return e

    return jsonify({'status': 'fail', 'message': 'User is already confirmed'})


@app.route('/api/confirm/<token>', methods=['POST'])
def update_confirmaton(token):
    user = User.query.filter_by(email=serializer.loads(token), confirmed=True).first()

    if not user:
        try:
            email = serializer.loads(token, max_age=300)
            user = User.query.filter_by(email=email).first()

            if not user:
                return jsonify({'status': 'fail', 'message': 'User not found'}), 404

            user.confirmed = True
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'User successfully confirmed'})

        except SignatureExpired as e:
            return jsonify({'status': 'fail', 'message': 'Signature has expired'}), 419

        except BadTimeSignature as e:
            return jsonify({'status': 'fail', 'message': 'Bad signature'}), 500

    return jsonify({'status': 'success', 'message': 'User is already confirmed'})



# TODO: make request safe for non authorized users
@app.route('/api/address/<address_id>', methods=['GET'])
@token_required
def get_address(current_user, address_id):
    address = db.session.query(Address, User).join(User, Address.user_id == User.id).filter(Address.id == address_id).first()

    if not address:
        return jsonify({'status': 'not found', 'message': 'Address was not found'}), 404

    address_data = {}
    address_data['id'] = address.Address.id
    address_data['firstname'] = address.User.firstname
    address_data['lastname'] = address.User.lastname
    address_data['email'] = address.User.email
    address_data['street'] = address.Address.street
    address_data['city'] = address.Address.city
    address_data['zipcode'] = address.Address.zipcode
    address_data['country'] = address.Address.country
    address_data['state'] = address.Address.state

    return jsonify({'status': 'success', 'address': address_data})


@app.route('/api/address', methods=['POST'])
@token_required
def create_address(current_user):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()
    address_id = create_id()

    new_address = Address(id=address_id, firstname=data['firstname'], lastname=data['lastname'], street=data['street'],
        zipcode=data['zipcode'], country=data['country'], city=data['city'], state=data['state'], user_id=str(current_user.id))

    user = User.query.filter_by(id=str(current_user.id)).first()

    user.address_id = address_id
    db.session.flush()

    db.session.add(new_address)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'New address with id {} was created!'.format(address_id), 'id': address_id})


@app.route('/api/address/<address_id>', methods=['PUT'])
@token_required
def update_address(current_user, address_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()
    address = Address.query.filter_by(id=address_id).filter_by(user_id=str(current_user.id)).first()

    if not address:
        return jsonify({'status': 'not found'}), 404

    address.firstname = data['firstname']
    address.lastname =data['lastname']
    address.zipcode = data['zipcode']
    address.country = data['country']
    address.street = data['street']
    address.state = data['state']
    address.city = data['city']

    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Updated address with id {}!'.format(address_id), 'id': address_id})


@app.route('/api/order', methods=['POST'])
@token_required
def create_order(current_user):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()

    product = Product.query.filter_by(id=data['product_id']).first()

    if not product:
        return jsonify({'status': 'fail', 'message': 'Product was not found!'}), 404

    product.status = 'sold'
    db.session.flush()

    order_id = create_id()
    new_order = Order(id=order_id, status='pending', user_id=data['user_id'], product_id=data['product_id'], address_id=data['address_id'])

    db.session.add(new_order)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'New order with id {} was created!'.format(order_id), 'id': order_id})


@app.route('/api/order/<order_id>', methods=['GET'])
@token_required
def get_order(current_user, order_id):
    order = db.session.query(Order, Product, User, Address, Currency, ProductCondition,
        func.group_concat(ProductImage.image).label('product_images')).join(
        User, Order.user_id == User.id).join(
        Product, Order.product_id == Product.id).join(
        Currency, Product.currency_id == Currency.id).join(
        ProductCondition, Product.condition_id == ProductCondition.id).join(
        ProductImage, ProductImage.product_id == Product.id).join(
        Address, Order.address_id == Address.id).filter(
        Order.id == order_id).group_by(Product.id, ProductImage.id).first()

    if not order:
        return jsonify({'status': 'not found', 'message': 'Address was not found'}), 404

    order_data = {}
    order_data['id'] = order.Address.id
    order_data['name'] = order.Product.name
    order_data['price'] = str(order.Product.price)
    order_data['condition'] = order.ProductCondition.name
    order_data['currency'] = order.Currency.unit_symbol
    order_data['thumbnail'] = order.product_images
    order_data['description'] = order.Product.description
    order_data['shipping_fee'] = str(order.Product.shipping_fee)
    order_data['total_amount'] = str(order.Product.price + order.Product.shipping_fee)
    order_data['created_date'] = order.Order.created_date
    order_data['street'] = order.Address.street
    order_data['city'] = order.Address.city
    order_data['zipcode'] = order.Address.zipcode
    order_data['firstname'] = order.Address.firstname
    order_data['lastname'] = order.Address.lastname

    return jsonify({'status': 'success', 'order': order_data})



@app.route('/api/order/user/<user_id>', methods=['GET'])
@token_required
def get_all_order_by_user(current_user, user_id):
    orders = db.session.query(Order, Product, User, Currency,
        Address, ProductImage, ProductCondition).join(
        User, Order.user_id == User.id).join(
        Address, Order.address_id == Address.id).join(
        Product, Order.product_id == Product.id).join(
        ProductCondition, Product.condition_id == ProductCondition.id).join(
        Currency, Product.currency_id == Currency.id).join(
        ProductImage, ProductImage.product_id == Product.id).filter(
        Order.visible == True).filter(Order.user_id == user_id).group_by(
        Order.id).order_by(Order.created_date.desc()).all()

    if not orders:
        return jsonify({'status': 'not found', 'message': 'No order was found'}), 404

    output = []
    for order in orders:
        order_data = {}
        order_data['id'] = order.Order.id
        order_data['name'] = order.Product.name
        order_data['price'] = str(order.Product.price)
        order_data['condition'] = order.ProductCondition.name
        order_data['currency'] = order.Currency.unit_symbol
        order_data['thumbnail'] = order.ProductImage.image
        order_data['description'] = order.Product.description
        order_data['shipping_fee'] = str(order.Product.shipping_fee)
        order_data['total_amount'] = str(order.Product.price + order.Product.shipping_fee)
        order_data['created_date'] = order.Order.created_date
        order_data['street'] = order.Address.street
        order_data['city'] = order.Address.city
        order_data['zipcode'] = order.Address.zipcode
        order_data['firstname'] = order.Address.firstname
        order_data['lastname'] = order.Address.lastname
        output.append(order_data)

    return jsonify({'status': 'success', 'orders': output})


@app.route('/api/order/<order_id>', methods=['PUT'])
@token_required
def update_order(current_user, order_id):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    order = Order.query.filter_by(id=order_id).filter_by(user_id=str(current_user.id)).first()

    if not order:
        return jsonify({'status': 'Order not found'}), 404

    order.visible = False
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Updated order with id {}!'.format(order_id), 'id': order_id})


@app.route('/api/condition/<condition_id>', methods=['GET'])
def get_condition_by_id(condition_id):
    print condition_id
    condition = ProductCondition.query.filter_by(id=condition_id).first()

    if not condition:
        return jsonify({'status': 'fail'})

    condition_data = {}
    condition_data['id'] = condition.id
    condition_data['name'] = condition.name
    condition_data['description'] = condition.description
    condition_data['user_id'] = condition.user_id

    return jsonify({'status': 'success', 'condition': condition_data})


@app.route('/api/conditions', methods=['GET'])
def get_all_conditions():
    conditions = ProductCondition.query.all()

    output = []
    for condition in conditions:
        condition_data = {}
        condition_data['id'] = condition.id
        condition_data['name'] = condition.name
        condition_data['description'] = condition.description
        condition_data['user_id'] = condition.user_id
        output.append(condition_data)

    return jsonify({'status': 'success', 'conditions': output})


@app.route('/api/condition', methods=['POST'])
@token_required
def create_condition(current_user):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()
    condition_id = create_id()
    new_condition = ProductCondition(id=condition_id, name=data['name'],
        description=data['description'], user_id=current_user.id)

    db.session.add(new_condition)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'New condition added!'})


@app.route('/api/radius', methods=['POST'])
def get_all_products_in_radius():
    data = request.get_json()

    location = db.session.query(Location).filter(or_(Location.city == data['city_or_zip'],
        Location.zip == data['city_or_zip'])).first()

    if not location:
        return jsonify({'status': 'fail', 'message': 'No location has been found'})

    products = db.session.query(Location, Product, Currency,
        ProductCategory, ProductCondition, ProductImage, Address, User,
        func.group_concat(ProductImage.image).label('product_images'),
        select([text('( 6371 * acos( cos( radians({0}) ) * \
        cos( radians( lat ) ) * cos( radians( lng ) - radians({1}) ) + \
        sin( radians({0}) ) * sin( radians( lat ) ) ) )'.format(location.lat, location.lng))])
        .label('distance')).join(Address, Address.zipcode == Location.zip) \
        .join(Product, Product.address_id == Address.id) \
        .join(Currency, Product.currency_id == Currency.id) \
        .join(ProductCondition, Product.condition_id == ProductCondition.id) \
        .join(ProductCategory, Product.category_id == ProductCategory.id) \
        .join(ProductImage, ProductImage.product_id == Product.id) \
        .join(User, Product.user_id == User.id) \
        .filter(Product.status != 'sold') \
        .having(column('distance') < '{}'.format(data['distance'])) \
        .group_by(Product.id) \
        .order_by(Product.created_date.desc()) \
        .all()

    output = []
    for product in products:
        product_data = {}

        product_data['id'] = product.Product.id
        product_data['name'] = product.Product.name
        product_data['price'] = str(product.Product.price)
        product_data['currency'] = product.Currency.unit_symbol
        product_data['condition'] = product.ProductCondition.name
        product_data['thumbnail'] = product.ProductImage.image
        product_data['description'] = product.Product.description
        product_data['shipping_fee'] = str(product.Product.shipping_fee)
        product_data['category'] = product.ProductCategory.name
        product_data['category_id'] = product.ProductCategory.id
        product_data['currency_id'] = product.Currency.id
        product_data['user_name'] = product.User.name
        product_data['image'] = product.product_images
        product_data['city'] = product.Address.city
        product_data['zip'] = product.Address.zipcode
        product_data['user_id'] = product.User.id
        output.append(product_data)

    return jsonify({'status': 'success', 'products': output})


@app.route('/api/wishlist', methods=['POST'])
@token_required
def create_wishlist_item(current_user):
    user = query_user_by_id(current_user.id)

    if not user:
        return jsonify({'status': 'fail', 'message': 'You must confirm your mail address!'}), 401

    data = request.get_json()
    wishlist_id = create_id()

    try:
        new_wishlist = Wishlist(id=wishlist_id, product_id=data['product_id'], user_id=str(current_user.id))
        db.session.add(new_wishlist)
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        return jsonify({'status': 'conflict', 'message': 'Item already on your wishlist!'}), 409

    return jsonify({'status': 'success', 'message': 'New wishlist with id {} was created!'.format(wishlist_id), 'id': wishlist_id})


@app.route('/api/wishlist', methods=['GET'])
@token_required
def get_all_wishlist_items_by_user(current_user):
    wishlist_items = db.session.query(Wishlist, Product, Currency, Address,
        ProductCondition, ProductImage, ProductCategory, User ) \
        .filter(Wishlist.user_id == str(current_user.id)) \
        .join(Product, Product.id == Wishlist.product_id) \
        .join(Currency, Product.currency_id == Currency.id) \
        .join(ProductCondition, Product.condition_id == ProductCondition.id) \
        .join(ProductCategory, Product.category_id == ProductCategory.id) \
        .join(ProductImage, ProductImage.product_id == Product.id) \
        .join(Address, Product.address_id == Address.id) \
        .join(User, Product.user_id == User.id) \
        .group_by(Product.id) \
        .all()

    output = []
    for wishlist_item in wishlist_items:
        wishlist_data = {}
        wishlist_data['id'] = wishlist_item.Product.id
        wishlist_data['product_id'] = wishlist_item.Product.id
        wishlist_data['name'] = wishlist_item.Product.name
        wishlist_data['price'] = str(wishlist_item.Product.price)
        wishlist_data['currency'] = wishlist_item.Currency.unit_symbol
        wishlist_data['condition'] = wishlist_item.ProductCondition.name
        wishlist_data['thumbnail'] = wishlist_item.ProductImage.image
        wishlist_data['description'] = wishlist_item.Product.description
        wishlist_data['shipping_fee'] = str(wishlist_item.Product.shipping_fee)
        wishlist_data['category'] = wishlist_item.ProductCategory.name
        wishlist_data['category_id'] = wishlist_item.ProductCategory.id
        wishlist_data['currency_id'] = wishlist_item.Currency.id
        wishlist_data['user_name'] = wishlist_item.User.name
        # wishlist_data['image'] = wishlist_item.product_images
        wishlist_data['city'] = wishlist_item.Address.city
        wishlist_data['zip'] = wishlist_item.Address.zipcode
        wishlist_data['user_id'] = wishlist_item.User.id
        output.append(wishlist_data)

    return jsonify({'status': 'success', 'wishlist': output})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
