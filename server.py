#!/usr/bin/env python

from flask import Flask, request, jsonify, make_response
from flask.ext.uploads import UploadSet, configure_uploads, IMAGES
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import column, func, literal_column, alias
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from whoosh.analysis import StemmingAnalyzer
from whoosh.analysis import SimpleAnalyzer
from resizeimage import resizeimage
from PIL import Image
import flask_whooshalchemy as wa
import datetime
import base64
import uuid
import time
import jwt
import os


app = Flask(__name__)
photos = UploadSet('photos', IMAGES)

app.config['SECRET_KEY'] = os.environ['SECRET']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(os.environ['DATABASE_URI'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['DEBUG'] = True
app.config['WHOOSH_BASE'] = 'whoosh'
app.config['WHOOSH_ANALYZER'] = StemmingAnalyzer()
app.config['UPLOADED_PHOTOS_DEST'] = 'static/img'

db = SQLAlchemy(app)
configure_uploads(app, photos)


class User(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    website = db.Column(db.String(80))
    phone = db.Column(db.String(50))
    name = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class Address(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    city = db.Column(db.String(50))
    street = db.Column(db.String(50))
    zipcode = db.Column(db.String(50))
    country = db.Column(db.String(50))
    suite = db.Column(db.String(50))
    user_id = db.Column(db.String(50))


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
    name = db.Column(db.String(70))
    price = db.Column(db.String(30))
    thumbnail = db.Column(db.String(500))
    description = db.Column(db.String(500))
    category_id = db.Column(db.String(50))
    currency_id = db.Column(db.String(30))
    user_id = db.Column(db.String(50))


class ProductImage(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    # created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    image = db.Column(db.String(500))
    product_id = db.Column(db.String(50))


class ProductCategory(db.Model):
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


@app.route('/user', methods=['GET'])
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
        user_data['username'] = user.username
        user_data['website'] = user.website
        user_data['email'] = user.email
        user_data['phone'] = user.phone
        user_data['admin'] = user.admin
        user_data['name'] = user.name
        output.append(user_data)

    return jsonify({'status': 'success', 'total': total, 'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'status': 'not found', 'message': 'No user found!'}), 404

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['website'] = user.website
    user_data['email'] = user.email
    user_data['phone'] = user.phone
    user_data['admin'] = user.admin
    user_data['name'] = user.name

    return jsonify({'status': 'success', 'user': user_data})


@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    if not data or not 'email' in data or not 'password' in data:
        return jsonify({'status': 'bad request', 'message': 'Please provide your email and password!'}), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')

    try:
        user_id = str(uuid.uuid4()).split('-')[4]
        new_user = User(id=user_id,
                        public_id=user_id,
                        password=hashed_password,
                        email=data['email'],
                        name=data['name'],
                        admin=False)

        db.session.add(new_user)
        db.session.flush()

        address_id = str(uuid.uuid4()).split('-')[4]
        new_address = Address(id=address_id, user_id=new_user.id)
        db.session.add(new_address)
        db.session.flush()

        exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)

        token = jwt.encode(
            {'public_id': user_id, 'exp': exp}, app.config['SECRET_KEY'])

        token_id = str(uuid.uuid4()).split('-')[4]
        new_token = Token(id=token_id, token=token,
                          blacklisted=False, user_id=user_id)
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
        return jsonify({'status': 'success', 'message': 'New user created!'}), 201


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def update_user(current_user, public_id):
    data = request.get_json()
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'status': 'not found', 'message': 'No user found!'}), 404

    return update_user_query(user, data)


def update_user_query(user, data):
    try:
        user.name = data['name']
        user.email = data['email']
        user.username = data['username']
        user.website = data['website']
        user.phone = data['phone']
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


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'status': 'not authorized', 'message': 'Cannot perform that function!'}), 401

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'status': 'not found', 'message': 'No user found!'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'The user has been deleted!'}), 204


@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    request_token = request.headers.get('authorization').split(' ')[1]
    token = Token.query.filter_by(token=request_token).first()

    if token:
        token.blacklisted = True
        db.session.commit()

    return jsonify({'status': 'success', 'message': 'Successfully logged out!'})


@app.route('/status', methods=['GET'])
def login_status():
    request_token = request.headers.get('authorization').split(' ')[1]
    token = db.session.query(Token, User).filter(
        Token.token == request_token).filter(User.id == Token.user_id).first()

    try:
        jwt.decode(request_token, app.config['SECRET_KEY'])
        return jsonify({'status': 'success', 'message': 'Go ahead you are logged in!', 'user_id': token.User.id, 'name': token.User.name})
    except AttributeError as e:
        return jsonify({'status': 'internal error', 'message': 'Oooopss, there was an error on our server!'}), 500
    except Exception as e:
        return jsonify({'status': 'not authorized', 'message': 'Please login!'}), 401


@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(jsonify({'status': 'not authorized', 'message': 'Please provide your login credentials!'}), 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    try:
        user = User.query.filter_by(email=auth.username).first()
    except Exception as e:
        print e
        return jsonify({'status': 'internal error', 'message': 'Oooopss, there was an error on our server!'}), 500

    if not user:
        return make_response(jsonify({'status': 'not authorized', 'message': 'Could not verify your credentials!'}), 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    if check_password_hash(user.password, auth.password):
        exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)

        token = jwt.encode({'public_id': user.public_id,
                            'exp': exp}, app.config['SECRET_KEY'])

        token_id = str(uuid.uuid4()).split('-')[4]
        new_token = Token(id=token_id, token=token,
                          blacklisted=False, user_id=user.id)
        db.session.add(new_token)
        db.session.commit()

        return jsonify({'status': 'success', 'admin': user.admin, 'token': token.decode('utf-8'), 'user_id': user.id})

    return make_response(jsonify({'status': 'not authorized', 'message': 'Could not verify your credentials!'}), 401, {'WWW-Authenticate': 'Basic realm="Login required"'})


@app.route('/currencies', methods=['GET'])
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


@app.route('/product-categories', methods=['GET'])
def get_all_product_categories():
    product_categories = ProductCategory.query.order_by(
        ProductCategory.user_id.desc()).all()
    output = []

    for product_category in product_categories:
        product_category_data = {}
        product_category_data['id'] = product_category.id
        product_category_data['name'] = product_category.name
        product_category_data['description'] = product_category.description
        product_category_data['user_id'] = product_category.user_id
        output.append(product_category_data)

    return jsonify({'status': 'success', 'product-categories': output})


@app.route('/product-categories/user', methods=['GET'])
@token_required
def get_all_product_categories_by_user(current_user):
    product_categories = ProductCategory.query.filter_by(
        user_id=current_user.id).order_by(ProductCategory.user_id.desc()).all()
    output = []

    for product_category in product_categories:
        product_category_data = {}
        product_category_data['id'] = product_category.id
        product_category_data['name'] = product_category.name
        product_category_data['description'] = product_category.description
        product_category_data['user_id'] = product_category.user_id
        output.append(product_category_data)

    return jsonify({'status': 'success', 'product-categories': output})


@app.route('/product-category/<product_category_id>', methods=['DELETE'])
@token_required
def delete_product_category(current_user, product_category_id):
    product_category = ProductCategory.query.filter_by(
        id=product_category_id).first()

    if not product_category:
        return jsonify({'status': 'not found', 'message': 'No product category found!'}), 404

    db.session.delete(product_category)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item deleted!'}), 204


@app.route('/product-category/<product_category_id>', methods=['PUT'])
@token_required
def update_product_category(current_user, product_category_id):
    data = request.get_json()

    product_category = ProductCategory.query.filter_by(
        id=product_category_id).first()

    if not product_category:
        return jsonify({'status': 'not found', 'message': 'No product found'}), 404

    product_category.name = data['name']
    product_category.description = data['description']
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item has been updated'})


@app.route('/product-category', methods=['POST'])
@token_required
def create_product_category(current_user):
    data = request.get_json()
    product_category_id = str(uuid.uuid4()).split('-')[4]
    new_product_category = ProductCategory(id=product_category_id,
                                           name=data['name'],
                                           description=data['description'],
                                           user_id=current_user.id)

    db.session.add(new_product_category)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'New product added!'})


@app.route('/products', methods=['GET'])
def get_all_products():
    # filter(ProductImage.product_id == Product.id)
    products = db.session.query(Product, ProductCategory, ProductImage, Currency, User).filter(
        Product.category_id == ProductCategory.id).filter(Product.user_id == User.id).filter(
        ProductImage.product_id == Product.id).group_by(Product.id).filter(Product.currency_id == Currency.id).all()

    output = []
    for product in products:
        product_data = {}
        product_data['id'] = product.Product.id
        product_data['name'] = product.Product.name
        product_data['price'] = product.Product.price
        product_data['currency'] = product.Currency.unit_symbol
        product_data['thumbnail'] = product.ProductImage.image
        product_data['description'] = product.Product.description
        product_data['category'] = product.ProductCategory.name
        product_data['category_id'] = product.ProductCategory.id
        product_data['user_name'] = product.User.name
        product_data['user_id'] = product.User.id
        output.append(product_data)

    return jsonify({'status': 'success', 'products': output})


@app.route('/product/category/<category_id>', methods=['GET'])
def get_all_products_by_category(category_id):
    products = db.session.query(Product, ProductCategory, ProductImage, Currency, User).filter(
        Product.category_id == ProductCategory.id).filter(Product.id == ProductImage.product_id).filter(
        Product.category_id == category_id).filter(Product.user_id == User.id).filter(
        Product.currency_id == Currency.id).group_by(Product.id).all()

    output = []
    for product in products:
        product_data = {}
        product_data['id'] = product.Product.id
        product_data['name'] = product.Product.name
        product_data['price'] = product.Product.price
        product_data['currency'] = product.Currency.unit_symbol
        product_data['thumbnail'] = product.ProductImage.image
        product_data['description'] = product.Product.description
        product_data['category'] = product.ProductCategory.name
        product_data['category_id'] = product.ProductCategory.id
        product_data['user_name'] = product.User.name
        product_data['user_id'] = product.User.id
        output.append(product_data)

    return jsonify({'status': 'success', 'products': output})


@app.route('/product/user/<user_id>', methods=['GET'])
def get_all_products_by_user(user_id):
    products = db.session.query(Product, ProductCategory, ProductImage, Currency, User).filter(
        Product.category_id == ProductCategory.id).filter(Product.id == ProductImage.product_id).filter(
        Product.user_id == user_id).filter(Product.user_id == User.id).filter(
        Product.currency_id == Currency.id).group_by(Product.id).all()

    output = []
    for product in products:
        product_data = {}
        product_data['id'] = product.Product.id
        product_data['name'] = product.Product.name
        product_data['price'] = product.Product.price
        product_data['currency'] = product.Currency.unit_symbol
        product_data['thumbnail'] = product.ProductImage.image
        product_data['description'] = product.Product.description
        product_data['category'] = product.ProductCategory.name
        product_data['category_id'] = product.ProductCategory.id
        product_data['currency_id'] = product.Currency.id
        product_data['user_name'] = product.User.name
        product_data['user_id'] = product.User.id
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


@app.route('/search/<search_query>', methods=['GET'])
def get_all_products_by_query(search_query):
    products = Product.query.whoosh_search(search_query).all()

    output = []
    for product in products:
        product_data = {}
        product_data['id'] = product.id
        product_data['name'] = product.name
        product_data['price'] = product.price
        product_data['currency'] = get_currency_unit(product.currency_id)
        product_data['thumbnail'] = get_product_image(product.id)
        product_data['description'] = product.description
        product_data['category'] = get_product_category_name(
            product.category_id)
        product_data['category_id'] = product.category_id
        product_data['user_name'] = get_user_name(product.user_id)
        product_data['user_id'] = product.user_id
        output.append(product_data)

    return jsonify({'status': 'success', 'products': output})


@app.route('/product/<product_id>', methods=['GET'])
def get_one_product(product_id):
    product = db.session.query(func.group_concat(ProductImage.image).label('product_images'),
                               Product, ProductCategory, ProductImage, Currency, User).filter(Product.user_id == User.id).filter(
        ProductImage.product_id == Product.id).filter(Product.category_id == ProductCategory.id).filter(
        Product.id == product_id).filter(Product.currency_id == Currency.id).first()

    if not product:
        return jsonify({'status': 'not found', 'message': 'No product found'}), 404

    product_data = {}
    product_data['id'] = product.Product.id
    product_data['name'] = product.Product.name
    product_data['price'] = product.Product.price
    product_data['currency'] = product.Currency.unit_symbol
    product_data['thumbnail'] = product.Product.thumbnail
    product_data['description'] = product.Product.description
    product_data['category'] = product.ProductCategory.name
    product_data['category_id'] = product.ProductCategory.id
    product_data['user_name'] = product.User.name
    product_data['user_id'] = product.User.id
    product_data['image'] = product.product_images

    return jsonify(product_data)


@app.route('/product/<product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
    data = request.get_json()

    product = Product.query.filter_by(
        id=product_id, user_id=current_user.id).first()

    if not product:
        return jsonify({'status': 'not found', 'message': 'No product found'}), 404

    product.name = data['name']
    product.price = data['price']
    product.category_id = data['category_id']
    product.description = data['description']

    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item has been updated'})


@app.route('/product/<product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    product = Product.query.filter_by(id=product_id).first()

    if not product:
        return jsonify({'status': 'not found', 'message': 'No product found!'}), 404

    db.session.delete(product)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item deleted!'}), 204


def img_to_base64(filename):
    with open(filename, "rb") as imageFile:
        img_txt = base64.b64encode(imageFile.read())
    return img_txt


@app.route('/upload', methods=['POST'])
@token_required
def create_product(current_user):
    data = request.form

    product_id = str(uuid.uuid4()).split('-')[4]

    for photo in request.files.getlist('thumbnail'):
        product_image_id = str(uuid.uuid4()).split('-')[4]
        filetype = photo.mimetype.split('/')[1]
        name = '{}.{}'.format(product_image_id, filetype)
        path = 'static/img/{}'.format(name)
        photo.save(path)

        try:
            with Image.open(path) as image:
                cover = resizeimage.resize_cover(
                    image, [800, 500], validate=False)
                cover.save(path, image.format)
                db.session.add(
                    ProductImage(
                        id=product_image_id, product_id=product_id, image=img_to_base64(path))
                )
                db.session.flush()
                db.session.commit()
        except Exception as e:
            print e

    try:
        db.session.add(
            Product(id=product_id, name=data['name'], price=data['price'], description=data['description'],
                    category_id=data['category_id'], currency_id=data['currency_id'], user_id=str(current_user.id))
        )
        db.session.flush()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'New product added!'})
    except Exception as e:
        print e
        return jsonify({'status': 'fail', 'message': 'err!'}), 500


@app.route('/inbox', methods=['POST'])
@token_required
def create_message(current_user):
    data = request.get_json()
    message_id = str(uuid.uuid4()).split('-')[4]
    new_message = Inbox(id=message_id, subject=data['subject'], user_id=data['user_id'],
                        parent_id=data['parent_id'], message=data['message'], creator_id=current_user.id)

    db.session.add(new_message)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'New message send!'})


@app.route('/inbox/user/<user_id>/<message_id>', methods=['PUT'])
@token_required
def update_one_message(current_user, user_id, message_id):
    if current_user.id != user_id:
        return jsonify({'status': 'fail', 'message': 'Error, you are not allowed to do this action.'})

    data = request.get_json()
    message = Inbox.query.filter_by(id=message_id, user_id=current_user.id).first()

    if not message:
        return jsonify({'status': 'not found', 'message': 'No message with id {} found!'.format(message_id)}), 404

    message.read = data
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Product item has been updated'})


@app.route('/inbox/user/<user_id>/<message_id>', methods=['GET'])
@token_required
def get_one_message(current_user, user_id, message_id):
    if current_user.id == user_id:
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
        inbox_data['user_id'] = message.User.id

        return jsonify(inbox_data)

    return jsonify({'status': 'fail', 'message': 'Error, you are not allowed to query this content.'})


@app.route('/inbox/user/<user_id>/<message_id>', methods=['DELETE'])
@token_required
def delete_one_message(current_user, user_id, message_id):
    if current_user.id != user_id:
        return jsonify({'status': 'fail', 'message': 'Error, you are not allowed to query this content.'})

    message = Inbox.query.filter_by(id=message_id).first()

    if not message:
        return jsonify({'status': 'not found', 'message': 'No message found'}), 404

    db.session.delete(message)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'The message has been deleted!'}), 204


@app.route('/inbox/user/<user_id>', methods=['GET'])
@token_required
def get_all_messages_by_user(current_user, user_id):
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
