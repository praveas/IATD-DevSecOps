import jsonschema

from api_views.users import token_validator
from config import db
from constants import APPLICATION_JSON, INVALID_TOKEN
from api_views.json_schemas import add_book_schema
from flask import jsonify, Response, request, json
from models.user_model import User
from models.books_model import Book
from app import vuln


def error_message_helper(msg):
    return '{ "status": "fail", "message": "' + msg + '"}'

def get_all_books():
    return_value = jsonify({'Books': Book.get_all_books()})
    return return_value

def add_new_book():
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, add_book_schema)
    except jsonschema.exceptions.ValidationError:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype=APPLICATION_JSON)
    resp = token_validator(request.headers.get('Authorization'))
    if "expired" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    elif INVALID_TOKEN in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    else:
        user = User.query.filter_by(username=resp).first()

        # check if user already has this book title
        book = Book.query.filter_by(user=user, book_title=request_data.get('book_title')).first()
        if book:
            return Response(error_message_helper("Book Already exists!"), 400, mimetype=APPLICATION_JSON)
        else:
            new_book = Book(book_title=request_data.get('book_title'), secret_content=request_data.get('secret'),
                            user_id=user.id)
            db.session.add(new_book)
            db.session.commit()
            response_object = {
                'status': 'success',
                'message': 'Book has been added.'
            }
            return Response(json.dumps(response_object), 200, mimetype=APPLICATION_JSON)

def get_by_title(book_title):
    resp = token_validator(request.headers.get('Authorization'))
    if "expired" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    elif INVALID_TOKEN in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    else:
        if vuln:  # Broken Object Level Authorization
            book = Book.query.filter_by(book_title=str(book_title)).first()
            if book:
                response_object = {
                    'book_title': book.book_title,
                    'secret': book.secret_content,
                    'owner': book.user.username
                }
                return Response(json.dumps(response_object), 200, mimetype=APPLICATION_JSON)
            else:
                return Response(error_message_helper("Book not found!"), 404, mimetype=APPLICATION_JSON)
        else:
            user = User.query.filter_by(username=resp).first()
            book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
            if book:
                response_object = {
                    'book_title': book.book_title,
                    'secret': book.secret_content,
                    'owner': book.user.username
                }
                return Response(json.dumps(response_object), 200, mimetype=APPLICATION_JSON)
            else:
                return Response(error_message_helper("Book not found!"), 404, mimetype=APPLICATION_JSON)