from typing import Callable
import jwt
import inspect
import asyncio

from datetime import timedelta, datetime
from flask import Flask, jsonify, request, redirect
from functools import wraps
from jwt.exceptions import (
    DecodeError,
    InvalidSignatureError,
    InvalidTokenError,
    ExpiredSignatureError
)

class FlaskAuthJWT:
    """
        Flask Auth JWT
    """
    def __init__(
        self,
        app: Flask,
        expire: timedelta = timedelta(days=1),
    ):
        self._app = app
        self._exp = expire

        if not self._app.config.get("JWT_SECRET_KEY"):
            raise ValueError("JWT_SECRET_KEY is missing")
    
    def create_access_token(self, data: dict = {}):
        """
            Create access token

            :param data: data to encode
            :return: encoded token
        """

        if not isinstance(data, dict):
            raise TypeError("data must be a dict")

        return jwt.encode(
            payload={
                "exp": datetime.now() + self._exp,
                "data": data
            },
            key=self._app.config["JWT_SECRET_KEY"],
            algorithm="HS256"
        )

    def token_required(self, options: dict = {}):
        """
            Token verification decorator
            :return: decorator
        """
        def decorator(f: Callable):
            @wraps(f)
            def wrapper(*args, **kwargs):
                cookie = request.cookies

                if not "token" in cookie:
                    return self.__response_exceiption(options=options)

                try:
                    data = jwt.decode(
                        cookie["token"],
                        self._app.config["JWT_SECRET_KEY"],
                        algorithms=["HS256"],
                        verify_exp=True,
                        verify_signature=True,
                        require=["exp"]
                    )

                    if len(f.__annotations__) >= 1:
                        if inspect.iscoroutinefunction(f):
                            return asyncio.run(f(data["data"], *args, **kwargs))

                        return f(data["data"], *args, **kwargs)
                    else:
                        if inspect.iscoroutinefunction(f):
                            return asyncio.run(f(*args, **kwargs))
                        
                        return f(*args, **kwargs)

                except (DecodeError,InvalidSignatureError,InvalidTokenError,ExpiredSignatureError) as e:
                    return self.__response_exceiption(options=options)

            return wrapper

        return decorator

    def __response_exceiption(self, options: dict = {}, status_code: int = 401, message: str = "Unauthorized"):
        if "return_type" in options:
            if options["return_type"] == "redirect":
                return redirect(options["redirect_url"], code=302)

            elif options["return_type"] == "html":
                return f"<h1>{message}</h1>", status_code
            else:
                return f"<h1>{message}</h1>", status_code

        resp = jsonify({"error": message})
        resp.status_code = status_code

        return resp