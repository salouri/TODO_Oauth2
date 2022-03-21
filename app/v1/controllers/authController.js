const { default: axios } = require('axios');
const crypto = require('crypto');
const JWT = require('jsonwebtoken');
const User = require('../models/userModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

//---------------------------------------------------------------------------
const createSendToken = (document, sendDoc, statusCode, req, res) => {
  const id = document._id;

  const token = JWT.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

  if ('password' in document) document.password = undefined;

  const data = sendDoc ? { user: document } : null;

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true, // prevents browser from accessing or modification cookie
    // req.secure: an attribute added by Express.js if https is used
    // must add app.enable('trust proxy') in app.js to check on 'x-forwarded-proto' header

    // secure: req.secure || req.headers['x-forwarded-proto'] === 'https'
  };
  // if (process.env.NODE_ENV === 'production') // not all production deployments use https

  res.cookie('jwt', token, cookieOptions);

  res.status(statusCode).json({
    status: 'success',
    token: process.env.NODE_ENV === 'development' ? token : null,
    data,
  });
};

//---------------------------------------------------------------------------
// async func bc we will use db operations(return promises)
exports.signup = catchAsync(async (req, res, next) => {
  next();
}); // end-of signup handler

//---------------------------------------------------------------------------
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || email === null || !password || password === null)
    return next(new AppError('Please provide email and password!', 400));
  //Because of "select: false" on "password" field at the User model, we need to select it manually on queries

  const myUser = await User.findOne({ email }).select('+password');
  if (!myUser || myUser == null) {
    return next(new AppError('Email used does not exist!', 400));
  }

  const correctPassword = await myUser.isPasswordCorrect(
    password,
    myUser.password
  );
  if (!correctPassword)
    return next(new AppError('Incorrect email or password!', 401)); // not authorized
  createSendToken(myUser, true, 201, req, res);
}); //end-of login handler

//---------------------------------------------------------------------------
exports.logout = (req, res) => {
  if('session' in req) {
    req.session?.destroy();
  }
  
  res.cookie('jwt', 'loggedout', {
    expired: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(200).json({ status: 'success' });
};

//---------------------------------------------------------------------------
exports.oauthRedirect = (req, res, next) => {
  try {
    res.redirect(
      `https://github.com/login/oauth/authorize?client_id=${process.env.OAUTH_CLIENT_ID}`
    );
  } catch (err) {
    console.error(err);
    return next(
      new AppError('Redirection to authenticator failed! Try gain later', 400)
    );
  }
};

//---------------------------------------------------------------------------
exports.oauthCallback = catchAsync(async (req, res) => {
  console.log('start oauthCallback');
  console.log(req.query);
  const url = 'https://github.com/login/oauth/access_token';
  const body = {
    client_id: process.env.OAUTH_CLIENT_ID,
    client_secret: process.env.OAUTH_CLIENT_SECRET,
    code: req.query.code,
  };
  const options = {
    headers: {
      accept: 'application/json',
    },
  };
  const auth_res = await axios.post(url, body, options).catch((err) => {
    return res.status(500).json({ err: err.message });
  });
  console.log('auth_res:');
  console.log(auth_res.data);
  const access_token = auth_res.data.access_token;
  
  const user = await axios
    .get('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    })
    .catch((err) => {
      return res.status(500).json({ err: err.message });
    });
    console.log('user profile:');
    console.log(user.data);
    
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: true,
  };

  res.cookie('oautoken', access_token, cookieOptions);

   res.status(200).json({
    status: 'success',
    token: process.env.NODE_ENV === 'development' ? access_token : null,
  });

});
//---------------------------------------------------------------------------
// isLoggedIn MIDDLEWARE: to be used for rendered pages ONLY(no errors)
exports.isLoggedIn = catchAsync(async (req, res, next) => {
  // Check if (JWT) token exists in the request header: Authorization
  let decoded;
  let currentUser;
  if (req.cookies.jwt) {
    await JWT.verify(
      req.cookies.jwt,
      process.env.JWT_SECRET,
      (err, payload) => {
        decoded = payload; // payload={id,iat,expireAt}
      }
    );
    if (decoded) {
      currentUser = await User.findById(decoded.id);
    }

    if (!currentUser) {
      return next();
    }
    // check if passwored has changed since issuing the JWT token
    const passChangeAfterJWT = await currentUser.changedPasswordAfter(
      decoded.iat
    );
    if (passChangeAfterJWT) {
      return next();
    }
  }
  // THERE IS A LOGGED IN USER
  res.locals.user = currentUser; // send currentUser to server side renderer (if any)
  next();
}); //end-of isLoggedIn middleware

//---------------------------------------------------------------------------
// "PROTECT" MIDDLEWARE method
exports.isAuthorized = catchAsync(async (req, res, next) => {
  // Check if (JWT) token exists in the request header: Authorization
  let token;
  // Bearer Schema => {"Authorization" : "Bearer <token>" }
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    // for requests coming from browsers
    token = req.cookies.jwt;
  }

  if (!token || typeof token === 'undefined') {
    return next(
      new AppError('You are not logged in! Please, log in to get access', 401)
    );
  }
  let decoded;
  let currentUser;
  //verify the token:
  await JWT.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) return next(err);
    decoded = payload; // payload={id,iat,expireAt}
    // console.log('JWT token is verified. Payload:', payload);
  });
  // Check if user still exists
  if (decoded) {
    currentUser = await User.findById(decoded.id); // returns a model instance of User ==> a complete Document
  }
  if (!currentUser || currentUser === null) {
    return next(new AppError('User of this token no longer exists.', 401)); // 401: unauthorized (user doesn't exist)
  }
  // check if passwored has changed since issuing the JWT token
  const wasPasswordChangeAfterJWT = await currentUser.changedPasswordAfter(
    decoded.iat
  );
  if (wasPasswordChangeAfterJWT) {
    return next(
      new AppError(
        'Password of this user has been changed. Please, try to login again'
      )
    );
  }
  req.user = currentUser; // usefull for later middleware methods
  res.locals.user = currentUser; // usefull for (views) web page rendering
  next();
}); //end-of isAuthorized middleware

//---------------------------------------------------------------------------
//restrictTo is a function that passes [roles] and wraps a MIDDLEWARE function
exports.restrictTo = (...roles) =>
  catchAsync(async (req, res, next) => {
    // req.user comes from "protect" middleware method, which always comes BEFORE "restrictTo"
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403) // 403: forbidden.
      );
    }
    next();
  }); //end-of restrictTo
//---------------------------------------------------------------------------
// ROUTE HANDLER method
exports.forgotPassword = catchAsync(async (req, res, next) => {
  // get user based on POSTed email
  const myUser = await User.findOne({ email: req.body.email });
  if (!myUser || myUser == null)
    return next(
      new AppError('There is no user with the provided email address.', 404)
    );

  // Generat the "salt" token to be used in generating the hashed password later
  //sets the fields: passwordResetToken, passwordResetExpireAt and returns the "salt"
  const saltToken = await myUser.createPasswordResetToken();
  await myUser.save({ validateBeforeSave: false }); // saves the modified fields of the document in previous method

  // send new password to user by email
  const host = req.get('host');
  const resetURL = `${req.protocol}://${host}/api/v1/users/resetPassword/${saltToken}`;

  try {
    res.status(200).json({
      status: 'success',
      message: `reset URL is created`,
      data: {
        resetURL: resetURL,
      },
    });
  } catch (err) {
    myUser.passwordResetToken = undefined;
    myUser.passwordResetExpireAt = undefined;

    await myUser.save({ validateBeforeSave: false });
    console.log(err);
    return next(
      new AppError(
        'There was a problem creating a reset URL. Try again later!',
        500
      )
    );
  }
}); //end-of forgotPassword handler

//---------------------------------------------------------------------------
// ROUTE HANDLER method for "users/resetPassword" route
exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token provided
  const saltToken = req.params.token;
  const hashedToken = crypto
    .createHash('sha256')
    .update(saltToken)
    .digest('hex');

  const myUser = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpireAt: { $gt: Date.now() },
  });
  // 2) If token has not expired and the user exists, se the new password
  if (!myUser || myUser === null)
    return next(new AppError('Token either is invalid or has expired', 400)); // 400: bad request

  myUser.password = req.body.password;
  myUser.passwordConfirm = req.body.passwordConfirm;
  myUser.passwordResetToken = undefined;
  myUser.passwordResetExpireAt = undefined;
  // myUser.passwordChangedAt = Date.now() - 1000;// moved to a pre-save document middleware
  await myUser.save();

  // 3) Update changedPasswordAt property: // Done on a pre-save middleware inside userModel.js

  // 4) Log the user in and send the JWT token
  createSendToken(myUser, false, 200, req, res);
}); //end-of resetPassword handler

//---------------------------------------------------------------------------
exports.updatePassword = catchAsync(async (req, res, next) => {
  //1) Get user based on email address
  const { passwordCurrent, password, passwordConfirm } = req.body;
  const userID = req.user.id; // user.id attached to req in the login handler!
  const myUser = await User.findById(userID).select('+password');
  //2) Check if POSTed current password is correct
  const correctPassword = await myUser.isPasswordCorrect(
    passwordCurrent,
    myUser.password
  );
  if (!correctPassword)
    return next(new AppError('Incorrect email or password!', 401)); // 401: Unauthorized

  //3) If so, update the password
  myUser.password = password;
  myUser.passwordConfirm = passwordConfirm;
  myUser.passwordResetToken = undefined;
  myUser.passwordResetExpireAt = undefined;
  // myUser.passwordChangedAt = Date.now() - 1000;// moved to a pre-save document middleware
  await myUser.save();
  //4) Log user in, send the JWT
  createSendToken(myUser, false, 200, req, res);
}); //end-of updatePassword handler
