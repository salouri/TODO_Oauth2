// const path = require('path');
const express = require('express');
var session = require('express-session');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const compression = require('compression');

const AppError = require('./app/v1/utils/appError');
const globalErrorHandler = require('./app/v1/controllers/utils/errorController');
const userRouter = require('./app/v1/routes/userRoutes');
const todoRouter = require('./app/v1/routes/todoRoutes');
const oauthRouter = require('./app/v1/routes/oauthRoutes');

const app = express();
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
  })
);
// enable ONLY if your website is running behind a proxy (e.g. allows to check on "X-Forwarded-Proto" header)
// app.enable('trust proxy');

// Implement CORS to allow other domains to request our API
app.use(cors()); // Acess-Control-Allow-Origin *
//if the front-end is on the same domain as the api: cors({ origin: 'https://www.mydomain.com'})

app.options('*', cors()); // respond to "options" requests the browser sends before put/patch/delete

/* GLOBAL MIDDLEWARES -----------------------------------------------------------------------------*/

//Serving static files: ./public directory as the root (/)
app.use(express.static(`${__dirname}/public`));

//set Security HTTP headers
app.use(helmet());

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev')); // Morgan: 3rd-party Middleware for logging
}

//Limit requests from the same IP address
const limiter = rateLimit({
  max: 100, //requests per window time
  windowMs: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again in an hour!',
});
app.use('/api', limiter); //apply limiter only to "/api" based routes

//Body parser, reading data from body into req.body (with size limit of 10 kb)
app.use(express.json({ limit: '10kb' }));
// Url-Encoded Form Parser
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
//Cookies parser
app.use(cookieParser());
//Data sanitization against NoSQL query injection
app.use(mongoSanitize());

//Data sanitization against XSS (html+js code)
app.use(xss());

//Prevent http paramter pollution (duplicate parameters in the query string)
app.use(hpp());

// The middleware will attempt to compress response bodies for all requests that traverse through it...
// ...(except when response has "Cache-Control" header with ""no-transform"" directive)
app.use(compression());

// Custom middleware:
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  // console.log('req.cookies:', JSON.stringify(req.cookies)); //must use "cookie-parser" as a middleware before this line
  next();
});

/* ROUTES ------------------------------------------------------------------------------ */

app.use('/api/v1/users', userRouter);
app.use('/api/v1/todos', todoRouter);
app.use('/api/v1/auth', oauthRouter);

// A midleware to handle ALL other (undefined) routes
app.all('*', (req, res, next) => {
  // using custom class for errors (extending Error)
  next(new AppError(`Can't find ${req.originalUrl} on this server`, 404));
});

// Error Handling Middleware:
app.use(globalErrorHandler);

module.exports = app;
