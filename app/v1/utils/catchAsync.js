// the purpose for this function is to avoid writing a try/catch on async functions in Express middlewares and route handlers.
// any error catched and sent to 'next()', will go to the global error handler: globalErrorHandler @ app.js
module.exports = (fn) => (req, res, next) => fn(req, res, next).catch(next);
// .catch(next) ===>> .catch(err => next(err));
