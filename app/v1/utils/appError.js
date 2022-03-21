// this class will be used for operaional errors only (not programming errors)
class AppError extends Error {
  constructor(message, statusCode) {
    super(message); // constructor of "Error" (parent) class accepts only one parameter: message

    this.message = message;
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;
