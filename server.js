// Handler of uncaught exception is supposed to be at the top before the entire app.
//crashing the app after an uncaught exception is a must; to get out of the unclean-state
process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION !! Shutting down...');
  console.log(err.name, err.message);
  process.exit(1); // crash the app
  //Note: another 3rd party tool, on the host, should be set to restart the app once it crashes
});

const app = require('./app'); // app.js = express, routes, middlewares

require('./database')
// Start the server
const port = process.env.PORT || 3001;
const server = app.listen(port, () => {
  console.log(
    `App is running on port ${port}, "${process.env.NODE_ENV.toUpperCase()}" environment`
  );
});

// listen on "unhandledRejection" event
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLER REJECTION * Shutting down...');
  console.log(err.name, err.message);
  // close the app gracefully
  server.close(() => {
    process.exit(1); // crash the app
    //Note: another 3rd party tool, on the host, should be set to restart the app once it crashes
  });
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down the app gracefully...');
  server.close(() => {
    console.log('Process Terminated!');
  });
});
