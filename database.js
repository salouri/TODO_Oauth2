const mongoose = require('mongoose');

const password = process.env.DB_PASSWORD;
const database = process.env.DATABASE.replace('<DB_PASSWORD>', password)
  .replace('<DB_USER>', process.env.DB_USER)
  .replace('<DB_NAME>', process.env.DB_NAME);

const connectOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true, //use the new "Server Discover and Monitoring" engine
  ssl: true,
  sslValidate: true,
};

mongoose
  .connect(database, connectOptions)
  .then(() => {
    console.log('Database Cloud-Connection Successful');
  })
  .catch((err) => {
    console.log('Database connection failed!');
    console.log(err);
  });