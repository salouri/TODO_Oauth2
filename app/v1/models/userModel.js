const crypto = require('crypto'); // built-in library
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const schemaDefinition = {
  name: {
    type: String,
    required: [true, 'A user must have a name'],
    trim: true,
  },
  username: {
    type: String,
    required: [true, 'Please provide your username(email)'],
    trim: true,
    unique: [true, 'This email already exists!'],
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
  },
  photo: {
    type: String,
    default: 'default.jpg',
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'lead-guide', 'guide'],
    default: 'user',
  },
  password: {
    type: String,
    required: [true, ' Please provide a password'],
    minlength: 8,
    select: false, // hide in query results. Use ".select('+password')" to select this field in queries.
  },
  passwordConfirm: {
    type: String,
    required: [true, ' Please provide a password confirmation'],
    validate: {
      validator: function (passConf) {
        return passConf === this.password;
      },
      message: 'passwords are not matched!',
    },
  },
  passwordChangedAt: Date, // Only set if the "password" field is modified in a pre-save middleware
  //Below fields ONLY get set in "forgotPassword", and then get deleleted in "resetPassword"
  passwordResetToken: String,
  passwordResetExpireAt: Date,
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
};

const userSchema = new mongoose.Schema(schemaDefinition);

// run this Document middleware ONLY if password has been modified
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  //this.isModified : mongoose method to check if document was modified before save

  const cpuCost = 12; // default value is 10. The higher the slower but it'll be more secure
  this.password = await bcrypt.hash(this.password, cpuCost);
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000; //the -1sec is to encounter the delay caused by document.save() slowness
  next();
});

userSchema.pre(/^find/, function (next) {
  //"this" points to the current query
  this.find({ active: { $ne: false } });
  next();
});

// Instance Method: available on all documents of the collection:
// method will compare plainPassword send by the user, with the encrypted encrPassword in the document
userSchema.methods.isPasswordCorrect = async function (
  plainPassword,
  encrPassword
) {
  return await bcrypt.compare(plainPassword, encrPassword);
};

//instance method to check if password was changed after a timestamp
userSchema.methods.changedPasswordAfter = async function (jwtTimestamp) {
  let result = false;
  if (this.passwordChangedAt) {
    result =
      Number(this.passwordChangedAt.getTime() / 1000) > Number(jwtTimestamp);
  }

  return result;
};

// instance method to generate new temporary password for user
userSchema.methods.createPasswordResetToken = async function () {
  const saltToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(saltToken)
    .digest('hex');

  this.passwordResetExpireAt = Date.now() + 10 * 60 * 1000; // 10 minutes

  return saltToken;
};
// CREATE MODEL
const User = mongoose.model('User', userSchema);
module.exports = User;
