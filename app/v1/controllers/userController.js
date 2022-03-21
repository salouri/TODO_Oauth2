const multer = require('multer');
const sharp = require('sharp');
const User = require('../models/userModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const factory = require('./utils/handlerFactory');

// // to save photo to storage/database:

// const multerStorage = multer.diskStorage({
//   // cb == next in Express
//   destination: (req, file, cb) => {
//     cb(null, 'public/img/users');
//   },
//   filename: (req, file, cb) => {
//     //user-id-timestamp.ext
//     const ext = file.mimetype.split('/')[1];
//     cb(null, `user-${req.user.id}-${Date.now()}.${ext}`);
//   },
// });

// to save photo as a buffer in memory (accessed as req.file.buffer)
const multerStorage = multer.memoryStorage();

const multerFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new AppError('Only imagees can be uploaded', 400), false);
  }
};

const upload = multer({ storage: multerStorage, fileFilter: multerFilter });

// Middleware for multipart/form-data forms (with input type "file")
exports.uploadUserPhoto = upload.single('photo');

exports.resizeUserPhoto = catchAsync(async (req, res, next) => {
  if (!req.file) return next();

  req.file.filename = `user-${req.user.id}-${Date.now()}.jpeg`;

  await sharp(req.file.buffer)
    .resize(500, 500)
    .toFormat('jpeg')
    .jpeg({ quality: 90 })
    .toFile(`public/img/users/${req.file.filename}`);

  next();
});
//---------------------------------------------------------------------------
const filterObject = (obj, ...arr) => {
  const newObj = {};
  Object.keys(obj).forEach((key) => {
    if (arr.includes(key)) newObj[key] = obj[key];
  });
  return newObj;
};

exports.getMe = catchAsync(async (req, res, next) => {
  req.params.id = req.user.id;
  next();
});

exports.updateMe = catchAsync(async (req, res, next) => {
  //1) Create error if user POSTs password data
  if (req.body.password || req.body.passwordConfirm) {
    return next(
      new AppError(
        'This route is not for password updates. Please, use /updatePassword instead.',
        400
      )
    );
  }

  const filteredBody = filterObject(req.body, 'name', 'email');
  if (req.file) filteredBody.photo = req.file.filename;

  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true,
  });

  if (!updatedUser || updatedUser === null) {
    return next(new AppError('User does not exist', 401));
  }

  res.status(200).json({
    status: 'success',
    token: req.cookies.jwt,
    data: {
      user: updatedUser,
    },
  });
});

//---------------------------------------------------------------------------
exports.deleteMe = catchAsync(async (req, res, next) => {
  const deletedUser = await User.findByIdAndUpdate(
    req.user.id,
    { active: false },
    {
      new: true,
      runValidators: true,
    }
  );
  if (!deletedUser || deletedUser === null) {
    return next(new AppError('User does not exist', 401));
  }

  res.cookie('jwt', 'loggedout', {
    expired: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(200).json({
    status: 'success',
    user: {
      id: deletedUser._id,
    },
    message: `User with email:${deletedUser.username} was deleted successfully.`,// username is actually an email address
  });
});

//---------------------------------------------------------------------------
exports.getAllUsers = factory.getAll(User);

exports.createUser = factory.createOne(User);
exports.getUser = factory.getOne(User);
exports.updateUser = factory.updateOne(User); // passwords are ONLY updated inside updateMe function
exports.deleteUser = factory.deleteOne(User); // for admins to delete a User.
