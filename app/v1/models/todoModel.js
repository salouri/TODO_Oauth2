const mongoose = require('mongoose');

const schemaDefinition = {
  title: {
    type: String,
    required: [true, 'A TODO item must have a title'],
    trim: true,
    maxlength: [100, 'A TODO title must not be longer than 100 characters'],
    minlength: [10, 'A TODO title must be 10 characters at least'],
  },
  description: {
    type: String,
    required: [true, 'A TODO item must have a description'],
    trim: true,
    maxlength: [400, 'A TODO description must not be longer than 400 characters'],
    minlength: [10, 'A TODO description must be 10 characters at least'],
  },
  createdAt: {
    type: Date,
    default: Date.now(), // mongoose re-formats the date from a timestamp (Date.now()) to mm/dd/yy
    select: false, // filter out this field from any request responces
  },
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'A TODO must belong to a user'],
  },
};
const schemaOptions = {
  toJSON: { virtuals: true }, // when data is outputed as JSON or as Object, set virtuals true
  toObject: { virtuals: true },
};
const todoSchema = new mongoose.Schema(schemaDefinition, schemaOptions);

const Todo = mongoose.model('Todo', todoSchema);

module.exports = Todo;