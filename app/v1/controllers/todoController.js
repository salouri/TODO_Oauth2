const Todo = require('../models/todoModel');
const factory = require('./utils/handlerFactory');

//---------------------------------------------------------------------------
exports.getAllTodos = factory.getAll(Todo);

exports.createTodo = factory.createOne(Todo);
exports.getTodo = factory.getOne(Todo);
exports.updateTodo = factory.updateOne(Todo);
exports.deleteTodo = factory.deleteOne(Todo);
