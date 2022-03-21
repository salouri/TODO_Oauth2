const express = require('express');
const authController = require('../controllers/authController');
const todoController = require('../controllers/todoController');

const router = express.Router();

//*****************************************************************/
//All below Routes are protected
router.use(authController.isAuthorized);

// Remember: '/' ==>> '/api/v1/todos/'
router.route('/')
.get(todoController.getAllTodos)
.post(todoController.createTodo);

router
  .route('/:id')
  .get(todoController.getTodo)
  .patch(todoController.updateTodo)
  .delete(todoController.deleteTodo);

module.exports = router;
