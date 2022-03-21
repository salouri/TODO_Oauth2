const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

// Remember: '/' ==>> '/api/v1/todos/'
router.get('/', authController.oauthRedirect);
router.get('/callback', authController.oauthCallback);

module.exports = router;
