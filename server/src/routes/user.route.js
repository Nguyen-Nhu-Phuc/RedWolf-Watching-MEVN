import express from 'express';
import { body } from 'express-validator';

import tokenMiddleware from '../middlewares/token.middleware.js';
import requestHandler from '../handlers/request.handler.js';
import userController from '../controllers/user.controller.js';
import User from '../models/user.model.js';

const router = express.Router();

// POST /users/auth/register
router.post(
    '/auth/register',
    body('fullName')
        .exists().withMessage('Full name is required')
        .isLength({ min: 3 }).withMessage('Full name minimum 3 characters'),
    body('username')
        .exists().withMessage('Username is required')
        .isLength({ min: 8 }).withMessage('Username minimum 8 characters')
        .custom(async value => {
            const user = await User.findOne({ username: value });
            if (user) {
                return Promise.reject('Username already used');
            }
        }),
    body('password')
        .exists().withMessage('Password is required')
        .isLength({ min: 8 }).withMessage('Password minimum 8 characters'),
    requestHandler.validate,  
    userController.registerUser
);

// POST /users/auth/login
router.post(
    '/auth/login',
    body('username')
        .exists().withMessage('Username is required')
        .isLength({ min: 8 }).withMessage('Username minimum 8 characters'),
    body('password')
        .exists().withMessage('Password is required')
        .isLength({ min: 8 }).withMessage('Password minimum 8 characters'),
    requestHandler.validate,  
    userController.loginUser
);


router.patch('/password', tokenMiddleware.auth, userController.changePassword);

router.get('/stored', tokenMiddleware.auth, userController.stored);

router.delete('/:id/force', tokenMiddleware.auth, userController.forceDelete);

router.delete('/:id', tokenMiddleware.auth, userController.softDel);

router.put('/restore', tokenMiddleware.auth, userController.restoreUser);

router.get('/trash', tokenMiddleware.auth, userController.deletedUsers);

router.get('/info', tokenMiddleware.auth, userController.getInfo);

export default router;
