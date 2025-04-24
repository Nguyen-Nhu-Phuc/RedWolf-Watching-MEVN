import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

import responseHandler from '../handlers/response.handler.js';

import User from '../models/user.model.js';
import Favorite from '../models/favorite.model.js';
import Review from '../models/review.model.js';

// Register user, route POST /users/auth/register
const registerUser = async (req, res) => {
    const { fullName, username, password } = req.body;
    try {
        const userExist = await User.findOne({ username });
        console.log(userExist);

        if (userExist) {
            return responseHandler.badRequest(res, 'Username already exist');
        }

        const hash = await bcrypt.hash(password, 10);

        // // Create user in DB
        const user = await User.create({ fullName, username, password: hash });

        const token = jwt.sign(
            { data: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        responseHandler.created(res, {
            token,
            ...user._doc
        })
    } catch {
        responseHandler.error(res);
    }
}

// Login user, route POST /users/auth/login
const loginUser = async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });

        if (!user) {
            return responseHandler.notFound(res, 'User not exist');
        }

        const validate = await bcrypt.compare(password, user.password);
        if (!validate) {
            return responseHandler.badRequest(res, 'Wrong password');
        }

        const token = jwt.sign(
            { data: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        user.password = undefined;

        responseHandler.created(res, {
            token,
            ...user._doc,
            id: user._id
        })
    } catch {
        responseHandler.error(res);
    }
}

// Soft delete user, route DELETE /users/:id
const softDel = async (req, res) => {
    try {
        const resDel = await User.delete(
            { _id: req.params.id }
        );
        if (resDel) {
            responseHandler.ok(res, resDel);
        }
        else {
            responseHandler.notFound(res);
        }
    } catch {
        responseHandler.error(res);
    }
}

// List deleted user, route GET /users/trash
const deletedUsers = async (req, res) => {
    try {
        const resDel = await User.findDeleted();
        if (resDel) {
            responseHandler.ok(res, resDel);
        }
        else {
            responseHandler.notFound(res);
        }
    } catch {
        responseHandler.error(res);
    }
}

// Real delete user, route DELETE /users/:id/force
const forceDelete = async (req, res) => {
    try {
        const resDel = await User.deleteOne({ _id: req.params.id });
        if (resDel) {
            const favorites = await Favorite.deleteOne({ userID: req.params.id });
            const reviews = await Review.deleteMany({ userID: req.params.id });
            responseHandler.ok(res, resDel);
        }
        else {
            responseHandler.notFound(res);
        }
    } catch {
        responseHandler.error(res);
    }
}

// Restore user, route PUT /users/restore
const restoreUser = async (req, res) => {
    try {
        const { id } = await req.body;
        const restore = await User.restore({ _id: id });
        const user = await User.findById(id);
        await user.save();
        if (restore) {
            responseHandler.ok(res, restore);
        }
        else {
            responseHandler.notFound(res);
        }
    } catch {
        responseHandler.error(res);
    }
}

// Change user password, route PATCH /users/password
const changePassword = async (req, res) => {
    const { oldPassword, newPassword, reEnterPassword } = req.body;
    try {
        const user = await User.findById(req.user._id);

        if (!user) {
            return responseHandler.unauthorize(res);
        }

        if (newPassword !== reEnterPassword) {
            return responseHandler.badRequest(res, 'Re-enter password is wrong');
        }

        const validate = await bcrypt.compare(oldPassword, user.password);
        if (!validate) {
            return responseHandler.badRequest(res, 'Wrong password');
        }

        // Hash new password
        const hash = await bcrypt.hash(newPassword, 10);

        user.password = hash;
        await user.save();

        responseHandler.ok(res, user);
    } catch {
        responseHandler.error(res);
    }
}

// List all user, GET /users/stored
const stored = async (req, res) => {
    try {
        var users = await User.find({});
        users = users.map(({ password, ...rest }) => {
            const item = rest._doc;
            item.password = undefined;
            return item;
        })
        responseHandler.ok(res, users);
    } catch {
        responseHandler.error(res);
    }
}

// Get info user, route GET /users/info
const getInfo = async (req, res) => {
    try {
        const user = await User.findById(req.user._id);

        if (!user) {
            return responseHandler.notFound(res);
        }

        user.password = undefined;
        responseHandler.ok(res, user);
    } catch {
        responseHandler.error(res);
    }
}

export default {
    registerUser, loginUser, changePassword,
    stored, getInfo,
    softDel, deletedUsers, restoreUser, forceDelete
};
