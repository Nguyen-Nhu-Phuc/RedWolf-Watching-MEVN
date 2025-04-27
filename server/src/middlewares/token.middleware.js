import jwt from 'jsonwebtoken';

import User from '../models/user.model.js';
import responseHandler from '../handlers/response.handler.js';

const tokenDecode = (req) => {
    try {
        const bearerHeader = req.headers['authorization'];

        if (bearerHeader) {
            const token = bearerHeader.split(' ')[1];
            return jwt.verify(token, process.env.JWT_SECRET);
        }

        return false;
    } catch {
        return false;
    }
}

const auth = async (req, res, next) => {
    const tokenDecoded = tokenDecode(req);

    if (!tokenDecoded) {
        return responseHandler.unauthorize(res);
    }

    const user = await User.findById(tokenDecoded.data);

    if (!user) {
        return responseHandler.unauthorize(res);
    }

    req.user = user;
    next();
}


export default { auth, tokenDecode };
