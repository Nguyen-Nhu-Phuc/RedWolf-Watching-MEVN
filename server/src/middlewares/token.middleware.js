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
    } catch (err) {
        return false; 
    }
};


const auth = async (req, res, next) => {
    const tokenDecoded = tokenDecode(req); 

    if (!tokenDecoded) {
        return responseHandler.unauthorize(res, 'Invalid or expired access token'); 
    }

    const user = await User.findById(tokenDecoded.data); 

    if (!user) {
        return responseHandler.unauthorize(res, 'User not found'); 
    }

    req.user = user; 
    next(); 
};

const refreshAuth = async (req, res) => {
    const { refreshToken } = req.body;  
    if (!refreshToken) {
        return responseHandler.badRequest(res, 'Refresh token is required');  
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);  

        const user = await User.findById(decoded.data);  

        if (!user || user.refreshToken !== refreshToken) {
            return responseHandler.unauthorize(res, 'Invalid refresh token');  
        }

        const newAccessToken = jwt.sign(
            { data: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }  
        );

        responseHandler.ok(res, { accessToken: newAccessToken });  
    } catch (err) {
        return responseHandler.unauthorize(res, 'Invalid or expired refresh token');  
    }
};


const logout = async (req, res) => {
    try {
        const user = await User.findById(req.user._id);  

        if (!user) {
            return responseHandler.notFound(res, "User not found"); 
        }

        user.refreshToken = null;  
        await user.save();  

        responseHandler.ok(res, "User logged out successfully"); 
    } catch (err) {
        responseHandler.error(res);  
    }
};

export default { auth, refreshAuth, logout };
