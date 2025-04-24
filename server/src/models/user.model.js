import mongoose from 'mongoose';
import mongooseDelete from 'mongoose-delete';

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    fullName: { type: String, required: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false }
}, { collection: 'user' })

userSchema.plugin(mongooseDelete, {
    deletedAt: true,
    overrideMethods: true
});

const User = mongoose.model('User', userSchema);
export default User;