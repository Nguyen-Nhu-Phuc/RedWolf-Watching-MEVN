import mongoose from 'mongoose';
import mongooseDelete from 'mongoose-delete';

const favoriteSchema = new mongoose.Schema({
    userID: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    mediaID: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Media',
        required: true
    }]
}, { collection: 'favorites' });

favoriteSchema.plugin(mongooseDelete, {
    deletedAt: true,
    overrideMethods: true
});

const Favorite = mongoose.model('Favorite', favoriteSchema);
export default Favorite;
