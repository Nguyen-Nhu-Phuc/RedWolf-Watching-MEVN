import mongoose from 'mongoose';
import mongooseDelete from 'mongoose-delete';


const reviewSchema = new mongoose.Schema({
    userID: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    mediaID: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Media',
        required: true
    },
    content: { type: String },
    date: {
        type: Date,
        default: Date.now
    },
    rate: {
        type: Number,
        default: 0
    }
}, { collection: 'reviews' });

reviewSchema.plugin(mongooseDelete, {
    deletedAt: true,
    overrideMethods: true
});

const Review = mongoose.model('Review', reviewSchema);
export default Review;
