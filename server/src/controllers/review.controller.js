import responseHandler from '../handlers/response.handler.js';
import Review from '../models/review.model.js';
import Media from '../models/media.model.js';

// Create review, route POST /reviews/create
const create = async (req, res) => {
    try {
        const review = new Review({
            ...req.body
        });

        await review.save();
        const filter = { _id: review.mediaID };
        const media = await Media.findOne(filter);
        if (review.rate > 0) {
            media.numberRater++;
            media.rate = media.rate + review.rate;
        }
        await media.save();
        const result = await Review.find({ userID: req.user._id, mediaID: req.body.mediaID }).populate('userID').populate('mediaID');

        responseHandler.created(res, result);
    } catch {
        responseHandler.error(res);
    }
}

// Soft delete review, route DELETE /reviews/:id
const remove = async (req, res) => {
    try {
        const reviewID = await req.params.id;
        const review = await Review.findById(reviewID);
        const remove = await Review.deleteOne({ _id: reviewID })
        if (!remove) {
            return responseHandler.notFound(res);
        }
        const media = await Media.findById(review.mediaID);
        if (review.rate > 0) {
            media.numberRater = media.numberRater - 1;
            media.rate = media.rate - review.rate;
        }
        await media.save()
        responseHandler.ok(res, media);
    } catch {
        responseHandler.error(res);
    }
}

// Get reviews of user, route GET /reviews/user/:id
const getReviewsOfUser = async (req, res) => {
    try {
        const reviews = await Review.find({ userID: req.user._id }).populate('userID').populate('mediaID');
        const result = [];
        for (let i = 0; i < reviews.length; i++) {
            const element = reviews[i];
            result.push(element);
        }
        responseHandler.ok(res, result);
    } catch {
        responseHandler.error(res);
    }
}

// Admin track reviews of user, route GET /reviews/:id
const adminTrackReviewsUser = async (req, res) => {
    try {
        const reviews = await Review.find({ userID: req.params.id }).populate('userID').populate('mediaID');
        const result = [];
        for (let i = 0; i < reviews.length; i++) {
            const element = reviews[i];
            result.push(element);
        }
        responseHandler.ok(res, result);
    } catch {
        responseHandler.error(res);
    }
}

// Set of review each of user, route GET /reviews/users
const eachOfReviewUser = async (req, res) => {
    try {
        var result = [];
        var usersId = await Review.find({}).distinct('userID');
        for (let i = 0; i < usersId.length; i++) {
            var item = usersId[i];
            var count = await Review.count({ userID: item });
            result.push({
                "userID": item,
                "reviews": count
            });
        }
        responseHandler.ok(res, result);
    } catch {
        responseHandler.error(res);
    }
}

//Get reviews of media, route GET /reviews/media/:id
const reviewsMedia = async (req, res) => {
    try {
        var reviews = await Review.find({ mediaID: req.params.id }).populate('userID').populate('mediaID');
        return responseHandler.ok(res, reviews);
    } catch {
        responseHandler.error(res);
    }
}

export default {
    create, remove, getReviewsOfUser, reviewsMedia, eachOfReviewUser, adminTrackReviewsUser
};
