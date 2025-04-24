import express from 'express';
import { body } from 'express-validator';

import reviewController from '../controllers/review.controller.js';
import tokenMiddleware from '../middlewares/token.middleware.js';
import requestHandler from '../handlers/request.handler.js';

const router = express.Router({ mergeParams: true });


router.post(
    '/create',
    tokenMiddleware.auth,
    requestHandler.validate,
    reviewController.create
);

router.delete('/:id', tokenMiddleware.auth, reviewController.remove);

router.get('/media/:id', reviewController.reviewsMedia);

router.get('/users', tokenMiddleware.auth, reviewController.eachOfReviewUser);

router.get('/:id', tokenMiddleware.auth, reviewController.adminTrackReviewsUser);

router.get('/user/:id', tokenMiddleware.auth, reviewController.getReviewsOfUser);

export default router;
