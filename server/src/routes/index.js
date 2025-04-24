import userRouter from './user.route.js';
import reviewRouter from './review.route.js';
import mediaRouter from './media.route.js';
import favoritesRouter from './favorites.route.js';

function route(app) {
    app.use('/users', userRouter);
    app.use('/reviews', reviewRouter);
    app.use('/media', mediaRouter);
    app.use('/favorites', favoritesRouter);
}

export { route };
