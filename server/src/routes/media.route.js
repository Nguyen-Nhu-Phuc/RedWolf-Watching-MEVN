import express from 'express';

import mediaController from '../controllers/media.controller.js';

import tokenMiddleware from '../middlewares/token.middleware.js';


const router = express.Router();

router.post('/add', tokenMiddleware.auth, mediaController.addMedia);

router.put('/update/:id', tokenMiddleware.auth, mediaController.updateMedia);

router.delete('/:id/force', tokenMiddleware.auth, mediaController.forceDel);

router.delete('/:id', tokenMiddleware.auth, mediaController.delMedia);

router.get('/trash', tokenMiddleware.auth, mediaController.trashMedia);

router.put('/restore', tokenMiddleware.auth, mediaController.restoreMedia);

router.get('/movies/intro', mediaController.getRandMovie);

router.get('/movies/popular', mediaController.popularMovies);

router.get('/movies/rated', mediaController.topRatedMovies);

router.get('/tv-series/intro', mediaController.getRandSeries);

router.get('/tv-series/popular', mediaController.popularTVSeries);

router.get('/tv-series/rated', mediaController.topRatedSeries);

router.get('/detail/:id', mediaController.show);

router.get('/', mediaController.storeMedia);


export default router;
