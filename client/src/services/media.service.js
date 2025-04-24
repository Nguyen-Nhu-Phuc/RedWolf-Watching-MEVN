import createApiClient from './api.server.js';

class MediaService {
    constructor(baseUrl = 'https://redwolf-cine-server.onrender.com/media') {
        this.api = createApiClient(baseUrl);
    }

    async getRandMovie() {
        return (await this.api.get('/movies/intro')).data;
    }

    async popularMovies() {
        return (await this.api.get('/movies/popular')).data;
    }

    async ratedMovies() {
        return (await this.api.get('/movies/rated')).data;
    }

    async getRandSeries() {
        return (await this.api.get('/tv-series/intro')).data;
    }

    async popularTVSeries() {
        return (await this.api.get('/tv-series/popular')).data;
    }

    async ratedTVSeries() {
        return (await this.api.get('/tv-series/rated')).data;
    }

    async getDetail(id) {
        return (await this.api.get(`/detail/${id}`)).data;
    }
}

export default new MediaService;
