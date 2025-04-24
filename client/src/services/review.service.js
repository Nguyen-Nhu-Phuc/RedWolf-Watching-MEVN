import createApiClient from './api.server.js';

class ReviewService {
    constructor(baseUrl = 'https://redwolf-cine-server.onrender.com/reviews') {
        this.api = createApiClient(baseUrl);
    }

    async getReviewsMedia(id) {
        return (await this.api.get(`/media/${id}`)).data;
    }

    async reviewsUser(id, tokenVal) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.get(`/user/${id}`, header)).data;
    }

    async post(datas, tokenVal) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.post('/create', datas, header));
    }

    async remove(id, tokenVal) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.delete(`/${id}`, header)).data;
    }
}

export default new ReviewService;
