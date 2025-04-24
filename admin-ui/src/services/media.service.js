import createApiClient from './api.server.js';

class MediaService {
    constructor(baseUrl = '/media') {
        this.api = createApiClient(baseUrl);
    }

    async popularMovies() {
        return (await this.api.get('/movies/popular')).data;
    }

    async popularSeries() {
        return (await this.api.get('/tv-series/popular')).data;
    }

    async create(formData, tokenVal) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.post('/add', formData, header));
    }

    async edit(formData, tokenVal, id) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.put(`/update/${id}`, formData, header));
    }

    async delete(tokenVal, id) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.delete(`/${id}`, header));
    }

    async realDelete(tokenVal, id) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.delete(`/${id}/force`, header));
    }

    async trash(tokenVal) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.get('/trash', header)).data;
    }

    async restore(tokenVal, id) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.put('/restore', id, header));
    }

    async getDetail(id) {
        return (await this.api.get(`/detail/${id}`)).data;
    }
}

export default new MediaService;
