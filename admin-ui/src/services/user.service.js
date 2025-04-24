import createApiClient from './api.server.js';

class UserService {
    constructor(baseUrl = '/users') {
        this.api = createApiClient(baseUrl);
    }

    async login(formData) {
        return await this.api.post('/auth/login', {
            username: formData.username,
            password: formData.password
        });
    }

    async list(tokenVal) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.get('/stored', header)).data;
    }

    async delete(tokenVal, id) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.delete(`/${id}`, header));
    }

    async forceDelete(tokenVal, id) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return (await this.api.delete(`/${id}/force`, header));
    }

    async listDeleted(tokenVal) {
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
}

export default new UserService;
