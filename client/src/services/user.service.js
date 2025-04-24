import createApiClient from './api.server.js';

class UserService {
    constructor(baseUrl = 'https://redwolf-cine-server.onrender.com/users') {
        this.api = createApiClient(baseUrl);
    }

    async login(formData) {
        return await this.api.post('/auth/login', {
            username: formData.username,
            password: formData.password
        });
    }

    async register(formData) {
        return await this.api.post('/auth/register', formData);
    }

    async changePwd(formData, tokenVal) {
        const header = {
            headers: { 'authorization': `Bearer ${tokenVal}` }
        }
        return await this.api.patch('/password', formData, header);
    }
}


export default new UserService;
