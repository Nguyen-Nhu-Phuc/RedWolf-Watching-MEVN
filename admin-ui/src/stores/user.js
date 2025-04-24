import { defineStore } from 'pinia';
import userService from '@/services/user.service.js';

export const useUserStore = defineStore('user', {
    state: () => {
        return {
            admin: null,
            isLoggedin: false,
            idRestore: {
                "id": null
            },
            formLogin: {
                username: '',
                password: ''
            },
            members: [],
            deletedMembers: []
        }
    },

    actions: {
        async loginUser() {
            try {
                const res = await userService.login(this.formLogin);

                if (res.status === 201) {
                    if (res.data.isAdmin === true) {
                        this.admin = res.data;
                        this.isLoggedin = true;
                        this.formLogin = {};
                        location.reload();
                    }
                    else {
                        alert('You are unauthorized!')
                    }
                }

                else if (res.status === 400) {
                    alert("Sai tài khoản hoặc mật khẩu");
                }
            } catch (error) {
                console.log(error);
                alert("Sai tài khoản hoặc mật khẩu");
            }
        },

        async logout() {
            sessionStorage.clear();
            this.admin = null;
            this.isLoggedin = false;
        },

        async idMember(member) {
            return member._id;
        },

        async getTrash(token) {
            this.deletedMembers = await userService.listDeleted(token);
        },

        async deleteMember(token, id) {
            return await userService.delete(token, id);
        },

        async forceDel(token, id) {
            const res = await userService.forceDelete(token, id);
            if (res.status == 200) {
                this.getTrash(token);
            }
        },

        async restoreMember(token, id) {
            this.idRestore.id = await id;
            const res = await userService.restore(token, this.idRestore);
            if (res.status == 200) {
                await this.getTrash(token);
            }
        },
    },

    persist: {
        key: 'ad',
        paths: ['admin', 'isLoggedin'],
        storage: sessionStorage
    }
});