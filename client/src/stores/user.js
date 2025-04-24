import { defineStore } from 'pinia';

import userService from '@/services/user.service.js';



export const useUserStore = defineStore('user', {
    state: () => {
        return {
            account: null,
            isLoggedin: false,
            formLogin: {
                username: '',
                password: ''
            },

            formRegister: {
                fullName: '',
                username: '',
                password: ''
            },

            formChangePwd: {
                'oldPassword': '',
                'newPassword': '',
                'reEnterPassword': ''
            },
        }
    },

    actions: {
        async register(form) {
            try {
                $(".toast").toast('show');
                const res = await userService.register(form)

                if (res.status === 201) {
                    const btnSignup = document.getElementById('btn-signup');
                    btnSignup.click();

                }
                else if (res.status === 400) {
                    window.alert("Sign up failure!!! username already exists");
                }
            } catch (err) {
                window.alert("Sign up failure!!! username already exists");
            }

        },

        async loginUser() {
            try {
                $(".toast").toast('show');
                const res = await userService.login(this.formLogin);
                if (res.status === 201) {
                    this.account = res.data;
                    this.isLoggedin = true;
                    this.formLogin = {};
                    const btnSignin = document.getElementById('btn-signin');
                    btnSignin.click();
                }

                else if (res.data.status === 400) {
                    alert("Wrong username or pasword");
                }
            } catch (error) {
                console.log(error);
                alert("Wrong username or pasword");
            }
        },

        async logout() {
            sessionStorage.clear();
            this.account = null;
            this.isLoggedin = false;
        },

        async changePassword() {
            const res = await userService.changePwd(this.formChangePwd, this.account.token);
            if (res.status == 400) {
                window.alert('Password is wrong!');
            }

            if (res.status == 200) {
                alert('Updated successfully!');
                window.location.href = "http://localhost:8000/"
                await this.logout();
            }

        }
    },

    persist: {
        key: 'membership',
        paths: ['account', 'isLoggedin'],
        storage: sessionStorage
    }
});