<template>
    <div class="signin-form modal fade" id="modal-signin-form" tabindex="-1" role="dialog" aria-labelledby="myModalLabel"
        aria-hidden="true" :key="userStore.isLoggedin">
        <div class="modal-dialog modal-dialog-centered" role="document">
            <form method="POST" @submit.prevent="userStore.loginUser()">
                <div class="modal-content">
                    <div class="modal-header text-center">
                        <div class="modal-title w-100 font-weight-bold">
                            <img src="@/assets/images/logo-red-wolf.png" class="w-50" alt="logo">
                        </div>
                        <button type="button" id="btn-signin" class="close btn-close" data-dismiss="modal"
                            aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body mx-4">

                        <div class="md-form mb-4">
                            <font-awesome-icon :icon="['fas', 'user']" /> <span class="ml-2"></span>
                            <label data-error="wrong" data-success="right" for="username">Your username</label>
                            <input type="text" id="username" class="form-control validate"
                                v-model="userStore.formLogin.username">
                        </div>

                        <div class="md-form mb-4">
                            <font-awesome-icon :icon="['fas', 'key']" /> <span class="ml-2"></span>
                            <label data-error="wrong" data-success="right" for="password">Your password</label>
                            <input type="password" id="password" class="form-control validate"
                                v-model="userStore.formLogin.password">
                        </div>

                    </div>
                    <div class="modal-footer d-flex justify-content-center">
                        <button type="submit" class="btn btn-default btn-submit-form">Sign in</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
</template>

<script>
import { useUserStore } from '@/stores/user.js';

export default {
    setup() {
        const userStore = useUserStore();
        return {
            userStore
        }
    },
}
</script>

<style lang="scss" scoped>
@import '@/assets/styles/signinForm.scss';
</style>