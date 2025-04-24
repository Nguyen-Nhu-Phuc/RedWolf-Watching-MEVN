<template>
    <section class="vh-100 gradient-custom">
        <div class="container h-100">
            <div class="row d-flex justify-content-center align-items-center h-100">
                <div class="col-12 col-md-8 col-lg-6 col-xl-5">
                    <div class="card bg-dark text-white" style="border-radius: 1rem;">
                        <form method="POST" @submit.prevent="userStore.loginUser()" class="card-body p-5 text-center">
                            <h2 class="fw-bold mb-2 text-uppercase">Login</h2>
                            <p class="text-white-50 mb-5">Please enter your username and password!</p>

                            <div class="form-outline form-white mb-4">
                                <input type="text" id="typetextX" class="form-control form-control-lg"
                                    v-model="userStore.formLogin.username" />
                                <label class="form-label" for="typetextX">Username</label>
                            </div>

                            <div class="form-outline form-white mb-4">
                                <input type="password" id="typePasswordX" class="form-control form-control-lg"
                                    v-model="userStore.formLogin.password" />
                                <label class="form-label" for="typePasswordX">Password</label>
                            </div>

                            <button class="btn btn-outline-light btn-lg px-5" type="submit">Login</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </section>
</template>
<script>
import { useUserStore } from '@/stores/user.js';

export default {
    setup() {
        const userStore = useUserStore();
        return {
            userStore
        }
    }
}
</script>
<style lang="scss" scoped></style>