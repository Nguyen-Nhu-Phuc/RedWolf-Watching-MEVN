<template>
    <div class="home-view" v-if="userStore.isLoggedin == true">
        <div class="bg-image">
            <h2 class="title-welcome text-uppercase text-white">
                Welcome to the Administration System
            </h2>
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

    async updated() {
        if (this.userStore.isLoggedin === false) {
            this.$router.push('admin/auth')
        }
    },
}
</script>

<style lang="scss" scoped>
.bg-image {
    height: 100vh;
    background-image: url('https://wallpapercave.com/wp/7Xn9V8t.jpg');
    background-attachment: fixed;
    background-position-y: -4.2rem;
    background-repeat: no-repeat;
    background-size: cover;
}

.title-welcome {
    display: flex;
    justify-content: center;
    align-items: center;
    text-align: center;
    min-height: 100%;
    font-size: 5.7rem;
    font-weight: 900;
}
</style>
