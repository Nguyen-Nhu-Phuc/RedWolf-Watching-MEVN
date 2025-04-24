<template>
    <div class="header">
        <nav class="navbar navbar-expand-lg">
            <img src="@/assets/images/logo-red-wolf.png" class="logo" alt="logo">
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent"
                aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarSupportedContent" :key="active_curUrl">
                <ul class="navbar-nav mr-auto">
                    <li class="nav-item navigate">
                        <router-link class="nav-link" :to="{ name: 'home' }">
                            HOME
                            <span class="sr-only">(current)</span>
                        </router-link>
                    </li>
                    <li class="nav-item navigate">
                        <router-link class="nav-link" :to="{ name: 'movies' }">
                            MOVIES
                        </router-link>
                    </li>
                    <li class="nav-item navigate">
                        <router-link class="nav-link" :to="{ name: 'series' }">
                            TV SERIES
                        </router-link>
                    </li>
                    <li class="nav-item navigate">
                        <router-link class="nav-link" :to="{ name: 'member' }">
                            MEMBERSHIP
                        </router-link>
                    </li>
                </ul>

                <ul class="navbar-nav ml-auto">
                    <li class="nav-item text-dark btn btn-lg btn-light py-1 px-3" @click="handleLogout">
                        LOGOUT
                    </li>
                </ul>
            </div>
        </nav>
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

    data() {
        return {
            active_curUrl: '',
            ariaExpended: false,
        }
    },

    methods: {
        handleActiveNav() {
            const navigateEle = document.getElementsByClassName("navigate");
            for (let i = 0; i < navigateEle.length; i++) {
                const curUrl = navigateEle[i].getElementsByClassName("nav-link")[0].href;
                var path = document.createElement('a');
                path.href = curUrl;

                if (path.pathname === this.active_curUrl) {
                    navigateEle[i].classList.add('active');
                }
                else navigateEle[i].classList.remove('active');
            }
        },

        async handleLogout() {
            await this.$router.push('/');
            this.userStore.logout();
        }
    },

    async created() {
        this.active_curUrl = window.location.pathname;
    },

    async mounted() {
        this.handleActiveNav();
    }
}
</script>

<style lang="scss" scoped>
@import '@/assets/styles/globalStyle.scss';

.navbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    min-height: 100%;
    background-color: $black-color-lighter;

    .logo {
        width: $width-logo;
        margin-right: 20px;
    }
}

.navbar-nav {
    .nav-item {
        display: inline-flex;
        justify-content: center;
        align-items: center;
        min-width: 80px;
        padding: 0 8px;
        font-weight: 600;
        border-radius: 5px;
        cursor: pointer;
        color: $white-color;

        &:hover {
            color: rgb(178, 0, 0);
        }

        .nav-link {
            font-size: 1.2rem;
            color: $white-color;
        }

        &.active {
            .nav-link {
                font-weight: 700;
                font-size: 1.3rem;
                color: $primary-color;
            }
        }
    }
}
</style>
