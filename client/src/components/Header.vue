<template>
    <div class="header" :key="widthScreen">
        <!-- Nav PC -->
        <nav class="nav-pc">
            <div class="d-flex align-items-center">
                <div class="logo">
                    <img class="w-100" src="../assets/images/logo-red-wolf.png" alt="Logo Image">
                </div>
                <ul class="nav-list text-uppercase">
                    <li class="navigate">
                        <router-link :to="{ name: 'home' }" class="nav-link">Home</router-link>
                    </li>
                    <li class="navigate">
                        <router-link :to="{ name: 'movies' }" class="nav-link">Movies</router-link>
                    </li>
                    <li class="navigate">
                        <router-link :to="{ name: 'series' }" class="nav-link">Series</router-link>
                    </li>
                    <li class="navigate">
                        <router-link :to="{ name: 'search' }" class="nav-link">Search</router-link>
                    </li>
                </ul>
            </div>

            <ul class="nav-list nav-list-right" v-if="widthScreen >= 740 && !userStore.isLoggedin">
                <li class="nav-auth active">
                    <button class="btn-auth text-uppercase" type="button" data-toggle="modal"
                        data-target="#modal-signin-form">
                        Sign in
                    </button>
                </li>
                <li class="nav-auth">
                    <button class="btn-auth text-uppercase" type="button" data-toggle="modal"
                        data-target="#modal-signup-form">
                        Sign up
                    </button>
                </li>
            </ul>

            <div class="dropdown" v-else-if="widthScreen >= 740 && userStore.isLoggedin">
                <Avatar :fullName="userStore.account.fullName" style="width: 50px; padding: 3px 2px;" />
                <button class="dropbtn text-white" style="padding-left: 12px;" @click="handleShowMenudropdown()">
                    {{ userStore.account.fullName }}
                    <i class="fa fa-caret-down"></i>
                </button>
                <div class="dropdown-content" id="myDropdown">
                    <router-link class="dropdown-content-text" :to="{ name: 'favorites' }">
                        <font-awesome-icon :icon="['fas', 'heart']" class="mr-1" />
                        FAVORITES
                    </router-link>
                    <router-link class="dropdown-content-text" :to="{ name: 'review' }">
                        <font-awesome-icon :icon="['fas', 'feather']" class="mr-1" />
                        REVIEWS
                    </router-link>
                    <router-link class="dropdown-content-text" :to="{ name: 'password' }">
                        <font-awesome-icon :icon="['fas', 'rotate-right']" class="mr-1" />
                        CHANGE PASSWORD
                    </router-link>
                    <button class="dropdown-content-text m-0" type="button" @click="handleLogout">
                        <div class="w-100">
                            <font-awesome-icon :icon="['fas', 'right-from-bracket']" class="mr-1" />
                            LOGOUT
                        </div>
                    </button>
                </div>
            </div>
        </nav>

        <!-- Nav mobile -->

        <!-- Menu side left -->
        <label for="nav-mobile-input-check" class="nav-bars-btn col-6">
            <font-awesome-icon :icon="['fas', 'list-ul']" />
        </label>
        <input type="checkbox" hidden class="nav-mobile-input-check" id="nav-mobile-input-check">

        <ul class="nav-list-mobile-screen nav-list-right col-6" v-if="widthScreen < 740 && !userStore.isLoggedin">
            <li class="nav-mobile-auth active">
                <button class="btn-mobile-auth text-uppercase" type="button" data-toggle="modal"
                    data-target="#modal-signin-form">
                    Sign in
                </button>
            </li>
            <li class="nav-mobile-auth">
                <button class="btn-mobile-auth text-uppercase" type="button" data-toggle="modal"
                    data-target="#modal-signup-form">
                    Sign up
                </button>
            </li>
        </ul>

        <label for="nav-mobile-user-menu-check" class="col-6 text-right m-0"
            v-else-if="widthScreen < 740 && userStore.isLoggedin">
            <Avatar class="" :fullName="userStore.account.fullName" style="width: 46px; padding: 3px 2px;" />
        </label>
        <input type="checkbox" hidden class="nav-mobile-user-menu-check" id="nav-mobile-user-menu-check">

        <label for="nav-mobile-user-menu-check" class="nav-user-menu-overplay"></label>
        <label for="nav-mobile-input-check" class="nav-overplay"></label>

        <nav class="nav-mobile">
            <label for="nav-mobile-input-check" class="nav-mobile-close">
                <font-awesome-icon :icon="['fas', 'times']" />
            </label>
            <ul class="nav-mobile-list">
                <li class="nav-mobile-item">
                    <font-awesome-icon :icon="['fas', 'home']" />
                    <router-link :to="{ name: 'home' }" class="nav-mobile-link">Home</router-link>
                </li>
                <li class="nav-mobile-item">
                    <font-awesome-icon :icon="['fas', 'clapperboard']" />
                    <router-link :to="{ name: 'movies' }" class="nav-mobile-link">Movies</router-link>
                </li>
                <li class="nav-mobile-item">
                    <font-awesome-icon :icon="['fas', 'film']" />
                    <router-link :to="{ name: 'series' }" class="nav-mobile-link">Series</router-link>
                </li>
                <li class="nav-mobile-item">
                    <font-awesome-icon :icon="['fas', 'magnifying-glass']" />
                    <router-link :to="{ name: 'search' }" class="nav-mobile-link">Search</router-link>
                </li>
            </ul>
        </nav>

        <!-- Menu side right -->
        <nav class="nav-mobile-user-menu" v-if="widthScreen < 740 && userStore.isLoggedin">
            <label for="nav-mobile-user-menu-check" class="nav-mobile-user-menu-close">
                <font-awesome-icon :icon="['fas', 'times']" />
            </label>
            <ul class="nav-mobile-user-menu-list">
                <li class="user-fullname">
                    <font-awesome-icon :icon="['fas', 'user']" />
                    {{ userStore.account.fullName }}
                </li>
                <li class="nav-mobile-user-menu-item">
                    <router-link :to="{ name: 'favorites' }" class="nav-mobile-user-menu-link">
                        <font-awesome-icon :icon="['fas', 'heart']" class="mr-1" />
                        Favorites
                    </router-link>
                </li>
                <li class="nav-mobile-user-menu-item">
                    <router-link :to="{ name: 'review' }" class="nav-mobile-user-menu-link">
                        <font-awesome-icon :icon="['fas', 'feather']" class="mr-1" />
                        Reviews
                    </router-link>
                </li>
                <li class="nav-mobile-user-menu-item">
                    <router-link :to="{ name: 'password' }" class="nav-mobile-user-menu-link">
                        <font-awesome-icon :icon="['fas', 'rotate-right']" class="mr-1" />
                        Change password
                    </router-link>
                </li>
                <li class="nav-mobile-user-menu-item">
                    <button class="nav-mobile-user-menu-link" type="button" @click="handleLogout">
                        <div class="w-100">
                            <font-awesome-icon :icon="['fas', 'right-from-bracket']" class="mr-1" />
                            Logout
                        </div>
                    </button>
                </li>
            </ul>
        </nav>
    </div>
</template>

<script>
import Avatar from './Avatar.vue';

import { useUserStore } from '@/stores/user.js';

export default {
    setup() {
        const userStore = useUserStore();
        return {
            userStore
        }
    },

    components: { Avatar },

    data() {
        return {
            active_curUrl: '',
            ariaExpended: false,
        }
    },

    computed: {
        widthScreen() {
            return window.innerWidth;
        }
    },

    methods: {
        handleShowMenudropdown() {
            document.getElementById("myDropdown").classList.toggle("show");

            window.onclick = function (e) {
                if (!e.target.matches('.dropbtn')) {
                    var myDropdown = document.getElementById("myDropdown");
                    if (myDropdown.classList.contains('show')) {
                        myDropdown.classList.remove('show');
                    }
                }
            }
        },

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
            window.location.href = "https://redwolf-cinema.netlify.app/"
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
@import '@/assets/styles/header.scss';
</style>
